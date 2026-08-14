/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * libnunchuk is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libnunchuk. If not, see <http://www.gnu.org/licenses/>.
 */

#include "utils/bitbox/bootloader.hpp"

#include <algorithm>
#include <array>
#include <crypto/common.h>
#include <cstdint>
#include <stdexcept>
#include <utility>

namespace nunchuk::bitbox {
namespace {

constexpr size_t CHUNK_SIZE = 8 * 512;
constexpr size_t MAX_FIRMWARE_SIZE = 884736;
constexpr size_t MAGIC_SIZE = 4;
constexpr size_t VERSION_SIZE = 4;
constexpr size_t KEY_SIZE = 64;
constexpr size_t SIGNING_KEY_COUNT = 3;
constexpr size_t ROOT_KEY_COUNT = 3;
constexpr size_t SIGNING_KEYS_DATA_SIZE =
    VERSION_SIZE + SIGNING_KEY_COUNT * KEY_SIZE + ROOT_KEY_COUNT * KEY_SIZE;
constexpr size_t FIRMWARE_DATA_SIZE =
    VERSION_SIZE + SIGNING_KEY_COUNT * KEY_SIZE;
constexpr size_t SIGNATURE_DATA_SIZE =
    SIGNING_KEYS_DATA_SIZE + FIRMWARE_DATA_SIZE;
static_assert(MAX_FIRMWARE_SIZE % CHUNK_SIZE == 0);
static_assert(MAX_FIRMWARE_SIZE / CHUNK_SIZE <= 255);

BitBoxProduct ProductForMagic(uint32_t magic) {
  switch (magic) {
    case 0x653f362b:
      return BitBoxProduct::BITBOX02_MULTI;
    case 0x11233b0b:
      return BitBoxProduct::BITBOX02_BITCOIN_ONLY;
    case 0x5b648ceb:
      return BitBoxProduct::NOVA_MULTI;
    case 0x48714774:
      return BitBoxProduct::NOVA_BITCOIN_ONLY;
    default:
      throw std::invalid_argument(
          "BitBox signed firmware has an unrecognized product magic");
  }
}

struct ParsedFirmware {
  BitBoxFirmwareInfo info;
  std::vector<unsigned char> signature_data;
  std::vector<unsigned char> firmware;
};

BitBoxFirmwareInfo ParseFirmwareInfo(
    std::span<const unsigned char> signed_firmware) {
  if (signed_firmware.size() <= MAGIC_SIZE + SIGNATURE_DATA_SIZE) {
    throw std::invalid_argument("BitBox signed firmware is too small");
  }
  const size_t firmware_size =
      signed_firmware.size() - MAGIC_SIZE - SIGNATURE_DATA_SIZE;
  if (firmware_size > MAX_FIRMWARE_SIZE) {
    throw std::invalid_argument("BitBox signed firmware is too large");
  }

  BitBoxFirmwareInfo result;
  result.product = ProductForMagic(ReadBE32(signed_firmware.data()));
  const auto signature_data =
      signed_firmware.subspan(MAGIC_SIZE, SIGNATURE_DATA_SIZE);
  result.monotonic_version =
      ReadLE32(signature_data.data() + SIGNING_KEYS_DATA_SIZE);
  result.firmware_size = firmware_size;
  return result;
}

ParsedFirmware ParseFirmware(
    std::span<const unsigned char> signed_firmware) {
  ParsedFirmware result;
  result.info = ParseFirmwareInfo(signed_firmware);
  const auto signature_data =
      signed_firmware.subspan(MAGIC_SIZE, SIGNATURE_DATA_SIZE);
  result.signature_data.assign(signature_data.begin(), signature_data.end());
  const auto firmware =
      signed_firmware.subspan(MAGIC_SIZE + SIGNATURE_DATA_SIZE);
  result.firmware.assign(firmware.begin(), firmware.end());
  return result;
}

}  // namespace

BitBoxFirmwareInfo InspectFirmware(
    std::span<const unsigned char> signed_firmware) {
  return ParseFirmwareInfo(signed_firmware);
}

BitBoxBootloaderSession::BitBoxBootloaderSession(BitBoxProduct product)
    : product_(product),
      framer_(0xff000000, U2fFramer::BOOTLOADER_COMMAND) {
  if (product_ == BitBoxProduct::UNKNOWN) {
    throw std::invalid_argument("BitBox bootloader product is unknown");
  }
}

BitBoxStep BitBoxBootloaderSession::upgradeFirmware(
    std::span<const unsigned char> signed_firmware) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (phase_ != Phase::IDLE || awaiting_data_) {
    return fail(BitBoxErrorCode::INVALID_STATE,
                "BitBox firmware upgrade is already in progress");
  }
  try {
    auto parsed = ParseFirmware(signed_firmware);
    if (parsed.info.product != product_) {
      return fail(BitBoxErrorCode::INVALID_FIRMWARE,
                  "BitBox signed firmware does not match the device product");
    }
    firmware_ = std::move(parsed.firmware);
    signature_data_ = std::move(parsed.signature_data);
    total_chunks_ = (firmware_.size() + CHUNK_SIZE - 1) / CHUNK_SIZE;
    next_chunk_ = 0;
    progress_ = 0;
    const std::array<unsigned char, 1> chunk_count{
        static_cast<unsigned char>(total_chunks_)};
    return sendQuery('e', chunk_count, Phase::ERASE, 0);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_FIRMWARE, e.what());
  }
}

BitBoxStep BitBoxBootloaderSession::onData(
    std::span<const unsigned char> data) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!awaiting_data_ || phase_ == Phase::IDLE) {
    return fail(BitBoxErrorCode::INVALID_STATE,
                "BitBox bootloader received data with no outstanding request");
  }
  const auto decoded = framer_.decode(data);
  if (decoded.type == U2fDecodeResult::Type::READ_MORE) {
    BitBoxStep step;
    step.type = BitBoxStepType::READ_MORE;
    step.progress = progress_;
    return step;
  }
  if (decoded.type == U2fDecodeResult::Type::FAILED) {
    return fail(BitBoxErrorCode::PROTOCOL, decoded.error);
  }
  awaiting_data_ = false;
  if (decoded.payload.size() < 2 ||
      decoded.payload[0] != expected_command_) {
    return fail(BitBoxErrorCode::INVALID_RESPONSE,
                "BitBox bootloader returned an unexpected response");
  }
  if (decoded.payload[1] != 0) {
    return fail(BitBoxErrorCode::DEVICE,
                "BitBox bootloader rejected the firmware command",
                decoded.payload[1]);
  }

  switch (phase_) {
    case Phase::ERASE:
      return sendChunk(0);
    case Phase::WRITE_CHUNK:
      ++next_chunk_;
      progress_ = static_cast<double>(next_chunk_) /
                  static_cast<double>(total_chunks_);
      if (next_chunk_ < total_chunks_) return sendChunk(progress_);
      return sendQuery('s', signature_data_, Phase::SIGNATURES, 1);
    case Phase::SIGNATURES:
      return sendReboot();
    case Phase::IDLE:
      break;
  }
  return fail(BitBoxErrorCode::INVALID_STATE,
              "BitBox bootloader reached an invalid phase");
}

BitBoxStep BitBoxBootloaderSession::sendQuery(
    unsigned char command, std::span<const unsigned char> data, Phase phase,
    double progress) {
  std::vector<unsigned char> payload;
  payload.reserve(data.size() + 1);
  payload.push_back(command);
  payload.insert(payload.end(), data.begin(), data.end());
  phase_ = phase;
  expected_command_ = command;
  awaiting_data_ = true;
  progress_ = progress;
  BitBoxStep step;
  step.type = BitBoxStepType::WRITE;
  step.writes = framer_.encode(payload);
  step.progress = progress;
  return step;
}

BitBoxStep BitBoxBootloaderSession::sendChunk(double progress) {
  const size_t offset = next_chunk_ * CHUNK_SIZE;
  const size_t length = std::min(CHUNK_SIZE, firmware_.size() - offset);
  std::vector<unsigned char> chunk(CHUNK_SIZE + 1, 0xff);
  chunk[0] = static_cast<unsigned char>(next_chunk_);
  std::copy_n(firmware_.begin() + offset, length, chunk.begin() + 1);
  return sendQuery('w', chunk, Phase::WRITE_CHUNK, progress);
}

BitBoxStep BitBoxBootloaderSession::sendReboot() {
  const std::array<unsigned char, 1> payload{'r'};
  BitBoxStep step;
  step.type = BitBoxStepType::REBOOT;
  step.writes = framer_.encode(payload);
  step.progress = 1;
  reset();
  return step;
}

BitBoxStep BitBoxBootloaderSession::fail(BitBoxErrorCode code,
                                         const std::string& message,
                                         int device_code) {
  reset();
  BitBoxStep step;
  step.type = BitBoxStepType::FAILED;
  step.error = BitBoxError{code, message, device_code};
  return step;
}

void BitBoxBootloaderSession::reset() {
  phase_ = Phase::IDLE;
  expected_command_ = 0;
  awaiting_data_ = false;
  firmware_.clear();
  signature_data_.clear();
  total_chunks_ = 0;
  next_chunk_ = 0;
  progress_ = 0;
  framer_.reset();
}

}  // namespace nunchuk::bitbox
