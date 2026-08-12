/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (c) 2020 Enigmo.
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

#include "utils/ledger/apdu_framer.hpp"

#include <algorithm>
#include <crypto/common.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tinyformat.h>

namespace nunchuk::ledger {
namespace {

constexpr unsigned char HEAD_TAG = 0x05;
constexpr size_t HEAD_TAG_LENGTH = 1;
constexpr size_t CHANNEL_LENGTH = 2;
constexpr size_t INDEX_LENGTH = 2;
constexpr size_t APDU_DATA_LENGTH_LENGTH = 2;
constexpr size_t APDU_RESPONSE_STATUS_WORD_LENGTH = 2;
constexpr size_t USB_HID_PACKET_SIZE = 64;
constexpr size_t BLE_PACKET_SIZE = 20;
constexpr uint16_t USB_HID_CHANNEL = 0x0101;

ApduDecodeResult FailedDecode(const std::string& message) {
  ApduDecodeResult result;
  result.type = ApduDecodeResult::Type::FAILED;
  result.error = LedgerError{-1, message, 0};
  return result;
}

}  // namespace

std::vector<unsigned char> SerializeApdu(uint8_t cla, uint8_t ins, uint8_t p1,
                                         uint8_t p2,
                                         std::span<const unsigned char> data) {
  if (data.size() > 0xff) {
    throw std::invalid_argument("Ledger APDU payload is larger than 255 bytes");
  }

  std::vector<unsigned char> apdu;
  apdu.reserve(5 + data.size());
  apdu.push_back(cla);
  apdu.push_back(ins);
  apdu.push_back(p1);
  apdu.push_back(p2);
  apdu.push_back(static_cast<unsigned char>(data.size()));
  apdu.insert(apdu.end(), data.begin(), data.end());
  return apdu;
}

void AppendLvString(std::vector<unsigned char>& out, std::string_view value,
                    std::string_view field_name) {
  if (value.size() > 0xff) {
    throw std::invalid_argument(
        strprintf("Ledger %s is too long", std::string(field_name)));
  }
  out.push_back(static_cast<unsigned char>(value.size()));
  out.insert(out.end(), value.begin(), value.end());
}

std::string ReadLvString(const std::vector<unsigned char>& data,
                         size_t& offset, std::string_view context,
                         std::string_view field_name) {
  if (offset >= data.size()) {
    throw std::runtime_error(strprintf("%s is missing %s",
                                       std::string(context),
                                       std::string(field_name)));
  }
  const auto length = static_cast<size_t>(data[offset++]);
  if (offset + length > data.size()) {
    throw std::runtime_error(strprintf("%s has invalid %s length",
                                       std::string(context),
                                       std::string(field_name)));
  }
  std::string result(data.begin() + offset, data.begin() + offset + length);
  offset += length;
  return result;
}

ApduFramer::ApduFramer(LedgerTransport transport) : transport_(transport) {}

std::vector<std::vector<unsigned char>> ApduFramer::encode(
    const std::vector<unsigned char>& apdu) const {
  if (apdu.size() > 0xffff) {
    throw std::invalid_argument("Ledger APDU is larger than 65535 bytes");
  }

  const auto packet_size = packetSize();
  if (headerSize(0) >= packet_size) {
    throw std::invalid_argument("Ledger packet size is too small");
  }

  std::vector<std::vector<unsigned char>> frames;
  size_t offset = 0;
  size_t frame_index = 0;

  while (offset < apdu.size()) {
    const auto header_size = headerSize(frame_index);
    if (header_size >= packet_size) {
      throw std::invalid_argument("Ledger packet size is too small");
    }

    std::vector<unsigned char> frame;
    frame.reserve(packet_size);

    if (hasChannel()) {
      const auto write_offset = frame.size();
      frame.resize(write_offset + sizeof(uint16_t));
      WriteBE16(frame.data() + write_offset, USB_HID_CHANNEL);
    }
    frame.push_back(HEAD_TAG);
    auto write_offset = frame.size();
    frame.resize(write_offset + sizeof(uint16_t));
    WriteBE16(frame.data() + write_offset, static_cast<uint16_t>(frame_index));
    if (frame_index == 0) {
      write_offset = frame.size();
      frame.resize(write_offset + sizeof(uint16_t));
      WriteBE16(frame.data() + write_offset, static_cast<uint16_t>(apdu.size()));
    }

    const auto max_data_size = packet_size - header_size;
    const auto remaining = apdu.size() - offset;
    const auto data_size = std::min(max_data_size, remaining);
    frame.insert(frame.end(), apdu.begin() + offset,
                 apdu.begin() + offset + data_size);

    if (hasPadding() && frame.size() < packet_size) {
      frame.resize(packet_size, 0);
    }

    frames.push_back(std::move(frame));
    offset += data_size;
    ++frame_index;
  }

  return frames;
}

ApduDecodeResult ApduFramer::decode(const std::vector<unsigned char>& frame) {
  const auto channel_size = hasChannel() ? CHANNEL_LENGTH : 0;
  const auto min_header_size = channel_size + HEAD_TAG_LENGTH + INDEX_LENGTH;

  if (frame.size() < min_header_size) {
    return FailedDecode("Ledger frame is shorter than the frame header");
  }

  size_t cursor = 0;
  if (hasChannel()) {
    const auto channel = ReadBE16(frame.data() + cursor);
    if (channel != USB_HID_CHANNEL) {
      return FailedDecode("Ledger frame channel does not match the session");
    }
    cursor += CHANNEL_LENGTH;
  }

  if (frame[cursor] != HEAD_TAG) {
    return FailedDecode("Ledger frame has an invalid tag");
  }
  cursor += HEAD_TAG_LENGTH;

  const auto frame_index = ReadBE16(frame.data() + cursor);
  cursor += INDEX_LENGTH;

  if (!expected_length_.has_value() && frame_index != 0) {
    return FailedDecode("Ledger response did not start with frame index 0");
  }
  if (frame_index != expected_index_) {
    return FailedDecode("Ledger frame index is out of order");
  }

  if (frame_index == 0) {
    if (frame.size() < cursor + APDU_DATA_LENGTH_LENGTH) {
      return FailedDecode("Ledger first frame is missing response length");
    }
    expected_length_ = ReadBE16(frame.data() + cursor);
    cursor += APDU_DATA_LENGTH_LENGTH;
  }

  pending_.insert(pending_.end(), frame.begin() + cursor, frame.end());

  if (!expected_length_.has_value() || pending_.size() < *expected_length_) {
    ++expected_index_;
    return ApduDecodeResult{};
  }

  const auto expected_length = *expected_length_;
  if (expected_length < APDU_RESPONSE_STATUS_WORD_LENGTH) {
    reset();
    return FailedDecode("Ledger response is missing status word");
  }

  ApduDecodeResult result;
  result.type = ApduDecodeResult::Type::COMPLETE;
  result.response.status_word =
      ReadBE16(pending_.data() + expected_length -
               APDU_RESPONSE_STATUS_WORD_LENGTH);
  result.response.data.assign(
      pending_.begin(),
      pending_.begin() + expected_length - APDU_RESPONSE_STATUS_WORD_LENGTH);

  reset();
  return result;
}

void ApduFramer::setPacketSize(size_t packet_size) {
  packet_size_ = packet_size;
}

void ApduFramer::reset() {
  pending_.clear();
  expected_length_.reset();
  expected_index_ = 0;
}

size_t ApduFramer::packetSize() const {
  if (packet_size_ != 0) {
    return packet_size_;
  }
  return transport_ == LedgerTransport::USB_HID ? USB_HID_PACKET_SIZE
                                                : BLE_PACKET_SIZE;
}

bool ApduFramer::hasChannel() const {
  return transport_ == LedgerTransport::USB_HID;
}

bool ApduFramer::hasPadding() const {
  return transport_ == LedgerTransport::USB_HID;
}

size_t ApduFramer::headerSize(size_t frame_index) const {
  return (hasChannel() ? CHANNEL_LENGTH : 0) + HEAD_TAG_LENGTH + INDEX_LENGTH +
         (frame_index == 0 ? APDU_DATA_LENGTH_LENGTH : 0);
}

}  // namespace nunchuk::ledger
