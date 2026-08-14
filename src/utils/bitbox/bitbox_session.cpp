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

#include "utils/bitbox/bitbox_session.hpp"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <hash.h>
#include <limits>
#include <random.h>
#include <stdexcept>
#include <util/strencodings.h>
#include <utility>

#include "utils/bitbox/bitcoin.hpp"
#include "utils/bitbox/crypto.hpp"
#include "utils/bitbox/noise.hpp"
#include "utils/bitbox/pairing_store.hpp"
#include "utils/bitbox/protobuf.hpp"

namespace nunchuk::bitbox {
namespace {

constexpr unsigned char HWW_NEW = 0x00;
constexpr unsigned char HWW_RETRY = 0x01;
constexpr unsigned char HWW_ACK = 0x00;
constexpr unsigned char HWW_NOT_READY = 0x01;
constexpr unsigned char HWW_BUSY = 0x02;
constexpr unsigned char HWW_NACK = 0x03;

uint256 AntiKleptoHostCommitment(
    std::span<const unsigned char> host_nonce) {
  auto hasher = TaggedHash("s2c/ecdsa/data");
  hasher.write(std::as_bytes(host_nonce));
  return hasher.GetSHA256();
}

struct DeviceDateTime {
  uint32_t timestamp = 0;
  int32_t timezone_offset = 0;
};

DeviceDateTime CurrentDeviceDateTime() {
  const std::time_t now = std::time(nullptr);
  if (now < 0 || static_cast<uint64_t>(now) >
                     std::numeric_limits<uint32_t>::max()) {
    throw std::runtime_error("Current time cannot be represented by BitBox");
  }

  std::tm local{};
#if defined(_WIN32)
  if (localtime_s(&local, &now) != 0) {
    throw std::runtime_error("Could not determine the local timezone");
  }
  long seconds_west = 0;
  if (_get_timezone(&seconds_west) != 0) {
    throw std::runtime_error("Could not determine the local timezone");
  }
  int64_t offset = -static_cast<int64_t>(seconds_west);
  if (local.tm_isdst > 0) offset += 60 * 60;
#else
  if (localtime_r(&now, &local) == nullptr) {
    throw std::runtime_error("Could not determine the local timezone");
  }
  const int64_t offset = local.tm_gmtoff;
#endif
  if (offset < std::numeric_limits<int32_t>::min() ||
      offset > std::numeric_limits<int32_t>::max()) {
    throw std::runtime_error("Local timezone offset is invalid");
  }
  return {static_cast<uint32_t>(now), static_cast<int32_t>(offset)};
}

std::string PairingCode(std::span<const unsigned char> channel_binding) {
  auto base32 = EncodeBase32(channel_binding);
  std::transform(base32.begin(), base32.end(), base32.begin(),
                 [](unsigned char value) { return std::toupper(value); });
  if (base32.size() < 20) {
    throw std::runtime_error("BitBox pairing code is too short");
  }
  return base32.substr(0, 5) + " " + base32.substr(5, 5) + "\n" +
         base32.substr(10, 5) + " " + base32.substr(15, 5);
}

std::string NormalizeVersion(std::string value) {
  if (!value.empty() && value.front() == 'v') value.erase(value.begin());
  return value;
}

std::string RegistrationName(const std::string& name, size_t account_index,
                             size_t account_count) {
  auto result = ValidateWalletName(name);
  if (account_count <= 1 || account_index == 0) return result;
  const auto suffix = " #" + std::to_string(account_index + 1);
  if (result.size() + suffix.size() > 30) {
    result.resize(30 - suffix.size());
  }
  return result + suffix;
}

BitBoxError DeviceError(const proto::DeviceError& error) {
  constexpr int FIRST_DEVICE_ERROR =
      static_cast<int>(BitBoxErrorCode::DEVICE_INVALID_INPUT);
  constexpr int LAST_DEVICE_ERROR =
      static_cast<int>(BitBoxErrorCode::DEVICE_NOISE_DECRYPT);
  const bool known_device_error =
      error.code >= FIRST_DEVICE_ERROR && error.code <= LAST_DEVICE_ERROR;
  const auto code = known_device_error
                        ? static_cast<BitBoxErrorCode>(error.code)
                        : BitBoxErrorCode::DEVICE;
  return {code, error.message, error.code};
}

}  // namespace

BitBoxSession::BitBoxSession(std::shared_ptr<PairingStore> pairing_store,
                             Chain chain, BitBoxTransport transport)
    : pairing_store_(std::move(pairing_store)),
      chain_(chain),
      transport_(transport),
      framer_([] {
        while (true) {
          std::array<unsigned char, 4> cid{};
          GetStrongRandBytes(cid);
          const uint32_t value =
              (static_cast<uint32_t>(cid[0]) << 24) |
              (static_cast<uint32_t>(cid[1]) << 16) |
              (static_cast<uint32_t>(cid[2]) << 8) | cid[3];
          if (value != 0 && value != 0xffffffffU) return value;
        }
      }()) {
  if (!pairing_store_) {
    throw std::invalid_argument("BitBox session dependencies are invalid");
  }
}

BitBoxSession::~BitBoxSession() { clearCommandContext(); }

BitBoxStep BitBoxSession::initialize() {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    resetCommand();
    result_.reset();
    initialized_ = false;
    noise_.reset();
    device_info_ = {};
    root_fingerprint_.reset();
    command_ = Command::INITIALIZE;
    command_context_ = InitializationContext{};
    return sendInfo();
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_STATE, e.what());
  }
}

BitBoxStep BitBoxSession::sendInfo() {
  phase_ = Phase::INFO;
  last_new_request_.clear();
  return makeWrite(std::array<unsigned char, 1>{'i'}, UserInteraction::NONE);
}

BitBoxStep BitBoxSession::sendRaw(
    std::vector<unsigned char> payload, Phase phase,
    UserInteraction interaction,
    const std::optional<std::string>& pairing_code) {
  phase_ = phase;
  interaction_ = interaction;
  last_new_request_.clear();
  const bool framed = device_info_.firmware_version.empty() ||
                      FirmwareAtLeast(device_info_.firmware_version, 7, 0, 0);
  last_new_request_.reserve(payload.size() + (framed ? 1 : 0));
  if (framed) last_new_request_.push_back(HWW_NEW);
  last_new_request_.insert(last_new_request_.end(), payload.begin(),
                           payload.end());
  return makeWrite(last_new_request_, interaction, pairing_code);
}

BitBoxStep BitBoxSession::sendEncrypted(std::vector<unsigned char> request,
                                        Phase phase,
                                        UserInteraction interaction) {
  if (!noise_ || !noise_->complete()) {
    return fail(BitBoxErrorCode::INVALID_STATE,
                "BitBox encrypted session is not established");
  }
  std::vector<unsigned char> encrypted;
  try {
    encrypted = noise_->encrypt(request);
  } catch (const std::exception& e) {
    SecureClear(request);
    return fail(BitBoxErrorCode::SESSION_LOST,
                std::string("BitBox Noise encryption failed: ") + e.what());
  } catch (...) {
    SecureClear(request);
    return fail(BitBoxErrorCode::SESSION_LOST,
                "BitBox Noise encryption failed");
  }
  SecureClear(request);
  if (FirmwareAtLeast(device_info_.firmware_version, 4, 0, 0)) {
    encrypted.insert(encrypted.begin(), 'n');
  }
  return sendRaw(std::move(encrypted), phase, interaction);
}

BitBoxStep BitBoxSession::makeWrite(
    std::span<const unsigned char> transport_payload,
    UserInteraction interaction,
    const std::optional<std::string>& pairing_code) {
  BitBoxStep step;
  step.type = BitBoxStepType::WRITE;
  step.interaction = interaction;
  step.pairing_code = pairing_code;
  step.writes = framer_.encode(transport_payload);
  awaiting_retry_poll_response_ =
      request_state_ == RequestState::RETRY_POLL &&
      transport_payload.size() == 1 && transport_payload[0] == HWW_RETRY;
  request_state_ = RequestState::AWAITING_DATA;
  return step;
}

const std::optional<std::string>& BitBoxSession::pairingCode() const {
  static const std::optional<std::string> empty;
  const auto* context =
      std::get_if<InitializationContext>(&command_context_);
  return context == nullptr ? empty : context->pairing_code;
}

BitBoxStep BitBoxSession::onData(std::span<const unsigned char> data) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (request_state_ != RequestState::AWAITING_DATA ||
      command_ == Command::NONE) {
    return fail(BitBoxErrorCode::INVALID_STATE,
                "BitBoxSession received data with no outstanding request");
  }
  try {
    const auto decoded = framer_.decode(data);
    if (decoded.type == U2fDecodeResult::Type::READ_MORE) {
      BitBoxStep step;
      step.type = BitBoxStepType::READ_MORE;
      step.interaction = interaction_;
      step.pairing_code = pairingCode();
      return step;
    }
    const bool retry_poll_response = awaiting_retry_poll_response_;
    awaiting_retry_poll_response_ = false;
    request_state_ = RequestState::IDLE;
    if (decoded.type == U2fDecodeResult::Type::FAILED) {
      if (command_ == Command::ENTER_FIRMWARE_UPGRADE) {
        return finishFirmwareUpgrade();
      }
      return fail(BitBoxErrorCode::PROTOCOL, decoded.error);
    }
    return handleTransportPayload(decoded.payload, retry_poll_response);
  } catch (const std::exception& e) {
    if (command_ == Command::ENTER_FIRMWARE_UPGRADE) {
      return finishFirmwareUpgrade();
    }
    return fail(BitBoxErrorCode::PROTOCOL, e.what());
  }
}

BitBoxStep BitBoxSession::handleTransportPayload(
    std::span<const unsigned char> transport_payload,
    bool retry_poll_response) {
  if (phase_ == Phase::INFO) return handleInfo(transport_payload);
  if (FirmwareBefore(device_info_.firmware_version, 7, 0, 0)) {
    return handleResponse(transport_payload);
  }
  if (transport_payload.empty()) {
    if (command_ == Command::ENTER_FIRMWARE_UPGRADE) {
      return finishFirmwareUpgrade();
    }
    return fail(BitBoxErrorCode::INVALID_RESPONSE,
                "BitBox HWW response is empty");
  }
  switch (transport_payload[0]) {
    case HWW_ACK:
      return handleResponse(transport_payload.subspan(1));
    case HWW_NOT_READY: {
      request_state_ = RequestState::RETRY_POLL;
      BitBoxStep step;
      step.type = BitBoxStepType::RETRY_AFTER;
      step.interaction = interaction_;
      step.retry_after_ms = 200;
      step.pairing_code = pairingCode();
      return step;
    }
    case HWW_BUSY: {
      if (retry_poll_response) {
        return fail(BitBoxErrorCode::INVALID_RESPONSE,
                    "BitBox returned busy while polling an outstanding "
                    "request");
      }
      request_state_ = RequestState::RETRY_RESEND;
      BitBoxStep step;
      step.type = BitBoxStepType::RETRY_AFTER;
      step.interaction = interaction_;
      step.retry_after_ms = 1000;
      step.pairing_code = pairingCode();
      return step;
    }
    case HWW_NACK:
      // The firmware returns NACK when an outstanding request was canceled,
      // for example after its polling timeout. This does not invalidate the
      // established Noise channel; match the official SDK and fail only the
      // current request.
      if (command_ == Command::ENTER_FIRMWARE_UPGRADE) {
        return finishFirmwareUpgrade();
      }
      return fail(BitBoxErrorCode::INVALID_RESPONSE,
                  "BitBox request expired or was canceled; retry the "
                  "operation");
    default:
      if (command_ == Command::ENTER_FIRMWARE_UPGRADE) {
        return finishFirmwareUpgrade();
      }
      return fail(BitBoxErrorCode::INVALID_RESPONSE,
                  "BitBox HWW response has an unknown status");
  }
}

BitBoxStep BitBoxSession::resume() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (request_state_ == RequestState::AWAITING_DATA) {
    return fail(BitBoxErrorCode::INVALID_STATE,
                "BitBoxSession is still awaiting a response");
  }
  if (request_state_ == RequestState::RETRY_POLL) {
    return makeWrite(std::array<unsigned char, 1>{HWW_RETRY}, interaction_,
                     pairingCode());
  }
  if (request_state_ == RequestState::RETRY_RESEND &&
      !last_new_request_.empty()) {
    return makeWrite(last_new_request_, interaction_, pairingCode());
  }
  return fail(BitBoxErrorCode::INVALID_STATE,
              "BitBoxSession has no request to resume");
}

BitBoxStep BitBoxSession::handleInfo(
    std::span<const unsigned char> payload) {
  auto* context = std::get_if<InitializationContext>(&command_context_);
  if (context == nullptr) {
    return fail(BitBoxErrorCode::INVALID_STATE,
                "BitBox initialization context is missing");
  }
  if (payload.empty()) {
    return fail(BitBoxErrorCode::INVALID_RESPONSE,
                "BitBox info response is empty");
  }
  const size_t version_length = payload[0];
  if (payload.size() < 1 + version_length + 3) {
    return fail(BitBoxErrorCode::INVALID_RESPONSE,
                "BitBox info response is truncated");
  }
  device_info_.firmware_version = NormalizeVersion(std::string(
      payload.begin() + 1, payload.begin() + 1 + version_length));
  const size_t offset = 1 + version_length;
  const auto platform = payload[offset];
  const auto edition = payload[offset + 1];
  if ((platform != 0x00 && platform != 0x02) || edition > 1) {
    return fail(BitBoxErrorCode::UNSUPPORTED_DEVICE,
                "Unsupported BitBox02 platform or edition");
  }
  if (transport_ == BitBoxTransport::BLE && platform != 0x02) {
    return fail(BitBoxErrorCode::UNSUPPORTED_DEVICE,
                "Only BitBox02 Nova devices are supported over Bluetooth");
  }
  if (platform == 0x02) {
    device_info_.product = edition == 0 ? BitBoxProduct::NOVA_MULTI
                                        : BitBoxProduct::NOVA_BITCOIN_ONLY;
  } else {
    device_info_.product = edition == 0 ? BitBoxProduct::BITBOX02_MULTI
                                        : BitBoxProduct::BITBOX02_BITCOIN_ONLY;
  }
  if (payload[offset + 2] > 1) {
    return fail(BitBoxErrorCode::INVALID_RESPONSE,
                "BitBox info response has an invalid unlock state");
  }
  device_info_.unlocked = payload[offset + 2] == 1;
  if (payload.size() > offset + 3) {
    device_info_.initialized = payload[offset + 3] == 1;
  }
  try {
    if (!FirmwareBefore(device_info_.firmware_version, 10, 0, 0)) {
      return fail(
          BitBoxErrorCode::UNSUPPORTED_FIRMWARE,
          "BitBox02 firmware 10.0.0 or newer requires an updated Nunchuk "
          "BitBox integration; device has " +
              device_info_.firmware_version);
    }
    device_info_.firmware_upgrade_required =
        FirmwareBefore(device_info_.firmware_version, 9, 0, 0);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_RESPONSE, e.what());
  }

  if (FirmwareBefore(device_info_.firmware_version, 2, 0, 0)) {
    // Firmware 1.x predates attestation and explicit unlock. The official SDK
    // skips both so the device can still be paired and upgraded.
    context->attestation = AttestationStatus::VALID;
    context->attestation_message =
        "BitBox firmware predates device attestation";
    device_info_.unlocked = true;
    return sendRaw({'h'}, Phase::HANDSHAKE_START);
  }

  GetStrongRandBytes(context->attestation_challenge);
  std::vector<unsigned char> request{'a'};
  request.insert(request.end(), context->attestation_challenge.begin(),
                 context->attestation_challenge.end());
  return sendRaw(std::move(request), Phase::ATTESTATION);
}

BitBoxStep BitBoxSession::handleResponse(
    std::span<const unsigned char> payload) {
  if (command_ == Command::INITIALIZE && phase_ != Phase::DEVICE_INFO) {
    return handleInitializeResponse(payload);
  }
  return handleEncryptedResponse(payload);
}

BitBoxStep BitBoxSession::handleInitializeResponse(
    std::span<const unsigned char> payload) {
  auto* context = std::get_if<InitializationContext>(&command_context_);
  if (context == nullptr) {
    return fail(BitBoxErrorCode::INVALID_STATE,
                "BitBox initialization context is missing");
  }
  switch (phase_) {
    case Phase::ATTESTATION: {
      if (payload.empty() || payload[0] != 0) {
        context->attestation = AttestationStatus::INVALID;
        context->attestation_message =
            "BitBox attestation request was rejected";
      } else {
        const auto attestation = VerifyAttestation(
            context->attestation_challenge, payload.subspan(1));
        context->attestation =
            attestation.valid ? AttestationStatus::VALID
                              : AttestationStatus::INVALID;
        context->attestation_message = attestation.message;
      }
      if (FirmwareAtLeast(device_info_.firmware_version, 2, 0, 0)) {
        return sendRaw({'u'}, Phase::UNLOCK, UserInteraction::UNLOCK_DEVICE);
      }
      device_info_.unlocked = true;
      return sendRaw({'h'}, Phase::HANDSHAKE_START);
    }
    case Phase::UNLOCK:
      device_info_.unlocked = true;
      return sendRaw({'h'}, Phase::HANDSHAKE_START);
    case Phase::HANDSHAKE_START: {
      if (payload.size() != 1 || payload[0] != 0) {
        return fail(BitBoxErrorCode::INVALID_RESPONSE,
                    "BitBox rejected Noise handshake start");
      }
      auto app_static_private_key = pairing_store_->appStaticPrivateKey();
      try {
        noise_ = std::make_unique<NoiseHandshake>(app_static_private_key);
      } catch (...) {
        SecureClear(app_static_private_key);
        throw;
      }
      SecureClear(app_static_private_key);
      auto message = noise_->start();
      if (FirmwareAtLeast(device_info_.firmware_version, 7, 0, 0)) {
        message.insert(message.begin(), 'H');
      }
      return sendRaw(std::move(message), Phase::HANDSHAKE_MESSAGE_1);
    }
    case Phase::HANDSHAKE_MESSAGE_1: {
      auto handshake_payload = payload;
      const bool framed =
          FirmwareAtLeast(device_info_.firmware_version, 7, 0, 0);
      if (framed) {
        if (payload.empty() || payload[0] != 0) {
          return fail(BitBoxErrorCode::INVALID_RESPONSE,
                      "BitBox rejected Noise handshake message 1");
        }
        handshake_payload = payload.subspan(1);
      }
      auto message = noise_->finish(handshake_payload);
      context->pairing_code = PairingCode(noise_->channelBinding());
      if (framed) message.insert(message.begin(), 'H');
      return sendRaw(std::move(message), Phase::HANDSHAKE_MESSAGE_3);
    }
    case Phase::HANDSHAKE_MESSAGE_3: {
      bool device_requires_pairing = false;
      if (FirmwareAtLeast(device_info_.firmware_version, 7, 0, 0)) {
        if (payload.size() != 2 || payload[0] != 0 || payload[1] > 1) {
          return fail(
              BitBoxErrorCode::INVALID_RESPONSE,
              "BitBox returned an invalid final Noise handshake response");
        }
        device_requires_pairing = payload[1] == 1;
      } else {
        if (payload.size() != 1 || payload[0] > 1) {
          return fail(
              BitBoxErrorCode::INVALID_RESPONSE,
              "BitBox returned an invalid final Noise handshake response");
        }
        device_requires_pairing = payload[0] == 1;
      }
      const bool known = pairing_store_->containsDevice(
          noise_->remoteStaticPublicKey());
      const bool trusted_transport = transport_ == BitBoxTransport::BLE;
      const bool app_requires_pairing = !trusted_transport && !known;
      if (!device_requires_pairing && !app_requires_pairing) {
        context->app_pairing_confirmed = true;
        context->device_pairing_confirmed = true;
        return finishPairing();
      }
      context->app_pairing_confirmed = trusted_transport || known
                                           ? std::optional<bool>(true)
                                           : std::nullopt;
      context->device_pairing_confirmed = false;
      return sendRaw({'v'}, Phase::PAIRING_VERIFY,
                     UserInteraction::CONFIRM_PAIRING,
                     context->pairing_code);
    }
    case Phase::PAIRING_VERIFY:
      context->device_pairing_confirmed =
          payload.size() == 1 && payload[0] == 0;
      if (!context->device_pairing_confirmed) {
        return fail(BitBoxErrorCode::PAIRING_REJECTED,
                    "BitBox pairing was rejected on the device");
      }
      if (!context->app_pairing_confirmed.has_value()) {
        BitBoxStep step;
        step.type = BitBoxStepType::AWAITING_USER;
        step.interaction = UserInteraction::CONFIRM_PAIRING;
        step.pairing_code = context->pairing_code;
        return step;
      }
      return finishPairing();
    default:
      return fail(BitBoxErrorCode::INVALID_STATE,
                  "BitBox initialization reached an invalid phase");
  }
}

BitBoxStep BitBoxSession::confirmPairing(bool accepted) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto* context = std::get_if<InitializationContext>(&command_context_);
  if (command_ != Command::INITIALIZE ||
      phase_ != Phase::PAIRING_VERIFY || context == nullptr ||
      !context->pairing_code.has_value()) {
    return fail(BitBoxErrorCode::INVALID_STATE,
                "BitBoxSession is not awaiting pairing confirmation");
  }
  context->app_pairing_confirmed = accepted;
  if (!accepted) {
    return fail(BitBoxErrorCode::PAIRING_REJECTED,
                "BitBox pairing was rejected by the app");
  }
  if (!context->device_pairing_confirmed) {
    BitBoxStep step;
    step.type = BitBoxStepType::AWAITING_USER;
    step.interaction = UserInteraction::CONFIRM_PAIRING;
    step.pairing_code = context->pairing_code;
    return step;
  }
  return finishPairing();
}

BitBoxStep BitBoxSession::finishPairing() {
  auto* context = std::get_if<InitializationContext>(&command_context_);
  if (context == nullptr ||
      !context->app_pairing_confirmed.value_or(false) ||
      !context->device_pairing_confirmed) {
    return fail(BitBoxErrorCode::PAIRING_REJECTED,
                "BitBox pairing was not confirmed on both sides");
  }
  pairing_store_->addDevice(noise_->remoteStaticPublicKey());
  context->pairing_code.reset();
  if (device_info_.firmware_upgrade_required) {
    device_info_.password_stretching_algo = "V1";
    initialized_ = true;
    return finish(InitializeResult{device_info_, context->attestation,
                                   context->attestation_message});
  }
  return sendEncrypted(proto::EncodeDeviceInfoRequest(), Phase::DEVICE_INFO);
}

BitBoxStep BitBoxSession::handleEncryptedResponse(
    std::span<const unsigned char> payload) {
  auto encrypted = payload;
  if (FirmwareAtLeast(device_info_.firmware_version, 7, 0, 0)) {
    if (payload.empty() || payload[0] != 0) {
      if (command_ == Command::ENTER_FIRMWARE_UPGRADE) {
        return finishFirmwareUpgrade();
      }
      return fail(BitBoxErrorCode::SESSION_LOST,
                  "BitBox encrypted session was rejected by the device");
    }
    encrypted = payload.subspan(1);
  }
  std::vector<unsigned char> plaintext;
  try {
    plaintext = noise_->decrypt(encrypted);
  } catch (const std::exception& e) {
    if (command_ == Command::ENTER_FIRMWARE_UPGRADE) {
      return finishFirmwareUpgrade();
    }
    return fail(BitBoxErrorCode::SESSION_LOST,
                std::string("BitBox encrypted session failed: ") + e.what());
  }
  try {
    auto result = handleCommandResponse(plaintext);
    SecureClear(plaintext);
    return result;
  } catch (const std::exception& e) {
    SecureClear(plaintext);
    if (command_ == Command::ENTER_FIRMWARE_UPGRADE) {
      return finishFirmwareUpgrade();
    }
    return fail(BitBoxErrorCode::INVALID_RESPONSE,
                std::string("BitBox response processing failed: ") +
                    e.what());
  }
}

BitBoxStep BitBoxSession::handleCommandResponse(
    std::span<const unsigned char> plaintext) {
  const auto response = proto::ParseResponse(plaintext, device_info_);
  if (const auto* device_error = std::get_if<proto::DeviceError>(&response)) {
    const auto error = DeviceError(*device_error);
    return fail(error.code, error.message, error.device_code);
  }

  if (phase_ == Phase::DEVICE_INFO ||
      phase_ == Phase::REFRESH_DEVICE_INFO) {
    const auto* device_info =
        std::get_if<proto::DeviceInfoResponse>(&response);
    if (device_info == nullptr) {
      return fail(BitBoxErrorCode::INVALID_RESPONSE,
                  "BitBox returned an unexpected device-info response");
    }
    device_info_ = device_info->device;
    device_info_.firmware_upgrade_required = false;
    if (FirmwareBefore(device_info_.firmware_version, 9, 25, 0)) {
      device_info_.password_stretching_algo = "V1";
    }
    if (phase_ == Phase::REFRESH_DEVICE_INFO) {
      return finish(std::monostate{});
    }
    const auto* context =
        std::get_if<InitializationContext>(&command_context_);
    if (context == nullptr) {
      return fail(BitBoxErrorCode::INVALID_STATE,
                  "BitBox initialization context is missing");
    }
    initialized_ = true;
    return finish(InitializeResult{device_info_, context->attestation,
                                   context->attestation_message});
  }

  switch (command_) {
    case Command::SET_DEVICE_NAME:
    case Command::CREATE_NEW_SEED:
    case Command::SHOW_MNEMONIC:
    case Command::CREATE_BACKUP:
    case Command::RESTORE_BACKUP:
    case Command::RESTORE_FROM_MNEMONIC:
      if (!std::holds_alternative<proto::SuccessResponse>(response)) {
        return fail(BitBoxErrorCode::INVALID_RESPONSE,
                    "BitBox returned an unexpected setup response");
      }
      return sendEncrypted(proto::EncodeDeviceInfoRequest(),
                           Phase::REFRESH_DEVICE_INFO);
    case Command::ENTER_FIRMWARE_UPGRADE:
      return finishFirmwareUpgrade();
    case Command::INSERT_SD_CARD:
      if (!std::holds_alternative<proto::SuccessResponse>(response)) {
        return fail(BitBoxErrorCode::INVALID_RESPONSE,
                    "BitBox returned an unexpected microSD response");
      }
      return finish(std::monostate{});
    case Command::CHECK_SD_CARD: {
      const auto* sd_card =
          std::get_if<proto::CheckSdCardResponse>(&response);
      if (sd_card == nullptr) {
        return fail(BitBoxErrorCode::INVALID_RESPONSE,
                    "BitBox returned an unexpected microSD status response");
      }
      return finish(SdCardStatusResult{sd_card->inserted});
    }
    case Command::LIST_BACKUPS: {
      const auto* backups =
          std::get_if<proto::ListBackupsResponse>(&response);
      if (backups == nullptr) {
        return fail(BitBoxErrorCode::INVALID_RESPONSE,
                    "BitBox returned an unexpected backup-list response");
      }
      return finish(ListBackupsResult{backups->backups});
    }
    default:
      break;
  }

  if (phase_ == Phase::FETCH_FINGERPRINT ||
      command_ == Command::GET_FINGERPRINT) {
    const auto* fingerprint_response =
        std::get_if<proto::FingerprintResponse>(&response);
    if (fingerprint_response == nullptr) {
      return fail(BitBoxErrorCode::INVALID_RESPONSE,
                  "BitBox returned an unexpected fingerprint response");
    }
    const auto& fingerprint = fingerprint_response->fingerprint;
    if (fingerprint.size() != 4) {
      return fail(BitBoxErrorCode::INVALID_RESPONSE,
                  "BitBox returned an invalid root fingerprint");
    }
    root_fingerprint_ = HexStr(fingerprint);
    if (phase_ == Phase::FETCH_FINGERPRINT) return continueAfterFingerprint();
    return finish(GetMasterFingerprintResult{*root_fingerprint_});
  }

  if (command_ == Command::GET_XPUB) {
    const auto* pub = std::get_if<proto::PubResponse>(&response);
    if (pub == nullptr) {
      return fail(BitBoxErrorCode::INVALID_RESPONSE,
                  "BitBox returned an unexpected xpub response");
    }
    return finish(GetExtendedPublicKeyResult{pub->pub});
  }

  if (command_ == Command::GET_ADDRESS) {
    const auto* pub = std::get_if<proto::PubResponse>(&response);
    if (pub == nullptr) {
      return fail(BitBoxErrorCode::INVALID_RESPONSE,
                  "BitBox returned an unexpected address response");
    }
    return finish(WalletAddressResult{pub->pub});
  }

  const auto* bitcoin = std::get_if<proto::BitcoinResponse>(&response);
  if (command_ == Command::CHECK_REGISTRATION) {
    const auto* registration =
        bitcoin == nullptr
            ? nullptr
            : std::get_if<proto::RegistrationResponse>(&bitcoin->value);
    if (registration == nullptr) {
      return fail(BitBoxErrorCode::INVALID_RESPONSE,
                  "BitBox returned an unexpected registration response");
    }
    auto* context = std::get_if<WalletCommandContext>(&command_context_);
    if (context == nullptr) {
      return fail(BitBoxErrorCode::INVALID_STATE,
                  "BitBox wallet-registration context is missing");
    }
    if (!registration->registered) {
      return finish(RegistrationResult{false});
    }
    ++context->registration_account_index;
    return continueRegistration(*context);
  }
  if (command_ == Command::REGISTER_WALLET) {
    if (bitcoin == nullptr ||
        !std::holds_alternative<proto::BitcoinSuccessResponse>(
            bitcoin->value)) {
      return fail(BitBoxErrorCode::INVALID_RESPONSE,
                  "BitBox returned an unexpected wallet-registration response");
    }
    auto* context = std::get_if<WalletCommandContext>(&command_context_);
    if (context == nullptr) {
      return fail(BitBoxErrorCode::INVALID_STATE,
                  "BitBox wallet-registration context is missing");
    }
    ++context->registration_account_index;
    return continueRegistration(*context);
  }
  if (command_ == Command::SIGN_MESSAGE) {
    auto* context =
        std::get_if<MessageSigningContext>(&command_context_);
    if (context == nullptr) {
      return fail(BitBoxErrorCode::INVALID_STATE,
                  "BitBox message-signing context is missing");
    }
    if (phase_ == Phase::MESSAGE_COMMITMENT) {
      const auto* commitment =
          bitcoin == nullptr
              ? nullptr
              : std::get_if<proto::SignerCommitmentResponse>(&bitcoin->value);
      if (commitment == nullptr || !context->anti_klepto.has_value()) {
        return fail(BitBoxErrorCode::INVALID_RESPONSE,
                    "BitBox returned an unexpected anti-klepto commitment");
      }
      auto& anti_klepto = *context->anti_klepto;
      anti_klepto.signer_commitment = commitment->commitment;
      return sendEncrypted(
          proto::EncodeAntiKleptoSignatureRequest(anti_klepto.host_nonce),
          Phase::MESSAGE_SIGNATURE, UserInteraction::SIGN_MESSAGE);
    }
    if (phase_ == Phase::MESSAGE_SIGNATURE) {
      const auto* message_signature =
          bitcoin == nullptr
              ? nullptr
              : std::get_if<proto::MessageSignatureResponse>(&bitcoin->value);
      if (message_signature == nullptr) {
        return fail(BitBoxErrorCode::INVALID_RESPONSE,
                    "BitBox returned an unexpected message signature");
      }
      const auto& signature = message_signature->signature;
      if (signature.size() != 65) {
        return fail(BitBoxErrorCode::INVALID_RESPONSE,
                    "BitBox returned an invalid message signature");
      }
      if (signature[64] > 3) {
        return fail(BitBoxErrorCode::INVALID_RESPONSE,
                    "BitBox returned an invalid message recovery ID");
      }
      if (FirmwareAtLeast(device_info_.firmware_version, 9, 5, 0)) {
        if (!context->anti_klepto.has_value()) {
          return fail(BitBoxErrorCode::INVALID_STATE,
                      "BitBox message anti-klepto context is missing");
        }
        const auto& anti_klepto = *context->anti_klepto;
        std::string error;
        if (!VerifyAntiKlepto(anti_klepto.host_nonce,
                              anti_klepto.signer_commitment,
                              std::span(signature).first(64), error)) {
          return fail(BitBoxErrorCode::ANTI_KLEPTO, error);
        }
      }
      std::vector<unsigned char> electrum_signature;
      electrum_signature.reserve(65);
      electrum_signature.push_back(31 + signature[64]);
      electrum_signature.insert(electrum_signature.end(), signature.begin(),
                                signature.begin() + 64);
      return finish(SignMessageResult{EncodeBase64(electrum_signature)});
    }
  }
  if (command_ == Command::SIGN_PSBT) {
    const auto* next_response = std::get_if<proto::SignNext>(&response);
    if (next_response == nullptr && bitcoin != nullptr) {
      next_response = std::get_if<proto::SignNext>(&bitcoin->value);
    }
    if (next_response == nullptr) {
      return fail(BitBoxErrorCode::INVALID_RESPONSE,
                  "BitBox returned an unexpected PSBT response");
    }
    auto* context = std::get_if<PsbtSigningContext>(&command_context_);
    if (context == nullptr || !context->prepared_psbt.has_value()) {
      return fail(BitBoxErrorCode::INVALID_STATE,
                  "BitBox PSBT signing context is missing");
    }
    const auto& next = *next_response;
    auto& prepared_psbt = *context->prepared_psbt;
    try {
      if (context->pending_signature_input.has_value()) {
        const auto signed_index = *context->pending_signature_input;
        const bool was_second_pass = context->second_pass;
        const bool awaiting_signer_commitment =
            was_second_pass && context->anti_klepto.has_value() &&
            context->anti_klepto->signer_commitment.empty();
        if (awaiting_signer_commitment) {
          if (next.type != proto::SignNext::Type::HOST_NONCE) {
            throw std::invalid_argument(
                "BitBox PSBT response has no anti-klepto commitment");
          }
        } else if (was_second_pass) {
          if (!next.has_signature) {
            throw std::invalid_argument(
                "BitBox PSBT response has no second-pass signature");
          }
          if (context->anti_klepto.has_value()) {
            const auto& anti_klepto = *context->anti_klepto;
            std::string error;
            if (!VerifyAntiKlepto(anti_klepto.host_nonce,
                                  anti_klepto.signer_commitment,
                                  next.signature, error)) {
              return fail(BitBoxErrorCode::ANTI_KLEPTO, error);
            }
            SecureClear(context->anti_klepto->host_nonce);
            SecureClear(context->anti_klepto->signer_commitment);
            context->anti_klepto.reset();
          }
          ApplyPsbtSignature(prepared_psbt, signed_index, next.signature);
          context->pending_signature_input.reset();
        } else {
          // The first input pass collects transaction data and does not
          // produce signatures. Match the official SDK and ignore any
          // signature fields until the second pass.
          context->pending_signature_input.reset();
        }
        if (!was_second_pass &&
            signed_index + 1 == prepared_psbt.inputs.size()) {
          context->second_pass = true;
        }
      }
      switch (next.type) {
        case proto::SignNext::Type::INPUT: {
          if (next.index >= prepared_psbt.inputs.size()) {
            throw std::invalid_argument("BitBox requested an invalid PSBT input");
          }
          auto input = prepared_psbt.inputs[next.index];
          const bool anti_klepto =
              context->second_pass &&
              prepared_psbt.keys.at(next.index).type ==
                  PsbtInputKey::Type::ECDSA &&
              FirmwareAtLeast(device_info_.firmware_version, 9, 4, 0);
          if (anti_klepto) {
            auto& anti_klepto_context = context->anti_klepto.emplace();
            GetStrongRandBytes(anti_klepto_context.host_nonce);
            const auto commitment = AntiKleptoHostCommitment(
                anti_klepto_context.host_nonce);
            input.host_nonce_commitment.assign(commitment.begin(),
                                               commitment.end());
          }
          context->pending_signature_input = next.index;
          return sendEncrypted(proto::EncodeSignInputRequest(input),
                               Phase::PSBT_RESPONSE,
                               UserInteraction::SIGN_TRANSACTION);
        }
        case proto::SignNext::Type::OUTPUT:
          if (next.index >= prepared_psbt.outputs.size()) {
            throw std::invalid_argument("BitBox requested an invalid PSBT output");
          }
          return sendEncrypted(
              proto::EncodeSignOutputRequest(prepared_psbt.outputs[next.index]),
              Phase::PSBT_RESPONSE, UserInteraction::SIGN_TRANSACTION);
        case proto::SignNext::Type::PREVIOUS_TRANSACTION_INIT: {
          const auto previous =
              PreviousTransactionInit(prepared_psbt, next.index);
          return sendEncrypted(
              proto::EncodePreviousTransactionInitRequest(
                  previous.version, previous.input_count,
                  previous.output_count, previous.locktime),
              Phase::PSBT_RESPONSE, UserInteraction::SIGN_TRANSACTION);
        }
        case proto::SignNext::Type::PREVIOUS_TRANSACTION_INPUT:
          return sendEncrypted(
              proto::EncodePreviousTransactionInputRequest(
                  PreviousTransactionInput(prepared_psbt, next.index,
                                           next.previous_index)),
              Phase::PSBT_RESPONSE, UserInteraction::SIGN_TRANSACTION);
        case proto::SignNext::Type::PREVIOUS_TRANSACTION_OUTPUT:
          return sendEncrypted(
              proto::EncodePreviousTransactionOutputRequest(
                  PreviousTransactionOutput(prepared_psbt, next.index,
                                            next.previous_index)),
              Phase::PSBT_RESPONSE, UserInteraction::SIGN_TRANSACTION);
        case proto::SignNext::Type::HOST_NONCE:
          if (!context->anti_klepto.has_value() ||
              next.signer_commitment.empty()) {
            throw std::invalid_argument(
                "BitBox PSBT anti-klepto response is invalid");
          }
          context->anti_klepto->signer_commitment = next.signer_commitment;
          return sendEncrypted(
              proto::EncodeAntiKleptoSignatureRequest(
                  context->anti_klepto->host_nonce),
              Phase::PSBT_RESPONSE, UserInteraction::SIGN_TRANSACTION);
        case proto::SignNext::Type::DONE: {
          auto signed_psbt = FinishPsbt(prepared_psbt);
          if (context->signing_account_keypath_index + 1 <
              context->signing_account_keypaths.size()) {
            context->encoded_psbt = signed_psbt.psbt;
            ++context->signing_account_keypath_index;
            return startPsbtPass(
                *context,
                context->signing_account_keypaths
                    [context->signing_account_keypath_index]);
          }
          return finish(std::move(signed_psbt));
        }
        case proto::SignNext::Type::PAYMENT_REQUEST:
          throw std::invalid_argument(
              "BitBox payment requests are not supported by this integration");
      }
    } catch (const std::exception& e) {
      return fail(BitBoxErrorCode::INVALID_PSBT, e.what());
    }
  }
  return fail(BitBoxErrorCode::INVALID_STATE,
              "BitBox response has no command handler");
}

std::optional<BitBoxStep> BitBoxSession::requireReady(
    bool allow_firmware_upgrade_required) {
  if (!initialized_ || !noise_ || !noise_->complete()) {
    return fail(BitBoxErrorCode::INVALID_STATE,
                "BitBoxSession must be initialized first");
  }
  if (command_ != Command::NONE) {
    return fail(BitBoxErrorCode::INVALID_STATE,
                "BitBoxSession already has an active command");
  }
  if (device_info_.firmware_upgrade_required &&
      !allow_firmware_upgrade_required) {
    return fail(BitBoxErrorCode::UNSUPPORTED_FIRMWARE,
                "BitBox02 firmware 9.0.0 or newer is required; upgrade the "
                "connected device from firmware " +
                    device_info_.firmware_version);
  }
  return std::nullopt;
}

std::optional<BitBoxStep> BitBoxSession::requireDeviceInitialized() {
  if (device_info_.initialized) return std::nullopt;
  return fail(BitBoxErrorCode::DEVICE_UNINITIALIZED,
              "BitBox02 is not set up. Complete device setup before requesting "
              "a wallet operation.");
}

BitBoxStep BitBoxSession::setDeviceName(const std::string& name) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    result_.reset();
    command_ = Command::SET_DEVICE_NAME;
    return sendEncrypted(proto::EncodeSetDeviceNameRequest(name),
                         Phase::COMMAND_RESPONSE,
                         UserInteraction::CONFIRM_DEVICE_NAME);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_ARGUMENT, e.what());
  }
}

BitBoxStep BitBoxSession::createNewSeed(
    BitBoxMnemonicLength mnemonic_length) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<unsigned char> entropy;
  try {
    if (auto error = requireReady()) return *error;
    if (device_info_.initialized) {
      return fail(BitBoxErrorCode::INVALID_STATE,
                  "BitBox02 is already initialized");
    }
    size_t entropy_size = 0;
    switch (mnemonic_length) {
      case BitBoxMnemonicLength::WORDS_12:
        if (!FirmwareAtLeast(device_info_.firmware_version, 9, 6, 0)) {
          return fail(
              BitBoxErrorCode::UNSUPPORTED_FIRMWARE,
              "Creating a 12-word BitBox seed requires firmware 9.6.0 or "
              "newer; device has " +
                  device_info_.firmware_version);
        }
        entropy_size = 16;
        break;
      case BitBoxMnemonicLength::WORDS_24:
        entropy_size = 32;
        break;
      default:
        throw std::invalid_argument(
            "BitBox recovery word count must be 12 or 24");
    }
    result_.reset();
    root_fingerprint_.reset();
    command_ = Command::CREATE_NEW_SEED;
    entropy.resize(entropy_size);
    GetStrongRandBytes(entropy);
    auto request = proto::EncodeSetPasswordRequest(entropy);
    SecureClear(entropy);
    return sendEncrypted(std::move(request), Phase::COMMAND_RESPONSE,
                         UserInteraction::SET_DEVICE_PASSWORD);
  } catch (const std::exception& e) {
    SecureClear(entropy);
    return fail(BitBoxErrorCode::INVALID_ARGUMENT, e.what());
  }
}

BitBoxStep BitBoxSession::showMnemonic() {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    if (!device_info_.initialized &&
        !FirmwareAtLeast(device_info_.firmware_version, 9, 13, 0)) {
      return fail(
          BitBoxErrorCode::UNSUPPORTED_FIRMWARE,
          "Using recovery words as the initial BitBox backup requires "
          "firmware 9.13.0 or newer; device has " +
              device_info_.firmware_version);
    }
    result_.reset();
    command_ = Command::SHOW_MNEMONIC;
    return sendEncrypted(proto::EncodeShowMnemonicRequest(),
                         Phase::COMMAND_RESPONSE,
                         UserInteraction::SHOW_RECOVERY_WORDS);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_STATE, e.what());
  }
}

BitBoxStep BitBoxSession::checkSdCard() {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    result_.reset();
    command_ = Command::CHECK_SD_CARD;
    return sendEncrypted(proto::EncodeCheckSdCardRequest(),
                         Phase::COMMAND_RESPONSE);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_STATE, e.what());
  }
}

BitBoxStep BitBoxSession::insertSdCard() {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    result_.reset();
    command_ = Command::INSERT_SD_CARD;
    return sendEncrypted(proto::EncodeInsertSdCardRequest(),
                         Phase::COMMAND_RESPONSE,
                         UserInteraction::INSERT_SD_CARD);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_STATE, e.what());
  }
}

BitBoxStep BitBoxSession::createBackup() {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    const auto date_time = CurrentDeviceDateTime();
    result_.reset();
    command_ = Command::CREATE_BACKUP;
    return sendEncrypted(
        proto::EncodeCreateBackupRequest(date_time.timestamp,
                                         date_time.timezone_offset),
        Phase::COMMAND_RESPONSE, UserInteraction::CREATE_BACKUP);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_STATE, e.what());
  }
}

BitBoxStep BitBoxSession::listBackups() {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    result_.reset();
    command_ = Command::LIST_BACKUPS;
    return sendEncrypted(proto::EncodeListBackupsRequest(),
                         Phase::COMMAND_RESPONSE);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_STATE, e.what());
  }
}

BitBoxStep BitBoxSession::restoreBackup(const std::string& id) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    if (device_info_.initialized) {
      return fail(BitBoxErrorCode::INVALID_STATE,
                  "BitBox02 is already initialized");
    }
    const auto date_time = CurrentDeviceDateTime();
    result_.reset();
    root_fingerprint_.reset();
    command_ = Command::RESTORE_BACKUP;
    return sendEncrypted(
        proto::EncodeRestoreBackupRequest(
            id, date_time.timestamp, date_time.timezone_offset),
        Phase::COMMAND_RESPONSE, UserInteraction::RESTORE_FROM_BACKUP);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_ARGUMENT, e.what());
  }
}

BitBoxStep BitBoxSession::restoreFromMnemonic() {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    if (device_info_.initialized) {
      return fail(BitBoxErrorCode::INVALID_STATE,
                  "BitBox02 is already initialized");
    }
    const auto date_time = CurrentDeviceDateTime();
    result_.reset();
    root_fingerprint_.reset();
    command_ = Command::RESTORE_FROM_MNEMONIC;
    return sendEncrypted(
        proto::EncodeRestoreFromMnemonicRequest(
            date_time.timestamp, date_time.timezone_offset),
        Phase::COMMAND_RESPONSE,
        UserInteraction::RESTORE_FROM_RECOVERY_WORDS);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_STATE, e.what());
  }
}

BitBoxStep BitBoxSession::enterFirmwareUpgrade() {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady(true)) return *error;
    result_.reset();
    command_ = Command::ENTER_FIRMWARE_UPGRADE;
    return sendEncrypted(
        proto::EncodeRebootToBootloaderRequest(), Phase::COMMAND_RESPONSE,
        UserInteraction::CONFIRM_FIRMWARE_UPGRADE);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_STATE, e.what());
  }
}

BitBoxStep BitBoxSession::getExtendedPublicKey(
    const std::string& derivation_path,
    const GetExtendedPublicKeyOptions& options) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    if (auto error = requireDeviceInitialized()) return *error;
    result_.reset();
    command_ = Command::GET_XPUB;
    if (chain_ == Chain::REGTEST &&
        !FirmwareAtLeast(device_info_.firmware_version, 9, 21, 0)) {
      return fail(BitBoxErrorCode::UNSUPPORTED_FIRMWARE,
                  "BitBox regtest support requires firmware 9.21.0 or newer; "
                  "device has " +
                      device_info_.firmware_version);
    }
    return sendEncrypted(
        proto::EncodeXpubRequest(CoinForChain(chain_),
                                 ParseKeypath(derivation_path),
                                 options.check_on_device),
        Phase::COMMAND_RESPONSE,
        options.check_on_device ? UserInteraction::VERIFY_ADDRESS
                                : UserInteraction::NONE);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_ARGUMENT, e.what());
  }
}

BitBoxStep BitBoxSession::getMasterFingerprint() {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    if (auto error = requireDeviceInitialized()) return *error;
    result_.reset();
    command_ = Command::GET_FINGERPRINT;
    return sendEncrypted(proto::EncodeFingerprintRequest(),
                         Phase::COMMAND_RESPONSE);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_STATE, e.what());
  }
}

BitBoxStep BitBoxSession::requireFingerprintOrContinue() {
  if (!root_fingerprint_.has_value()) {
    return sendEncrypted(proto::EncodeFingerprintRequest(),
                         Phase::FETCH_FINGERPRINT);
  }
  return continueAfterFingerprint();
}

BitBoxStep BitBoxSession::isWalletRegistered(const Wallet& wallet) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    if (auto error = requireDeviceInitialized()) return *error;
    result_.reset();
    command_ = Command::CHECK_REGISTRATION;
    command_context_ = WalletCommandContext{wallet};
    return requireFingerprintOrContinue();
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::UNSUPPORTED_WALLET, e.what());
  }
}

BitBoxStep BitBoxSession::registerWallet(const Wallet& wallet) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    if (auto error = requireDeviceInitialized()) return *error;
    result_.reset();
    command_ = Command::REGISTER_WALLET;
    command_context_ = WalletCommandContext{wallet};
    return requireFingerprintOrContinue();
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::UNSUPPORTED_WALLET, e.what());
  }
}

BitBoxStep BitBoxSession::getWalletAddress(
    const Wallet& wallet, uint32_t address_index,
    const WalletAddressOptions& options) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    if (auto error = requireDeviceInitialized()) return *error;
    result_.reset();
    command_ = Command::GET_ADDRESS;
    command_context_ = AddressCommandContext{wallet, address_index, options};
    return requireFingerprintOrContinue();
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::UNSUPPORTED_WALLET, e.what());
  }
}

BitBoxStep BitBoxSession::continueRegistration(
    WalletCommandContext& context) {
  if (!root_fingerprint_.has_value()) {
    return fail(BitBoxErrorCode::INVALID_STATE,
                "BitBox root fingerprint is missing");
  }
  const auto wallet = BuildWalletConfig(context.wallet, *root_fingerprint_);
  if (wallet.accounts.empty()) {
    return fail(BitBoxErrorCode::UNSUPPORTED_WALLET,
                "BitBox wallet has no owned account");
  }
  if (wallet.script_config.kind == proto::ScriptConfig::Kind::SIMPLE) {
    return finish(RegistrationResult{true});
  }
  const size_t registration_count =
      wallet.script_config.kind == proto::ScriptConfig::Kind::POLICY
          ? 1
          : wallet.accounts.size();
  if (context.registration_account_index >= registration_count) {
    return finish(RegistrationResult{true});
  }
  const size_t account_index =
      wallet.script_config.kind == proto::ScriptConfig::Kind::POLICY
          ? 0
          : context.registration_account_index;
  const auto script_config = ScriptConfigForAccount(wallet, account_index);
  const std::vector<uint32_t> registration_keypath =
      wallet.script_config.kind == proto::ScriptConfig::Kind::POLICY
          ? std::vector<uint32_t>{}
          : wallet.accounts[account_index].keypath;
  if (command_ == Command::CHECK_REGISTRATION) {
    return sendEncrypted(
        proto::EncodeIsRegisteredRequest(CoinForChain(chain_), script_config,
                                         registration_keypath),
        Phase::COMMAND_RESPONSE);
  }
  if (command_ == Command::REGISTER_WALLET) {
    return sendEncrypted(
        proto::EncodeRegisterRequest(
            CoinForChain(chain_), script_config, registration_keypath,
            RegistrationName(context.wallet.get_name(), account_index,
                             registration_count)),
        Phase::COMMAND_RESPONSE, UserInteraction::REGISTER_WALLET);
  }
  return fail(BitBoxErrorCode::INVALID_STATE,
              "BitBox registration has an invalid command");
}

BitBoxStep BitBoxSession::startPsbtPass(
    PsbtSigningContext& context,
    const std::optional<std::vector<uint32_t>>& account_keypath) {
  context.prepared_psbt =
      PreparePsbt(context.encoded_psbt, context.wallet, *root_fingerprint_,
                  device_info_.firmware_version, account_keypath);
  if (!account_keypath.has_value()) {
    context.signing_account_keypaths =
        context.prepared_psbt->signing_account_keypaths;
    context.signing_account_keypath_index = 0;
  }
  context.encoded_psbt.clear();
  context.second_pass = false;
  context.pending_signature_input.reset();
  if (context.anti_klepto.has_value()) {
    SecureClear(context.anti_klepto->host_nonce);
    SecureClear(context.anti_klepto->signer_commitment);
  }
  context.anti_klepto.reset();
  const auto& prepared_psbt = *context.prepared_psbt;
  return sendEncrypted(
      proto::EncodeSignInitRequest(
          CoinForChain(chain_), prepared_psbt.script_configs,
          prepared_psbt.psbt.tx->version, prepared_psbt.inputs.size(),
          prepared_psbt.outputs.size(), prepared_psbt.psbt.tx->nLockTime),
      Phase::PSBT_RESPONSE, UserInteraction::SIGN_TRANSACTION);
}

BitBoxStep BitBoxSession::continueAfterFingerprint() {
  const Wallet* command_wallet = nullptr;
  if (const auto* context =
          std::get_if<WalletCommandContext>(&command_context_)) {
    command_wallet = &context->wallet;
  } else if (const auto* context =
                 std::get_if<AddressCommandContext>(&command_context_)) {
    command_wallet = &context->wallet;
  } else if (const auto* context =
                 std::get_if<PsbtSigningContext>(&command_context_)) {
    command_wallet = &context->wallet;
  }
  if (!root_fingerprint_.has_value() || command_wallet == nullptr) {
    return fail(BitBoxErrorCode::INVALID_STATE,
                "BitBox wallet command is missing its context");
  }
  try {
    const auto wallet = BuildWalletConfig(*command_wallet, *root_fingerprint_);
    if (chain_ == Chain::REGTEST &&
        !FirmwareAtLeast(device_info_.firmware_version, 9, 21, 0)) {
      return fail(BitBoxErrorCode::UNSUPPORTED_FIRMWARE,
                  "BitBox regtest support requires firmware 9.21.0 or newer; "
                  "device has " +
                      device_info_.firmware_version);
    }
    const auto wallet_type = command_wallet->get_wallet_type();
    const auto address_type = command_wallet->get_address_type();
    if (wallet_type == WalletType::MINISCRIPT &&
        address_type == AddressType::TAPROOT &&
        !FirmwareAtLeast(device_info_.firmware_version, 9, 21, 0)) {
      return fail(BitBoxErrorCode::UNSUPPORTED_FIRMWARE,
                  "BitBox Taproot wallet policies require firmware 9.21.0 "
                  "or newer; device has " +
                      device_info_.firmware_version);
    }
    if (wallet_type == WalletType::MINISCRIPT &&
        address_type != AddressType::TAPROOT &&
        !FirmwareAtLeast(device_info_.firmware_version, 9, 15, 0)) {
      return fail(BitBoxErrorCode::UNSUPPORTED_FIRMWARE,
                  "BitBox Miniscript wallet policies require firmware "
                  "9.15.0 or newer; device has " +
                      device_info_.firmware_version);
    }
    if (wallet_type != WalletType::MINISCRIPT &&
        address_type == AddressType::TAPROOT &&
        !FirmwareAtLeast(device_info_.firmware_version, 9, 10, 0)) {
      return fail(BitBoxErrorCode::UNSUPPORTED_FIRMWARE,
                  "BitBox Taproot requires firmware 9.10.0 or newer; "
                  "device has " +
                      device_info_.firmware_version);
    }
    switch (command_) {
      case Command::CHECK_REGISTRATION:
      case Command::REGISTER_WALLET: {
        auto* context = std::get_if<WalletCommandContext>(&command_context_);
        if (context == nullptr) {
          return fail(BitBoxErrorCode::INVALID_STATE,
                      "BitBox wallet-registration context is missing");
        }
        context->registration_account_index = 0;
        return continueRegistration(*context);
      }
      case Command::GET_ADDRESS: {
        const auto* context =
            std::get_if<AddressCommandContext>(&command_context_);
        if (context == nullptr) {
          return fail(BitBoxErrorCode::INVALID_STATE,
                      "BitBox address command context is missing");
        }
        return sendEncrypted(
            proto::EncodeAddressRequest(
                CoinForChain(chain_),
                BuildAddressKeypath(wallet, context->options.change,
                                    context->address_index),
                ScriptConfigForAccount(wallet, 0),
                context->options.check_on_device),
            Phase::COMMAND_RESPONSE,
            context->options.check_on_device
                ? UserInteraction::VERIFY_ADDRESS
                : UserInteraction::NONE);
      }
      case Command::SIGN_PSBT: {
        auto* context =
            std::get_if<PsbtSigningContext>(&command_context_);
        if (context == nullptr) {
          return fail(BitBoxErrorCode::INVALID_STATE,
                      "BitBox PSBT signing context is missing");
        }
        try {
          return startPsbtPass(*context);
        } catch (const std::exception& e) {
          return fail(BitBoxErrorCode::INVALID_PSBT, e.what());
        }
      }
      default:
        return fail(BitBoxErrorCode::INVALID_STATE,
                    "BitBox fingerprint was fetched for an invalid command");
    }
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::UNSUPPORTED_WALLET, e.what());
  }
}

BitBoxStep BitBoxSession::signMessage(const std::string& derivation_path,
                                      const std::string& message) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    if (auto error = requireDeviceInitialized()) return *error;
    result_.reset();
    command_ = Command::SIGN_MESSAGE;
    command_context_ = MessageSigningContext{};
    const auto config = BuildMessageConfig(derivation_path);
    if (!FirmwareAtLeast(device_info_.firmware_version, 9, 2, 0)) {
      return fail(BitBoxErrorCode::UNSUPPORTED_FIRMWARE,
                  "BitBox message signing requires firmware 9.2.0 or newer; "
                  "device has " +
                      device_info_.firmware_version);
    }
    if (chain_ != Chain::MAIN &&
        !FirmwareAtLeast(device_info_.firmware_version, 9, 23, 0)) {
      return fail(BitBoxErrorCode::UNSUPPORTED_FIRMWARE,
                  "BitBox message signing on test networks requires firmware "
                  "9.23.0 or newer; device has " +
                      device_info_.firmware_version);
    }
    std::vector<unsigned char> commitment;
    auto phase = Phase::MESSAGE_SIGNATURE;
    if (FirmwareAtLeast(device_info_.firmware_version, 9, 5, 0)) {
      auto& anti_klepto =
          std::get<MessageSigningContext>(command_context_)
              .anti_klepto.emplace();
      GetStrongRandBytes(anti_klepto.host_nonce);
      const auto hash = AntiKleptoHostCommitment(anti_klepto.host_nonce);
      commitment.assign(hash.begin(), hash.end());
      phase = Phase::MESSAGE_COMMITMENT;
    }
    return sendEncrypted(
        proto::EncodeSignMessageRequest(
            CoinForChain(chain_), config,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(message.data()),
                message.size()),
            commitment),
        phase, UserInteraction::SIGN_MESSAGE);
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_ARGUMENT, e.what());
  }
}

BitBoxStep BitBoxSession::signPsbt(const Wallet& wallet,
                                   const std::string& psbt) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (auto error = requireReady()) return *error;
    if (auto error = requireDeviceInitialized()) return *error;
    result_.reset();
    command_ = Command::SIGN_PSBT;
    command_context_ = PsbtSigningContext{wallet, psbt};
    return requireFingerprintOrContinue();
  } catch (const std::exception& e) {
    return fail(BitBoxErrorCode::INVALID_PSBT, e.what());
  }
}

BitBoxStep BitBoxSession::finish(BitBoxValue value) {
  result_ = std::move(value);
  resetCommand();
  BitBoxStep step;
  step.type = BitBoxStepType::COMPLETE;
  const auto* initialize_result =
      std::get_if<InitializeResult>(&*result_);
  if (initialize_result != nullptr &&
      initialize_result->attestation == AttestationStatus::INVALID) {
    step.warning = initialize_result->attestation_message;
  }
  return step;
}

BitBoxStep BitBoxSession::finishFirmwareUpgrade() {
  initialized_ = false;
  noise_.reset();
  return finish(std::monostate{});
}

BitBoxStep BitBoxSession::fail(BitBoxErrorCode code,
                               const std::string& message,
                               int device_code) {
  const bool initialization_failed = command_ == Command::INITIALIZE;
  if (initialization_failed) initialized_ = false;
  result_.reset();
  if (initialization_failed || code == BitBoxErrorCode::SESSION_LOST ||
      code == BitBoxErrorCode::DEVICE_NOISE_ENCRYPT ||
      code == BitBoxErrorCode::DEVICE_NOISE_DECRYPT) {
    initialized_ = false;
    noise_.reset();
  }
  resetCommand();
  BitBoxStep step;
  step.type = BitBoxStepType::FAILED;
  step.error = BitBoxError{code, message, device_code};
  return step;
}

void BitBoxSession::resetCommand() {
  command_ = Command::NONE;
  phase_ = Phase::NONE;
  request_state_ = RequestState::IDLE;
  awaiting_retry_poll_response_ = false;
  interaction_ = UserInteraction::NONE;
  last_new_request_.clear();
  clearCommandContext();
  framer_.reset();
}

void BitBoxSession::clearCommandContext() {
  const auto clear_anti_klepto =
      [](std::optional<AntiKleptoContext>& anti_klepto) {
        if (!anti_klepto.has_value()) return;
        SecureClear(anti_klepto->host_nonce);
        SecureClear(anti_klepto->signer_commitment);
        anti_klepto.reset();
      };
  if (auto* context =
          std::get_if<MessageSigningContext>(&command_context_)) {
    clear_anti_klepto(context->anti_klepto);
  } else if (auto* context =
                 std::get_if<PsbtSigningContext>(&command_context_)) {
    clear_anti_klepto(context->anti_klepto);
  }
  command_context_ = std::monostate{};
}

bool BitBoxSession::initialized() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return initialized_;
}

BitBoxDeviceInfo BitBoxSession::deviceInfo() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return device_info_;
}

BitBoxValue BitBoxSession::result() const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!result_.has_value()) {
    throw std::logic_error("BitBoxSession has no result");
  }
  return *result_;
}

}  // namespace nunchuk::bitbox
