/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */

#include "utils/jade/jade_session.hpp"

#include <algorithm>
#include <array>
#include <common/signmessage.h>
#include <ctime>
#include <key_io.h>
#include <limits>
#include <pubkey.h>
#include <random.h>
#include <stdexcept>
#include <support/cleanse.h>
#include <util/strencodings.h>
#include <utility>
#include <wally_anti_exfil.h>
#include <wally_crypto.h>

namespace nunchuk::jade {
namespace {

constexpr int RPC_INVALID_REQUEST = -32600;
constexpr int RPC_UNKNOWN_METHOD = -32601;
constexpr int RPC_BAD_PARAMETERS = -32602;
constexpr int RPC_INTERNAL_ERROR = -32603;
constexpr int RPC_USER_CANCELLED = -32000;
constexpr int RPC_PROTOCOL_ERROR = -32001;
constexpr int RPC_HW_LOCKED = -32002;
constexpr int RPC_NETWORK_MISMATCH = -32003;
constexpr size_t MAX_BLE_ATTRIBUTE_SIZE = 512;
constexpr size_t MAX_CBOR_BUFFER_SIZE = 16U * 1024U * 1024U;
constexpr std::array<unsigned char, 5> PSBT_MAGIC{{'p', 's', 'b', 't', 0xff}};

enum class CborScanResult { COMPLETE, INCOMPLETE, MALFORMED };

struct CborScanValue {
  CborScanResult result = CborScanResult::INCOMPLETE;
  size_t end = 0;
};

CborScanValue ScanCborItem(std::span<const unsigned char> data, size_t offset,
                           size_t depth);

CborScanValue ReadCborArgument(std::span<const unsigned char> data,
                               size_t offset, unsigned char additional,
                               uint64_t& value, bool& indefinite) {
  indefinite = false;
  if (additional < 24) {
    value = additional;
    return {CborScanResult::COMPLETE, offset};
  }
  if (additional == 31) {
    indefinite = true;
    value = 0;
    return {CborScanResult::COMPLETE, offset};
  }

  size_t bytes = 0;
  switch (additional) {
    case 24:
      bytes = 1;
      break;
    case 25:
      bytes = 2;
      break;
    case 26:
      bytes = 4;
      break;
    case 27:
      bytes = 8;
      break;
    default:
      return {CborScanResult::MALFORMED, offset};
  }
  if (offset > data.size() || bytes > data.size() - offset) {
    return {CborScanResult::INCOMPLETE, offset};
  }

  value = 0;
  for (size_t index = 0; index < bytes; ++index) {
    value = (value << 8) | data[offset + index];
  }
  return {CborScanResult::COMPLETE, offset + bytes};
}

CborScanValue ScanCborContainer(std::span<const unsigned char> data,
                                size_t offset, uint64_t items, bool indefinite,
                                size_t depth, bool is_map) {
  if (!indefinite) {
    if (is_map && items > std::numeric_limits<uint64_t>::max() / 2) {
      return {CborScanResult::MALFORMED, offset};
    }
    const uint64_t total = is_map ? items * 2 : items;
    for (uint64_t index = 0; index < total; ++index) {
      const auto child = ScanCborItem(data, offset, depth + 1);
      if (child.result != CborScanResult::COMPLETE) return child;
      offset = child.end;
    }
    return {CborScanResult::COMPLETE, offset};
  }

  while (true) {
    if (offset >= data.size()) return {CborScanResult::INCOMPLETE, offset};
    if (data[offset] == 0xff) {
      return {CborScanResult::COMPLETE, offset + 1};
    }
    const auto key_or_item = ScanCborItem(data, offset, depth + 1);
    if (key_or_item.result != CborScanResult::COMPLETE) return key_or_item;
    offset = key_or_item.end;
    if (is_map) {
      if (offset >= data.size()) return {CborScanResult::INCOMPLETE, offset};
      if (data[offset] == 0xff) {
        return {CborScanResult::MALFORMED, offset};
      }
      const auto value = ScanCborItem(data, offset, depth + 1);
      if (value.result != CborScanResult::COMPLETE) return value;
      offset = value.end;
    }
  }
}

CborScanValue ScanIndefiniteCborString(std::span<const unsigned char> data,
                                       size_t offset, unsigned char major,
                                       size_t depth) {
  while (true) {
    if (offset >= data.size()) return {CborScanResult::INCOMPLETE, offset};
    if (data[offset] == 0xff) {
      return {CborScanResult::COMPLETE, offset + 1};
    }
    if ((data[offset] >> 5) != major || (data[offset] & 0x1f) == 31) {
      return {CborScanResult::MALFORMED, offset};
    }
    const auto chunk = ScanCborItem(data, offset, depth + 1);
    if (chunk.result != CborScanResult::COMPLETE) return chunk;
    offset = chunk.end;
  }
}

CborScanValue ScanCborItem(std::span<const unsigned char> data, size_t offset,
                           size_t depth) {
  if (depth > 128) return {CborScanResult::MALFORMED, offset};
  if (offset >= data.size()) return {CborScanResult::INCOMPLETE, offset};

  const unsigned char initial = data[offset++];
  const unsigned char major = initial >> 5;
  const unsigned char additional = initial & 0x1f;
  if (major == 7 && additional == 31) {
    return {CborScanResult::MALFORMED, offset - 1};
  }

  uint64_t argument = 0;
  bool indefinite = false;
  const auto parsed =
      ReadCborArgument(data, offset, additional, argument, indefinite);
  if (parsed.result != CborScanResult::COMPLETE) return parsed;
  offset = parsed.end;

  switch (major) {
    case 0:
    case 1:
      return indefinite ? CborScanValue{CborScanResult::MALFORMED, offset}
                        : CborScanValue{CborScanResult::COMPLETE, offset};
    case 2:
    case 3:
      if (indefinite) {
        return ScanIndefiniteCborString(data, offset, major, depth);
      }
      if (argument > data.size() - offset) {
        return {CborScanResult::INCOMPLETE, offset};
      }
      return {CborScanResult::COMPLETE, offset + static_cast<size_t>(argument)};
    case 4:
      return ScanCborContainer(data, offset, argument, indefinite, depth,
                               false);
    case 5:
      return ScanCborContainer(data, offset, argument, indefinite, depth, true);
    case 6:
      if (indefinite) return {CborScanResult::MALFORMED, offset};
      return ScanCborItem(data, offset, depth + 1);
    case 7:
      return indefinite ? CborScanValue{CborScanResult::MALFORMED, offset}
                        : CborScanValue{CborScanResult::COMPLETE, offset};
    default:
      return {CborScanResult::MALFORMED, offset};
  }
}

std::vector<unsigned char> EncodeRequest(
    const std::string& id, const std::string& method,
    const std::optional<nlohmann::json>& params) {
  if (id.empty() || id.size() > 16) {
    throw std::invalid_argument("Jade request id must contain 1-16 characters");
  }
  if (method.empty() || method.size() > 32) {
    throw std::invalid_argument(
        "Jade request method must contain 1-32 characters");
  }
  nlohmann::json request{{"id", id}, {"method", method}};
  if (params.has_value()) request["params"] = *params;
  return nlohmann::json::to_cbor(request);
}

std::vector<unsigned char> JsonBinary(const nlohmann::json& value,
                                      const std::string& field_name) {
  if (!value.is_binary()) {
    throw std::runtime_error("Jade " + field_name + " is not binary data");
  }
  const auto& binary = value.get_binary();
  return {binary.begin(), binary.end()};
}

bool JsonBool(const nlohmann::json& value, const std::string& field) {
  if (!value.is_boolean()) {
    throw std::runtime_error("Jade " + field + " response is not boolean");
  }
  return value.get<bool>();
}

std::string JsonString(const nlohmann::json& value, const std::string& field) {
  if (!value.is_string()) {
    throw std::runtime_error("Jade " + field + " response is not a string");
  }
  return value.get<std::string>();
}

JadeDeviceState ParseDeviceState(const std::string& state) {
  if (state == "LOCKED") return JadeDeviceState::LOCKED;
  if (state == "UNSAVED") return JadeDeviceState::UNSAVED;
  if (state == "UNINIT") return JadeDeviceState::UNINITIALIZED;
  if (state == "TEMP") return JadeDeviceState::TEMPORARY;
  if (state == "READY") return JadeDeviceState::READY;
  return JadeDeviceState::UNKNOWN;
}

JadeDeviceNetworks ParseDeviceNetworks(const std::string& networks) {
  if (networks == "MAIN") return JadeDeviceNetworks::MAIN;
  if (networks == "TEST") return JadeDeviceNetworks::TEST;
  if (networks == "ALL") return JadeDeviceNetworks::ALL;
  return JadeDeviceNetworks::UNKNOWN;
}

std::string ErrorData(const nlohmann::json& error) {
  if (!error.contains("data")) return {};
  const auto& data = error.at("data");
  return data.is_string() ? data.get<std::string>() : data.dump();
}

JadeDeviceInfo ParseDeviceInfo(const nlohmann::json& result);

}  // namespace

void JadeSession::CborFramer::push(std::span<const unsigned char> data) {
  if (data.size() > MAX_CBOR_BUFFER_SIZE - buffer_.size()) {
    throw std::runtime_error("Jade CBOR receive buffer limit exceeded");
  }
  buffer_.insert(buffer_.end(), data.begin(), data.end());
}

std::optional<nlohmann::json> JadeSession::CborFramer::next() {
  if (buffer_.empty()) return std::nullopt;
  const auto scanned = ScanCborItem(buffer_, 0, 0);
  if (scanned.result == CborScanResult::INCOMPLETE) return std::nullopt;
  if (scanned.result == CborScanResult::MALFORMED || scanned.end == 0 ||
      scanned.end > buffer_.size()) {
    throw std::runtime_error("Malformed Jade CBOR stream");
  }

  std::vector<unsigned char> item(buffer_.begin(),
                                  buffer_.begin() + scanned.end);
  buffer_.erase(buffer_.begin(), buffer_.begin() + scanned.end);
  try {
    return nlohmann::json::from_cbor(item, true, true);
  } catch (const std::exception& e) {
    throw std::runtime_error(std::string("Invalid Jade CBOR object: ") +
                             e.what());
  }
}

void JadeSession::CborFramer::reset() { buffer_.clear(); }

JadeSession::JadeSession(Chain chain, std::string certificate_file,
                         size_t max_write_size)
    : chain_(chain),
      certificate_file_(std::move(certificate_file)),
      max_write_size_(max_write_size == 0
                          ? 0
                          : std::min(max_write_size, MAX_BLE_ATTRIBUTE_SIZE)) {}

JadeSession::~JadeSession() { clearMessageContext(); }

JadeStep JadeSession::initialize() {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    requireAvailable(false);
    result_.reset();
    initialized_ = false;
    root_fingerprint_.reset();
    command_ = Command::INITIALIZE;

    std::vector<unsigned char> entropy(32);
    GetStrongRandBytes(entropy);
    try {
      auto step =
          sendRpc("add_entropy",
                  nlohmann::json{{"entropy", nlohmann::json::binary(entropy)}},
                  Phase::INITIALIZE_ENTROPY);
      memory_cleanse(entropy.data(), entropy.size());
      return step;
    } catch (...) {
      memory_cleanse(entropy.data(), entropy.size());
      throw;
    }
  } catch (const std::exception& e) {
    return fail(JadeErrorCode::INVALID_STATE, e.what());
  }
}

JadeStep JadeSession::onData(std::span<const unsigned char> data) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    if (pending_http_.has_value()) {
      JadeStep step;
      step.type = JadeStepType::CUSTOM_SERVER_APPROVAL;
      step.interaction = UserInteraction::APPROVE_PINSERVER;
      step.custom_server = pending_http_->custom_server;
      return step;
    }
    if (command_ == Command::NONE || expected_id_.empty()) {
      return fail(JadeErrorCode::INVALID_STATE,
                  "Jade session is not awaiting device data");
    }
    framer_.push(data);
    while (const auto response = framer_.next()) {
      if (response->is_object() && response->contains("log") &&
          !response->contains("id")) {
        continue;
      }
      return handleResponse(*response);
    }
    JadeStep step;
    step.type = JadeStepType::READ_MORE;
    step.interaction = interaction_;
    return step;
  } catch (const std::exception& e) {
    return fail(JadeErrorCode::INVALID_RESPONSE, e.what());
  }
}

JadeStep JadeSession::confirmCustomPinServer(bool approved) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!pending_http_.has_value() || !expected_id_.empty()) {
    return fail(JadeErrorCode::INVALID_STATE,
                "Jade is not awaiting custom pinserver approval");
  }
  if (!approved) {
    return failHttp(JadeErrorCode::CUSTOM_SERVER_REJECTED,
                    "Custom Jade pinserver was rejected");
  }

  PendingHttp pending = std::move(*pending_http_);
  pending_http_.reset();
  try {
    const auto response =
        PerformHttpRequest(pending.request, certificate_file_, true);
    return sendRpc(pending.request.on_reply,
                   BuildHttpReplyParams(pending.request, response.body), phase_,
                   interaction_);
  } catch (const std::exception& e) {
    return failHttp(JadeErrorCode::HTTP, e.what());
  }
}

JadeStep JadeSession::getVersionInfo() {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    requireAvailable(false);
    result_.reset();
    command_ = Command::GET_VERSION_INFO;
    return sendRpc("get_version_info", std::nullopt, Phase::VERSION_INFO);
  } catch (const std::exception& e) {
    return fail(JadeErrorCode::INVALID_STATE, e.what());
  }
}

JadeStep JadeSession::getExtendedPublicKey(const std::string& derivation_path) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    requireAvailable();
    const auto path = ParseKeypath(derivation_path);
    result_.reset();
    command_ = Command::GET_XPUB;
    return sendRpc(
        "get_xpub",
        nlohmann::json{{"network", NetworkForChain(chain_)}, {"path", path}},
        Phase::XPUB);
  } catch (const std::invalid_argument& e) {
    return fail(JadeErrorCode::INVALID_ARGUMENT, e.what());
  } catch (const std::logic_error& e) {
    return fail(JadeErrorCode::INVALID_STATE, e.what());
  } catch (const std::exception& e) {
    return fail(JadeErrorCode::INVALID_ARGUMENT, e.what());
  }
}

JadeStep JadeSession::getMasterFingerprint() {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    requireAvailable();
    result_.reset();
    command_ = Command::GET_FINGERPRINT;
    if (root_fingerprint_.has_value()) {
      return finish(GetMasterFingerprintResult{*root_fingerprint_});
    }
    return sendRpc("get_xpub",
                   nlohmann::json{{"network", NetworkForChain(chain_)},
                                  {"path", nlohmann::json::array()}},
                   Phase::FETCH_FINGERPRINT);
  } catch (const std::invalid_argument& e) {
    return fail(JadeErrorCode::INVALID_ARGUMENT, e.what());
  } catch (const std::logic_error& e) {
    return fail(JadeErrorCode::INVALID_STATE, e.what());
  } catch (const std::exception& e) {
    return fail(JadeErrorCode::INVALID_ARGUMENT, e.what());
  }
}

JadeStep JadeSession::isWalletRegistered(const Wallet& wallet) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    requireAvailable();
    result_.reset();
    command_ = Command::CHECK_REGISTRATION;
    wallet_context_ = WalletContext{wallet};
    if (root_fingerprint_.has_value()) return continueAfterFingerprint();
    return sendRpc("get_xpub",
                   nlohmann::json{{"network", NetworkForChain(chain_)},
                                  {"path", nlohmann::json::array()}},
                   Phase::FETCH_FINGERPRINT);
  } catch (const std::invalid_argument& e) {
    return fail(JadeErrorCode::UNSUPPORTED_WALLET, e.what());
  } catch (const std::logic_error& e) {
    return fail(JadeErrorCode::INVALID_STATE, e.what());
  } catch (const std::exception& e) {
    return fail(JadeErrorCode::UNSUPPORTED_WALLET, e.what());
  }
}

JadeStep JadeSession::registerWallet(const Wallet& wallet) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    requireAvailable();
    result_.reset();
    command_ = Command::REGISTER_WALLET;
    wallet_context_ = WalletContext{wallet};
    if (root_fingerprint_.has_value()) return continueAfterFingerprint();
    return sendRpc("get_xpub",
                   nlohmann::json{{"network", NetworkForChain(chain_)},
                                  {"path", nlohmann::json::array()}},
                   Phase::FETCH_FINGERPRINT);
  } catch (const std::invalid_argument& e) {
    return fail(JadeErrorCode::UNSUPPORTED_WALLET, e.what());
  } catch (const std::logic_error& e) {
    return fail(JadeErrorCode::INVALID_STATE, e.what());
  } catch (const std::exception& e) {
    return fail(JadeErrorCode::UNSUPPORTED_WALLET, e.what());
  }
}

JadeStep JadeSession::getWalletAddress(const Wallet& wallet,
                                       uint32_t address_index,
                                       const WalletAddressOptions& options) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    requireAvailable();
    if (address_index > 0x7fffffffU) {
      throw std::invalid_argument("Jade address index must be unhardened");
    }
    result_.reset();
    command_ = Command::GET_ADDRESS;
    wallet_context_ = WalletContext{wallet};
    wallet_context_->address_index = address_index;
    wallet_context_->address_options = options;
    if (root_fingerprint_.has_value()) return continueAfterFingerprint();
    return sendRpc("get_xpub",
                   nlohmann::json{{"network", NetworkForChain(chain_)},
                                  {"path", nlohmann::json::array()}},
                   Phase::FETCH_FINGERPRINT);
  } catch (const std::invalid_argument& e) {
    return fail(JadeErrorCode::INVALID_ARGUMENT, e.what());
  } catch (const std::logic_error& e) {
    return fail(JadeErrorCode::INVALID_STATE, e.what());
  } catch (const std::exception& e) {
    return fail(JadeErrorCode::UNSUPPORTED_WALLET, e.what());
  }
}

JadeStep JadeSession::signMessage(const std::string& derivation_path,
                                  const std::string& message) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    requireAvailable();
    if (message.empty()) {
      throw std::invalid_argument("Jade message must not be empty");
    }
    if (message.size() > BITCOIN_MESSAGE_MAX_LEN) {
      throw std::invalid_argument("Jade message exceeds the Bitcoin limit");
    }
    const auto path = ParseKeypath(derivation_path);
    if (path.empty()) {
      throw std::invalid_argument(
          "Jade message signing requires a non-root derivation path");
    }
    result_.reset();
    command_ = Command::SIGN_MESSAGE;
    message_context_ = MessageContext{path, message};
    return sendRpc("get_xpub",
                   nlohmann::json{{"network", NetworkForChain(chain_)},
                                  {"path", message_context_->path}},
                   Phase::MESSAGE_XPUB);
  } catch (const std::invalid_argument& e) {
    return fail(JadeErrorCode::INVALID_ARGUMENT, e.what());
  } catch (const std::logic_error& e) {
    return fail(JadeErrorCode::INVALID_STATE, e.what());
  } catch (const std::exception& e) {
    return fail(JadeErrorCode::INVALID_ARGUMENT, e.what());
  }
}

JadeStep JadeSession::signPsbt(const Wallet& wallet, const std::string& psbt) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    requireAvailable();
    const auto decoded = DecodeBase64(psbt);
    if (!decoded.has_value() || decoded->size() < PSBT_MAGIC.size() ||
        !std::equal(PSBT_MAGIC.begin(), PSBT_MAGIC.end(), decoded->begin())) {
      throw std::invalid_argument("Invalid base64 PSBT");
    }
    result_.reset();
    command_ = Command::SIGN_PSBT;
    wallet_context_ = WalletContext{wallet};
    wallet_context_->psbt = *decoded;
    if (root_fingerprint_.has_value()) return continueAfterFingerprint();
    return sendRpc("get_xpub",
                   nlohmann::json{{"network", NetworkForChain(chain_)},
                                  {"path", nlohmann::json::array()}},
                   Phase::FETCH_FINGERPRINT);
  } catch (const std::invalid_argument& e) {
    return fail(JadeErrorCode::INVALID_PSBT, e.what());
  } catch (const std::logic_error& e) {
    return fail(JadeErrorCode::INVALID_STATE, e.what());
  } catch (const std::exception& e) {
    return fail(JadeErrorCode::INVALID_PSBT, e.what());
  }
}

bool JadeSession::initialized() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return initialized_;
}

JadeDeviceInfo JadeSession::deviceInfo() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return device_info_;
}

JadeValue JadeSession::result() const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!result_.has_value()) {
    throw std::logic_error("Jade session has no completed result");
  }
  return *result_;
}

JadeStep JadeSession::sendRpc(const std::string& method,
                              const std::optional<nlohmann::json>& params,
                              Phase phase, UserInteraction interaction) {
  if (!expected_id_.empty()) {
    throw std::logic_error("Jade already has an outstanding request");
  }
  expected_id_ = std::to_string(next_request_id_++);
  const auto request = EncodeRequest(expected_id_, method, params);
  phase_ = phase;
  interaction_ = interaction;

  JadeStep step;
  step.type = JadeStepType::WRITE;
  step.interaction = interaction;
  if (max_write_size_ == 0) {
    step.writes.push_back(request);
  } else {
    for (size_t offset = 0; offset < request.size();
         offset += max_write_size_) {
      const size_t size =
          std::min(max_write_size_, request.size() - offset);
      step.writes.emplace_back(request.begin() + offset,
                               request.begin() + offset + size);
    }
  }
  return step;
}

JadeStep JadeSession::handleResponse(const nlohmann::json& response) {
  if (!response.is_object() || !response.contains("id") ||
      !response.at("id").is_string()) {
    return fail(JadeErrorCode::INVALID_RESPONSE,
                "Jade response has no string request id");
  }
  const std::string id = response.at("id").get<std::string>();
  if (id != expected_id_) {
    return fail(JadeErrorCode::PROTOCOL,
                "Jade response id does not match the active request");
  }
  expected_id_.clear();

  if (response.contains("error") && !response.at("error").is_null()) {
    const auto& error = response.at("error");
    const int code = error.value("code", 0);
    const std::string message =
        error.value("message", std::string("Jade device error"));
    const std::string data = ErrorData(error);

    if (phase_ == Phase::REGISTRATION_QUERY && code == RPC_BAD_PARAMETERS) {
      if (command_ == Command::CHECK_REGISTRATION) {
        const std::string name = wallet_context_->config->name;
        return finish(RegistrationResult{false, name});
      }
      return fail(JadeErrorCode::WALLET_NOT_REGISTERED,
                  "Wallet is not registered on Jade", code, data);
    }
    if (code == RPC_USER_CANCELLED) {
      return fail(JadeErrorCode::USER_CANCELLED, message, code, data);
    }
    if (code == RPC_HW_LOCKED) {
      initialized_ = false;
      return fail(JadeErrorCode::DEVICE_LOCKED, message, code, data);
    }
    if (code == RPC_NETWORK_MISMATCH) {
      return fail(JadeErrorCode::NETWORK_MISMATCH, message, code, data);
    }
    if (code == RPC_PROTOCOL_ERROR || code == RPC_INVALID_REQUEST ||
        code == RPC_UNKNOWN_METHOD || code == RPC_BAD_PARAMETERS ||
        code == RPC_INTERNAL_ERROR) {
      return fail(JadeErrorCode::PROTOCOL, message, code, data);
    }
    return fail(JadeErrorCode::DEVICE, message, code, data);
  }

  if (!response.contains("result")) {
    return fail(JadeErrorCode::INVALID_RESPONSE,
                "Jade response contains neither result nor error");
  }
  const auto& result = response.at("result");
  if (result.is_object() && result.contains("http_request")) {
    return handleHttpRequest(result);
  }
  return handleResult(response, result);
}

JadeStep JadeSession::handleResult(const nlohmann::json& response,
                                   const nlohmann::json& result) {
  switch (phase_) {
    case Phase::INITIALIZE_ENTROPY:
      if (!JsonBool(result, "add_entropy")) {
        return fail(JadeErrorCode::DEVICE, "Jade rejected host entropy");
      }
      return sendRpc("get_version_info", std::nullopt,
                     Phase::INITIALIZE_VERSION);

    case Phase::INITIALIZE_VERSION: {
      device_info_ = ParseDeviceInfo(result);
      if (!FirmwareAtLeast(device_info_.firmware_version, 1, 0, 40)) {
        device_info_.firmware_upgrade_required = true;
        return fail(JadeErrorCode::UNSUPPORTED_FIRMWARE,
                    "Jade firmware 1.0.40 or newer is required; device has " +
                        device_info_.firmware_version);
      }
      if (device_info_.state == JadeDeviceState::TEMPORARY ||
          (device_info_.state == JadeDeviceState::READY &&
           device_info_.has_pin_reported && !device_info_.has_pin)) {
        return fail(JadeErrorCode::INVALID_STATE,
                    "Temporary Jade wallets are not supported");
      }
      if (device_info_.state == JadeDeviceState::READY) {
        initialized_ = true;
        return finish(InitializeResult{device_info_});
      }
      const UserInteraction interaction =
          device_info_.state == JadeDeviceState::UNINITIALIZED
              ? UserInteraction::SETUP_DEVICE
              : UserInteraction::ENTER_PIN;
      return sendRpc(
          "auth_user",
          nlohmann::json{{"network", NetworkForChain(chain_)},
                         {"epoch", static_cast<int64_t>(std::time(nullptr))}},
          Phase::INITIALIZE_AUTH, interaction);
    }

    case Phase::INITIALIZE_AUTH:
      if (JsonBool(result, "auth_user")) {
        return sendRpc("get_version_info", std::nullopt,
                       Phase::INITIALIZE_FINAL_VERSION);
      }
      return sendRpc(
          "auth_user",
          nlohmann::json{{"network", NetworkForChain(chain_)},
                         {"epoch", static_cast<int64_t>(std::time(nullptr))}},
          Phase::INITIALIZE_AUTH, interaction_);

    case Phase::INITIALIZE_FINAL_VERSION:
      device_info_ = ParseDeviceInfo(result);
      if (device_info_.state != JadeDeviceState::READY) {
        return fail(JadeErrorCode::DEVICE_LOCKED,
                    "Jade did not remain unlocked after authentication");
      }
      if (device_info_.has_pin_reported && !device_info_.has_pin) {
        return fail(JadeErrorCode::INVALID_STATE,
                    "Temporary Jade wallets are not supported");
      }
      initialized_ = true;
      return finish(InitializeResult{device_info_});

    case Phase::VERSION_INFO:
      device_info_ = ParseDeviceInfo(result);
      device_info_.firmware_upgrade_required =
          !FirmwareAtLeast(device_info_.firmware_version, 1, 0, 40);
      if (device_info_.state != JadeDeviceState::READY) initialized_ = false;
      return finish(GetVersionInfoResult{device_info_});

    case Phase::FETCH_FINGERPRINT: {
      const auto xpub = DecodeExtPubKey(JsonString(result, "get_xpub"));
      if (!xpub.pubkey.IsFullyValid()) {
        throw std::invalid_argument(
            "Jade returned an invalid extended public key");
      }
      const auto id = xpub.pubkey.GetID();
      root_fingerprint_ =
          HexStr(std::span<const unsigned char>(id.begin(), size_t{4}));
      if (command_ == Command::GET_FINGERPRINT) {
        return finish(GetMasterFingerprintResult{*root_fingerprint_});
      }
      return continueAfterFingerprint();
    }

    case Phase::XPUB:
      return finish(GetExtendedPublicKeyResult{JsonString(result, "get_xpub")});

    case Phase::REGISTRATION_QUERY: {
      const bool registered =
          RegistrationMatches(*wallet_context_->config, result);
      if (command_ == Command::CHECK_REGISTRATION) {
        return finish(
            RegistrationResult{registered, wallet_context_->config->name});
      }
      if (!registered) {
        return fail(JadeErrorCode::WALLET_NOT_REGISTERED,
                    "Wallet registration on Jade does not match libnunchuk");
      }
      if (command_ == Command::GET_ADDRESS) return sendAddress();
      return fail(JadeErrorCode::INVALID_STATE,
                  "Unexpected Jade registration continuation");
    }

    case Phase::REGISTRATION_REGISTER:
      if (!JsonBool(result, "wallet registration")) {
        return fail(JadeErrorCode::DEVICE, "Jade did not register the wallet");
      }
      return finish(RegistrationResult{true, wallet_context_->config->name});

    case Phase::ADDRESS:
      return finish(
          WalletAddressResult{JsonString(result, "get_receive_address")});

    case Phase::MESSAGE_XPUB: {
      auto& context = *message_context_;
      const auto xpub = DecodeExtPubKey(JsonString(result, "get_xpub"));
      if (!xpub.pubkey.IsFullyValid()) {
        throw std::invalid_argument(
            "Jade returned an invalid extended public key");
      }
      context.public_key.assign(xpub.pubkey.begin(), xpub.pubkey.end());
      GetStrongRandBytes(context.host_entropy);
      std::array<unsigned char, WALLY_HOST_COMMITMENT_LEN> commitment{};
      if (wally_ae_host_commit_from_bytes(context.host_entropy.data(),
                                          context.host_entropy.size(),
                                          EC_FLAG_ECDSA, commitment.data(),
                                          commitment.size()) != WALLY_OK) {
        return fail(JadeErrorCode::ANTI_EXFIL,
                    "Could not create Jade anti-exfil commitment");
      }
      return sendRpc(
          "sign_message",
          nlohmann::json{{"path", context.path},
                         {"message", context.message},
                         {"ae_host_commitment",
                          nlohmann::json::binary(std::vector<unsigned char>(
                              commitment.begin(), commitment.end()))}},
          Phase::MESSAGE_COMMITMENT, UserInteraction::SIGN_MESSAGE);
    }

    case Phase::MESSAGE_COMMITMENT: {
      auto& context = *message_context_;
      context.signer_commitment =
          JsonBinary(result, "anti-exfil signer commitment");
      if (context.signer_commitment.size() != WALLY_S2C_OPENING_LEN) {
        return fail(JadeErrorCode::ANTI_EXFIL,
                    "Jade returned an invalid anti-exfil opening");
      }
      return sendRpc(
          "get_signature",
          nlohmann::json{
              {"ae_host_entropy",
               nlohmann::json::binary(std::vector<unsigned char>(
                   context.host_entropy.begin(), context.host_entropy.end()))}},
          Phase::MESSAGE_SIGNATURE, UserInteraction::SIGN_MESSAGE);
    }

    case Phase::MESSAGE_SIGNATURE: {
      auto& context = *message_context_;
      const std::string signature = JsonString(result, "message signature");
      const auto decoded = DecodeBase64(signature);
      if (!decoded.has_value() ||
          decoded->size() != CPubKey::COMPACT_SIGNATURE_SIZE - 1) {
        return fail(JadeErrorCode::ANTI_EXFIL,
                    "Jade returned an invalid message signature");
      }
      const uint256 message_hash = MessageHash(context.message);
      if (wally_ae_verify(
              context.public_key.data(), context.public_key.size(),
              message_hash.begin(), message_hash.size(),
              context.host_entropy.data(), context.host_entropy.size(),
              context.signer_commitment.data(),
              context.signer_commitment.size(), EC_FLAG_ECDSA,
              decoded->data(), decoded->size()) != WALLY_OK) {
        return fail(JadeErrorCode::ANTI_EXFIL,
                    "Jade message signature failed anti-exfil verification");
      }
      std::vector<unsigned char> recoverable_signature(
          CPubKey::COMPACT_SIGNATURE_SIZE);
      std::copy(decoded->begin(), decoded->end(),
                recoverable_signature.begin() + 1);
      const CPubKey signing_key(context.public_key.begin(),
                                context.public_key.end());
      bool recovered = false;
      for (unsigned char recovery_id = 0; recovery_id < 4; ++recovery_id) {
        recoverable_signature[0] = 31 + recovery_id;
        CPubKey recovered_key;
        if (recovered_key.RecoverCompact(message_hash,
                                         recoverable_signature) &&
            recovered_key == signing_key) {
          recovered = true;
          break;
        }
      }
      if (!recovered) {
        return fail(JadeErrorCode::ANTI_EXFIL,
                    "Could not recover the Jade message signing key");
      }
      memory_cleanse(context.host_entropy.data(), context.host_entropy.size());
      return finish(SignMessageResult{EncodeBase64(recoverable_signature)});
    }

    case Phase::PSBT_CHUNK: {
      const auto chunk = JsonBinary(result, "signed PSBT chunk");
      const bool has_seqnum = response.contains("seqnum");
      const bool has_seqlen = response.contains("seqlen");
      if (has_seqnum != has_seqlen) {
        return fail(JadeErrorCode::INVALID_RESPONSE,
                    "Jade PSBT response has incomplete sequence metadata");
      }

      if (!has_seqnum) {
        if (psbt_expected_seqnum_ != 0) {
          return fail(JadeErrorCode::INVALID_RESPONSE,
                      "Jade omitted PSBT sequence metadata");
        }
        psbt_result_.insert(psbt_result_.end(), chunk.begin(), chunk.end());
        return finishPsbt();
      }

      const uint32_t seqnum = response.at("seqnum").get<uint32_t>();
      const uint32_t seqlen = response.at("seqlen").get<uint32_t>();
      const uint32_t expected =
          psbt_expected_seqnum_ == 0 ? 1 : psbt_expected_seqnum_;
      if (seqnum != expected || seqlen == 0 || seqnum > seqlen ||
          (psbt_seqlen_ != 0 && seqlen != psbt_seqlen_)) {
        return fail(JadeErrorCode::INVALID_RESPONSE,
                    "Jade returned invalid PSBT sequence metadata");
      }
      psbt_seqlen_ = seqlen;
      psbt_result_.insert(psbt_result_.end(), chunk.begin(), chunk.end());
      if (seqnum == seqlen) {
        return finishPsbt();
      }
      psbt_expected_seqnum_ = seqnum + 1;
      return sendRpc("get_extended_data",
                     nlohmann::json{{"origid", psbt_original_id_},
                                    {"orig", "sign_psbt"},
                                    {"seqnum", psbt_expected_seqnum_},
                                    {"seqlen", psbt_seqlen_}},
                     Phase::PSBT_CHUNK, UserInteraction::SIGN_TRANSACTION);
    }

    case Phase::NONE:
      break;
  }
  return fail(JadeErrorCode::INVALID_STATE,
              "Jade response arrived in an invalid phase");
}

JadeStep JadeSession::handleHttpRequest(const nlohmann::json& result) {
  JadeHttpRequest request;
  try {
    request = ParseHttpRequest(result);
  } catch (const std::exception& e) {
    return failHttp(JadeErrorCode::INVALID_RESPONSE, e.what());
  }
  try {
    const auto response = PerformHttpRequest(request, certificate_file_, false);
    if (response.custom_server.has_value()) {
      pending_http_ = PendingHttp{std::move(request), *response.custom_server};
      JadeStep step;
      step.type = JadeStepType::CUSTOM_SERVER_APPROVAL;
      step.interaction = UserInteraction::APPROVE_PINSERVER;
      step.custom_server = response.custom_server;
      return step;
    }
    return sendRpc(request.on_reply,
                   BuildHttpReplyParams(request, response.body), phase_,
                   interaction_);
  } catch (const std::exception& e) {
    return failHttp(JadeErrorCode::HTTP, e.what());
  }
}

JadeStep JadeSession::continueAfterFingerprint() {
  if (!wallet_context_.has_value() || !root_fingerprint_.has_value()) {
    return fail(JadeErrorCode::INVALID_STATE,
                "Jade wallet context is incomplete");
  }
  auto& context = *wallet_context_;
  try {
    context.config =
        BuildWalletConfig(context.wallet, *root_fingerprint_, chain_);
  } catch (const std::exception& e) {
    return fail(JadeErrorCode::UNSUPPORTED_WALLET, e.what());
  }
  if (command_ == Command::SIGN_PSBT) return sendPsbt();
  if (context.config->kind == JadeWalletKind::SINGLE_SIG) {
    if (command_ == Command::CHECK_REGISTRATION ||
        command_ == Command::REGISTER_WALLET) {
      return finish(RegistrationResult{true, context.config->name});
    }
    if (command_ == Command::GET_ADDRESS) return sendAddress();
  }

  if (command_ == Command::CHECK_REGISTRATION ||
      command_ == Command::GET_ADDRESS) {
    return sendRegistrationQuery();
  }
  if (command_ == Command::REGISTER_WALLET) {
    const auto [method, params] = RegistrationRequest(*context.config);
    return sendRpc(method, std::optional<nlohmann::json>{params},
                   Phase::REGISTRATION_REGISTER,
                   UserInteraction::REGISTER_WALLET);
  }
  return fail(JadeErrorCode::INVALID_STATE,
              "Invalid Jade wallet command continuation");
}

JadeStep JadeSession::sendRegistrationQuery() {
  const auto [method, params] = RegistrationQuery(*wallet_context_->config);
  return sendRpc(method, std::optional<nlohmann::json>{params},
                 Phase::REGISTRATION_QUERY);
}

JadeStep JadeSession::sendAddress() {
  const auto& context = *wallet_context_;
  try {
    return sendRpc(
        "get_receive_address",
        AddressRequest(context.wallet, *context.config, chain_,
                       context.address_index, context.address_options.change),
        Phase::ADDRESS, UserInteraction::VERIFY_ADDRESS);
  } catch (const std::exception& e) {
    return fail(JadeErrorCode::UNSUPPORTED_WALLET, e.what());
  }
}

JadeStep JadeSession::sendPsbt() {
  const auto& context = *wallet_context_;
  auto step =
      sendRpc("sign_psbt",
              nlohmann::json{{"network", NetworkForChain(chain_)},
                             {"psbt", nlohmann::json::binary(context.psbt)}},
              Phase::PSBT_CHUNK, UserInteraction::SIGN_TRANSACTION);
  psbt_original_id_ = expected_id_;
  psbt_expected_seqnum_ = 0;
  psbt_seqlen_ = 0;
  psbt_result_.clear();
  return step;
}

JadeStep JadeSession::finishPsbt() {
  if (psbt_result_.size() < PSBT_MAGIC.size() ||
      !std::equal(PSBT_MAGIC.begin(), PSBT_MAGIC.end(), psbt_result_.begin())) {
    return fail(JadeErrorCode::INVALID_RESPONSE,
                "Jade returned invalid signed PSBT data");
  }
  return finish(SignPsbtResult{EncodeBase64(psbt_result_)});
}

JadeStep JadeSession::finish(JadeValue value) {
  result_ = std::move(value);
  resetCommand();
  JadeStep step;
  step.type = JadeStepType::COMPLETE;
  return step;
}

JadeStep JadeSession::fail(JadeErrorCode code, const std::string& message,
                           int device_code, const std::string& device_data) {
  result_.reset();
  resetCommand();
  JadeStep step;
  step.type = JadeStepType::FAILED;
  step.error = JadeError{code, message, device_code, device_data};
  return step;
}

JadeStep JadeSession::failHttp(JadeErrorCode code, const std::string& message) {
  transport_reset_required_ = true;
  initialized_ = false;
  return fail(code, message);
}

void JadeSession::requireAvailable(bool require_initialized) const {
  if (transport_reset_required_) {
    throw std::logic_error(
        "Jade pinserver flow was abandoned; reconnect with a fresh session");
  }
  if (command_ != Command::NONE) {
    throw std::logic_error("Jade session already has an active command");
  }
  if (require_initialized && !initialized_) {
    throw std::logic_error("Jade session must be initialized first");
  }
  if (require_initialized && device_info_.firmware_upgrade_required) {
    throw std::logic_error("Jade firmware upgrade is required");
  }
}

void JadeSession::resetCommand() {
  clearMessageContext();
  command_ = Command::NONE;
  phase_ = Phase::NONE;
  interaction_ = UserInteraction::NONE;
  expected_id_.clear();
  wallet_context_.reset();
  pending_http_.reset();
  psbt_original_id_.clear();
  psbt_expected_seqnum_ = 0;
  psbt_seqlen_ = 0;
  psbt_result_.clear();
  framer_.reset();
}

void JadeSession::clearMessageContext() {
  if (message_context_.has_value()) {
    memory_cleanse(message_context_->host_entropy.data(),
                   message_context_->host_entropy.size());
  }
  message_context_.reset();
}

namespace {

JadeDeviceInfo ParseDeviceInfo(const nlohmann::json& result) {
  if (!result.is_object()) {
    throw std::runtime_error("Jade version response is not an object");
  }
  JadeDeviceInfo info;
  info.firmware_version = result.value("JADE_VERSION", std::string{});
  if (info.firmware_version.empty()) {
    throw std::runtime_error("Jade version response has no firmware version");
  }
  info.ota_max_chunk = result.value("JADE_OTA_MAX_CHUNK", uint32_t{0});
  info.config = result.value("JADE_CONFIG", std::string{});
  info.board_type = result.value("BOARD_TYPE", std::string{});
  info.features = result.value("JADE_FEATURES", std::string{});
  info.idf_version = result.value("IDF_VERSION", std::string{});
  info.chip_features = result.value("CHIP_FEATURES", std::string{});
  if (result.contains("EFUSEMAC") && result.at("EFUSEMAC").is_string()) {
    info.efuse_mac = result.at("EFUSEMAC").get<std::string>();
  }
  if (result.contains("BATTERY_STATUS") &&
      result.at("BATTERY_STATUS").is_number_unsigned()) {
    info.battery_status = result.at("BATTERY_STATUS").get<uint32_t>();
  }
  info.state = ParseDeviceState(result.value("JADE_STATE", std::string{}));
  info.networks =
      ParseDeviceNetworks(result.value("JADE_NETWORKS", std::string{}));
  if (result.contains("JADE_HAS_PIN") &&
      result.at("JADE_HAS_PIN").is_boolean()) {
    info.has_pin = result.at("JADE_HAS_PIN").get<bool>();
    info.has_pin_reported = true;
  }
  return info;
}

}  // namespace

}  // namespace nunchuk::jade
