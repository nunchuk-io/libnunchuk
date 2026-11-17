/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */
#include "utils/onekey/onekey_session.hpp"

#include <algorithm>
#include <stdexcept>
#include <common/signmessage.h>
#include <key_io.h>
#include <support/cleanse.h>
#include <util/strencodings.h>
#include "utils/onekey/bitcoin.hpp"
#include "utils/onekey/protobuf.hpp"

namespace nunchuk::onekey {
using json = nlohmann::json;

OneKeySession::OneKeySession(Chain chain, OneKeyTransport transport)
    : chain_(chain), framer_(transport) {}

void OneKeySession::requireAvailable(bool require_initialized) const {
  if (command_ != Command::NONE)
    throw std::logic_error("OneKey command is already in progress");
  if (reset_required_)
    throw std::logic_error("Reconnect OneKey and create a new session");
  if (require_initialized && (!initialized_ || !device_info_.initialized)) {
    throw std::logic_error("OneKey device is not initialized");
  }
  if (chain_ != Utils::GetChain())
    throw std::logic_error("OneKey session network changed");
}

void OneKeySession::resetCommand() {
  command_ = Command::NONE;
  phase_ = Phase::NONE;
  prompt_ = Prompt::NONE;
  interaction_ = UserInteraction::NONE;
  on_device_entry_ = false;
  attach_pin_available_ = false;
  passphrase_required_on_device_ = false;
  wallet_.reset();
  prepared_.reset();
  signatures_.clear();
  path_.clear();
  fingerprint_.clear();
  message_.clear();
  message_public_key_.clear();
  expected_address_.clear();
  psbt_.clear();
  framer_.reset();
}

void OneKeySession::begin(Command command) {
  resetCommand();
  result_.reset();
  command_ = command;
}

OneKeyStep OneKeySession::send(uint16_t type, const json& data) {
  auto bytes = proto::Encode(type, data);
  OneKeyStep step;
  step.type = OneKeyStepType::WRITE;
  step.interaction = interaction_;
  step.writes = WireFramer::encode(type, bytes);
  if (!bytes.empty()) memory_cleanse(bytes.data(), bytes.size());
  return step;
}

OneKeyStep OneKeySession::requestPublicKey(const std::vector<uint32_t>& path,
                                           Phase phase, bool display) {
  path_ = path;
  phase_ = phase;
  return send(proto::GET_PUBLIC_KEY, {{"address_n", path},
                                      {"coin_name", CoinName(chain_)},
                                      {"show_display", display}});
}

OneKeyStep OneKeySession::initialize() {
  std::lock_guard<std::mutex> lock(mutex_);
  requireAvailable(false);
  begin(Command::INITIALIZE);
  initialized_ = false;
  phase_ = Phase::FEATURES;
  return send(proto::INITIALIZE);
}

OneKeyStep OneKeySession::getExtendedPublicKey(
    const std::string& path, const GetExtendedPublicKeyOptions& options) {
  std::lock_guard<std::mutex> lock(mutex_);
  requireAvailable();
  const auto keypath = ParseKeypath(path);
  begin(Command::XPUB);
  interaction_ = options.check_on_device ? UserInteraction::EXPORT_PUBLIC_KEY
                                         : UserInteraction::NONE;
  return requestPublicKey(keypath, Phase::XPUB, options.check_on_device);
}

OneKeyStep OneKeySession::getMasterFingerprint() {
  std::lock_guard<std::mutex> lock(mutex_);
  requireAvailable();
  begin(Command::FINGERPRINT);
  return requestPublicKey({0x80000000}, Phase::FINGERPRINT);
}

OneKeyStep OneKeySession::getWalletAddress(
    const Wallet& wallet, uint32_t index, const WalletAddressOptions& options) {
  std::lock_guard<std::mutex> lock(mutex_);
  requireAvailable();
  ValidateWallet(wallet);
  const auto address = WalletAddress(wallet, options.change, index);
  begin(Command::ADDRESS);
  wallet_ = wallet;
  address_index_ = index;
  address_options_ = options;
  expected_address_ = address;
  return requestPublicKey({0x80000000}, Phase::FINGERPRINT);
}

OneKeyStep OneKeySession::signMessage(const std::string& path,
                                      const std::string& message) {
  std::lock_guard<std::mutex> lock(mutex_);
  requireAvailable();
  const auto keypath = ParseKeypath(path);
  if (message.size() > 1024 * 1024)
    throw std::invalid_argument("OneKey message is too large");
  begin(Command::MESSAGE);
  message_ = message;
  return requestPublicKey(keypath, Phase::MESSAGE_KEY);
}

OneKeyStep OneKeySession::signPsbt(const Wallet& wallet,
                                   const std::string& psbt) {
  std::lock_guard<std::mutex> lock(mutex_);
  requireAvailable();
  ValidateWallet(wallet);
  if (psbt.size() > WireFramer::MAX_MESSAGE_SIZE)
    throw std::invalid_argument("OneKey PSBT is too large");
  begin(Command::PSBT);
  wallet_ = wallet;
  psbt_ = psbt;
  return requestPublicKey({0x80000000}, Phase::FINGERPRINT);
}

OneKeyStep OneKeySession::providePin(const std::string& pin) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (prompt_ != Prompt::PIN)
    throw std::logic_error("OneKey is not waiting for a PIN");
  if (pin.empty() || pin.size() > 50 ||
      pin.find_first_not_of("123456789") != std::string::npos) {
    throw std::invalid_argument("Invalid OneKey matrix PIN");
  }
  auto step = send(proto::PIN_MATRIX_ACK, {{"pin", pin}});
  prompt_ = Prompt::NONE;
  return step;
}

OneKeyStep OneKeySession::enterPinOnDevice() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (prompt_ != Prompt::PIN)
    throw std::logic_error("OneKey is not waiting for a PIN");
  if (device_info_.model == OneKeyModel::PRO)
    throw std::logic_error("Unexpected Pro matrix PIN request");
  prompt_ = Prompt::NONE;
  on_device_entry_ = true;
  return send(proto::PIN_ON_DEVICE);
}

OneKeyStep OneKeySession::providePassphrase(const std::string& passphrase) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (prompt_ != Prompt::PASSPHRASE)
    throw std::logic_error("OneKey is not waiting for a passphrase");
  if (passphrase_required_on_device_)
    throw std::logic_error("Enter the passphrase on OneKey");
  if (passphrase.size() > 50 || passphrase.find('\0') != std::string::npos) {
    throw std::invalid_argument("OneKey passphrase must be at most 50 bytes");
  }
  auto step = send(proto::PASSPHRASE_ACK, {{"passphrase", passphrase}});
  prompt_ = Prompt::NONE;
  return step;
}

OneKeyStep OneKeySession::enterPassphraseOnDevice(bool attach_to_pin) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (prompt_ != Prompt::PASSPHRASE)
    throw std::logic_error("OneKey is not waiting for a passphrase");
  if (attach_to_pin ? !attach_pin_available_
                    : !device_info_.passphrase_on_device &&
                          !passphrase_required_on_device_) {
    throw std::logic_error(
        "OneKey does not support this passphrase entry mode");
  }
  prompt_ = Prompt::NONE;
  on_device_entry_ = true;
  return send(proto::PASSPHRASE_ACK, attach_to_pin
                                         ? json{{"on_device_attach_pin", true}}
                                         : json{{"on_device", true}});
}

OneKeyStep OneKeySession::cancel() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (command_ == Command::NONE)
    throw std::logic_error("No OneKey command to cancel");
  phase_ = Phase::CANCEL;
  prompt_ = Prompt::NONE;
  result_.reset();
  framer_.reset();
  reset_required_ = true;
  return send(on_device_entry_ ? proto::INITIALIZE : proto::CANCEL);
}

OneKeyStep OneKeySession::onDisconnected() {
  std::lock_guard<std::mutex> lock(mutex_);
  return fail(OneKeyErrorCode::SESSION_LOST,
              "OneKey disconnected; reconnect and create a new session");
}

OneKeyStep OneKeySession::onData(std::span<const unsigned char> data) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (command_ == Command::NONE)
    return fail(OneKeyErrorCode::INVALID_STATE,
                "Unexpected OneKey data without a pending command");
  if (chain_ != Utils::GetChain()) {
    return fail(OneKeyErrorCode::SESSION_LOST,
                "OneKey session network changed");
  }
  try {
    auto message = framer_.receive(data);
    if (!message) {
      OneKeyStep step;
      step.interaction = interaction_;
      return step;
    }
    if (phase_ == Phase::CANCEL)
      return fail(OneKeyErrorCode::USER_CANCELLED,
                  "OneKey operation cancelled");
    return handleResponse(message->type,
                          proto::Decode(message->type, message->data));
  } catch (const std::exception& e) {
    return fail(OneKeyErrorCode::INVALID_RESPONSE, e.what());
  }
}

OneKeyStep OneKeySession::handleResponse(uint16_t type, const json& response) {
  if (type == proto::FAILURE) {
    int code = response.at("code");
    return fail(code == 4 || code == 6 ? OneKeyErrorCode::USER_CANCELLED
                                       : OneKeyErrorCode::DEVICE,
                response.at("message"), code);
  }
  if (prompt_ != Prompt::NONE)
    return fail(OneKeyErrorCode::INVALID_RESPONSE,
                "OneKey replied before the pending prompt was answered");
  if (type == proto::BUTTON_REQUEST) {
    auto step = send(proto::BUTTON_ACK);
    step.request_code = response.at("code");
    if (step.request_code == 19)
      step.interaction = UserInteraction::ENTER_PASSPHRASE;
    if (step.request_code == 20)
      step.interaction = UserInteraction::UNLOCK_DEVICE;
    return step;
  }
  if (type == proto::PIN_MATRIX_REQUEST || type == proto::PASSPHRASE_REQUEST) {
    if (type == proto::PASSPHRASE_REQUEST &&
        (phase_ == Phase::ACCOUNT_KEY || phase_ == Phase::ADDRESS ||
         phase_ == Phase::TX || phase_ == Phase::RAW_PSBT ||
         phase_ == Phase::MESSAGE)) {
      return fail(OneKeyErrorCode::SESSION_LOST,
                  "OneKey wallet session changed during the operation");
    }
    OneKeyStep step;
    step.type = OneKeyStepType::AWAITING_USER;
    if (type == proto::PIN_MATRIX_REQUEST) {
      prompt_ = Prompt::PIN;
      step.interaction = UserInteraction::ENTER_PIN;
      step.request_code = response.at("type");
      step.on_device_available = device_info_.model != OneKeyModel::PRO;
    } else {
      prompt_ = Prompt::PASSPHRASE;
      step.interaction = UserInteraction::ENTER_PASSPHRASE;
      attach_pin_available_ = response.at("exists_attach_pin_user");
      passphrase_required_on_device_ = response.at("on_device");
      step.on_device_required = passphrase_required_on_device_;
      step.on_device_available =
          device_info_.passphrase_on_device || passphrase_required_on_device_;
      step.attach_pin_available = attach_pin_available_;
    }
    return step;
  }
  if (phase_ == Phase::FEATURES && type == proto::FEATURES) {
    device_info_ = ParseDeviceInfo(response);
    if (device_info_.model == OneKeyModel::UNKNOWN || device_info_.bootloader) {
      return fail(OneKeyErrorCode::UNSUPPORTED_DEVICE,
                  "OneKey Pro, Classic or Classic 1S firmware is required");
    }
    initialized_ = true;
    return finish(InitializeResult{device_info_});
  }
  if (type == proto::PUBLIC_KEY &&
      (phase_ == Phase::XPUB || phase_ == Phase::FINGERPRINT ||
       phase_ == Phase::ACCOUNT_KEY || phase_ == Phase::MESSAGE_KEY)) {
    const auto xpub = ValidatePublicKey(response, path_);
    if (phase_ == Phase::XPUB) return finish(GetExtendedPublicKeyResult{xpub});
    if (phase_ == Phase::FINGERPRINT) {
      fingerprint_ = MasterFingerprint(response);
      if (command_ == Command::FINGERPRINT)
        return finish(GetMasterFingerprintResult{fingerprint_});
      const auto& signer = WalletSigner(*wallet_, fingerprint_);
      return requestPublicKey(ParseKeypath(signer.get_derivation_path()),
                              Phase::ACCOUNT_KEY);
    }
    if (phase_ == Phase::ACCOUNT_KEY) {
      const auto& signer = WalletSigner(*wallet_, fingerprint_);
      if (DecodeExtPubKey(xpub) != DecodeExtPubKey(signer.get_xpub()) ||
          (response.contains("root_fingerprint") &&
           MasterFingerprint(response) != fingerprint_)) {
        return fail(OneKeyErrorCode::UNSUPPORTED_WALLET,
                    "OneKey account key does not match the wallet");
      }
      return continueWallet();
    }
    message_public_key_ = HexStr(DecodeExtPubKey(xpub).pubkey);
    interaction_ = UserInteraction::SIGN_MESSAGE;
    phase_ = Phase::MESSAGE;
    return send(
        proto::SIGN_MESSAGE,
        {{"address_n", path_},
         {"coin_name", CoinName(chain_)},
         {"message", HexStr(std::span(reinterpret_cast<const unsigned char*>(
                                          message_.data()),
                                      message_.size()))}});
  }
  if (phase_ == Phase::ADDRESS && type == proto::ADDRESS) {
    if (response.at("address") != expected_address_) {
      return fail(OneKeyErrorCode::INVALID_RESPONSE,
                  "OneKey address does not match the wallet");
    }
    return finish(WalletAddressResult{expected_address_});
  }
  if (phase_ == Phase::MESSAGE && type == proto::MESSAGE_SIGNATURE) {
    auto signature = ParseHex(response.at("signature").get<std::string>());
    CPubKey recovered;
    if (signature.size() != 65 ||
        !recovered.RecoverCompact(MessageHash(message_), signature) ||
        HexStr(recovered) != message_public_key_ ||
        response.at("address") !=
            EncodeDestination(PKHash(recovered.GetID()))) {
      return fail(OneKeyErrorCode::INVALID_RESPONSE,
                  "Invalid OneKey message signature");
    }
    return finish(SignMessageResult{EncodeBase64(signature)});
  }
  if (phase_ == Phase::TX && type == proto::TX_REQUEST) {
    if (response.contains("signature_index")) {
      size_t index = response.at("signature_index").get<uint32_t>();
      if (index >= signatures_.size() || !signatures_[index].empty() ||
          response.at("signature").get<std::string>().empty()) {
        return fail(OneKeyErrorCode::INVALID_RESPONSE,
                    "Invalid or duplicate OneKey signature index");
      }
      signatures_[index] = response.at("signature");
    }
    if (response.at("request_type") == 3) {
      return finish(SignPsbtResult{MergeSignatures(*prepared_, signatures_)});
    }
    return send(proto::TX_ACK, TransactionAck(*prepared_, response));
  }
  if (phase_ == Phase::RAW_PSBT && type == proto::SIGNED_PSBT) {
    return finish(
        SignPsbtResult{MergeSignedPsbt(*prepared_, response.at("psbt"))});
  }
  return fail(OneKeyErrorCode::INVALID_RESPONSE,
              "Unexpected OneKey response for the pending command");
}

OneKeyStep OneKeySession::continueWallet() {
  if (command_ == Command::ADDRESS) {
    auto request =
        AddressRequest(*wallet_, WalletSigner(*wallet_, fingerprint_),
                       address_options_.change, address_index_);
    request["coin_name"] = CoinName(chain_);
    request["show_display"] = address_options_.check_on_device;
    interaction_ = address_options_.check_on_device
                       ? UserInteraction::VERIFY_ADDRESS
                       : UserInteraction::NONE;
    phase_ = Phase::ADDRESS;
    return send(proto::GET_ADDRESS, request);
  }
  try {
    prepared_ = PreparePsbt(*wallet_, psbt_, fingerprint_, chain_);
  } catch (const std::exception& e) {
    return fail(OneKeyErrorCode::INVALID_PSBT, e.what());
  }
  interaction_ = UserInteraction::SIGN_TRANSACTION;
  if (!prepared_->raw_psbt.empty() && device_info_.supports_raw_psbt) {
    phase_ = Phase::RAW_PSBT;
    return send(proto::SIGN_PSBT, {{"psbt", prepared_->raw_psbt},
                                   {"coin_name", CoinName(chain_)}});
  }
  phase_ = Phase::TX;
  signatures_.resize(prepared_->transaction.at("inputs").size());
  return send(proto::SIGN_TX, prepared_->transaction);
}

OneKeyStep OneKeySession::finish(OneKeyValue value) {
  resetCommand();
  result_ = std::move(value);
  OneKeyStep step;
  step.type = OneKeyStepType::COMPLETE;
  return step;
}

OneKeyStep OneKeySession::fail(OneKeyErrorCode code, const std::string& message,
                               int device_code) {
  resetCommand();
  result_.reset();
  initialized_ = false;
  reset_required_ = true;
  OneKeyStep step;
  step.type = OneKeyStepType::FAILED;
  step.error = OneKeyError{code, message, device_code};
  return step;
}

bool OneKeySession::initialized() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return initialized_;
}

OneKeyDeviceInfo OneKeySession::deviceInfo() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return device_info_;
}

OneKeyValue OneKeySession::result() const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!result_) throw std::logic_error("OneKey operation has not completed");
  return *result_;
}

}  // namespace nunchuk::onekey
