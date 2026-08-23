/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */

#ifndef NUNCHUK_JADE_SESSION_H
#define NUNCHUK_JADE_SESSION_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <nunchuk.h>

#include "utils/jade/bitcoin.hpp"
#include "utils/jade/http_client.hpp"
#include "utils/jade/types.hpp"

namespace nunchuk::jade {

class JadeSession {
 public:
  JadeSession(Chain chain, std::string certificate_file,
              size_t max_write_size);
  ~JadeSession();

  JadeStep initialize();
  JadeStep onData(std::span<const unsigned char> data);
  JadeStep confirmCustomPinServer(bool approved);

  JadeStep getVersionInfo();
  JadeStep getExtendedPublicKey(const std::string& derivation_path);
  JadeStep getMasterFingerprint();
  JadeStep isWalletRegistered(const Wallet& wallet);
  JadeStep registerWallet(const Wallet& wallet);
  JadeStep getWalletAddress(const Wallet& wallet, uint32_t address_index,
                            const WalletAddressOptions& options = {});
  JadeStep signMessage(const std::string& derivation_path,
                       const std::string& message);
  JadeStep signPsbt(const Wallet& wallet, const std::string& psbt);

  bool initialized() const;
  JadeDeviceInfo deviceInfo() const;
  JadeValue result() const;

  template <typename T>
  T result() const {
    return std::get<T>(result());
  }

 private:
  class CborFramer {
   public:
    void push(std::span<const unsigned char> data);
    std::optional<nlohmann::json> next();
    void reset();

   private:
    std::vector<unsigned char> buffer_;
  };

  enum class Command {
    NONE,
    INITIALIZE,
    GET_VERSION_INFO,
    GET_XPUB,
    GET_FINGERPRINT,
    CHECK_REGISTRATION,
    REGISTER_WALLET,
    GET_ADDRESS,
    SIGN_MESSAGE,
    SIGN_PSBT,
  };

  enum class Phase {
    NONE,
    INITIALIZE_ENTROPY,
    INITIALIZE_VERSION,
    INITIALIZE_AUTH,
    INITIALIZE_FINAL_VERSION,
    VERSION_INFO,
    FETCH_FINGERPRINT,
    XPUB,
    REGISTRATION_QUERY,
    REGISTRATION_REGISTER,
    ADDRESS,
    MESSAGE_XPUB,
    MESSAGE_COMMITMENT,
    MESSAGE_SIGNATURE,
    PSBT_CHUNK,
  };

  struct WalletContext {
    Wallet wallet;
    std::optional<JadeWalletConfig> config;
    uint32_t address_index = 0;
    WalletAddressOptions address_options;
    std::vector<unsigned char> psbt;
  };

  struct MessageContext {
    std::vector<uint32_t> path;
    std::string message;
    std::array<unsigned char, 32> host_entropy{};
    std::vector<unsigned char> public_key;
    std::vector<unsigned char> signer_commitment;
  };

  struct PendingHttp {
    JadeHttpRequest request;
    CustomPinServerInfo custom_server;
  };

  JadeStep sendRpc(const std::string& method,
                   const std::optional<nlohmann::json>& params, Phase phase,
                   UserInteraction interaction = UserInteraction::NONE);
  JadeStep handleResponse(const nlohmann::json& response);
  JadeStep handleResult(const nlohmann::json& response,
                        const nlohmann::json& result);
  JadeStep handleHttpRequest(const nlohmann::json& result);
  JadeStep continueAfterFingerprint();
  JadeStep sendRegistrationQuery();
  JadeStep sendAddress();
  JadeStep sendPsbt();
  JadeStep finishPsbt();
  JadeStep finish(JadeValue value);
  JadeStep fail(JadeErrorCode code, const std::string& message,
                int device_code = 0, const std::string& device_data = {});
  JadeStep failHttp(JadeErrorCode code, const std::string& message);
  void requireAvailable(bool require_initialized = true) const;
  void resetCommand();
  void clearMessageContext();

  mutable std::mutex mutex_;
  const Chain chain_;
  const std::string certificate_file_;
  const size_t max_write_size_;
  CborFramer framer_;
  Command command_ = Command::NONE;
  Phase phase_ = Phase::NONE;
  UserInteraction interaction_ = UserInteraction::NONE;
  bool initialized_ = false;
  bool transport_reset_required_ = false;
  uint64_t next_request_id_ = 1;
  std::string expected_id_;
  std::optional<JadeValue> result_;
  JadeDeviceInfo device_info_;
  std::optional<std::string> root_fingerprint_;
  std::optional<WalletContext> wallet_context_;
  std::optional<MessageContext> message_context_;
  std::optional<PendingHttp> pending_http_;
  std::string psbt_original_id_;
  uint32_t psbt_expected_seqnum_ = 0;
  uint32_t psbt_seqlen_ = 0;
  std::vector<unsigned char> psbt_result_;
};

}  // namespace nunchuk::jade

#endif  // NUNCHUK_JADE_SESSION_H
