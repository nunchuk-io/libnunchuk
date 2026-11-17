/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */
#ifndef NUNCHUK_ONEKEY_SESSION_HPP
#define NUNCHUK_ONEKEY_SESSION_HPP

#include <mutex>
#include <nunchuk.h>
#include "utils/onekey/psbt.hpp"
#include "utils/onekey/wire_framer.hpp"

namespace nunchuk::onekey {

class OneKeySession {
 public:
  OneKeySession(Chain chain, OneKeyTransport transport);
  OneKeyStep initialize();
  OneKeyStep onData(std::span<const unsigned char> data);
  OneKeyStep providePin(const std::string& pin);
  OneKeyStep enterPinOnDevice();
  OneKeyStep providePassphrase(const std::string& passphrase);
  OneKeyStep enterPassphraseOnDevice(bool attach_to_pin = false);
  OneKeyStep cancel();
  OneKeyStep onDisconnected();

  OneKeyStep getExtendedPublicKey(
      const std::string& derivation_path,
      const GetExtendedPublicKeyOptions& options = {});
  OneKeyStep getMasterFingerprint();
  OneKeyStep getWalletAddress(const Wallet& wallet, uint32_t address_index,
                              const WalletAddressOptions& options = {});
  OneKeyStep signMessage(const std::string& derivation_path,
                         const std::string& message);
  OneKeyStep signPsbt(const Wallet& wallet, const std::string& psbt);

  bool initialized() const;
  OneKeyDeviceInfo deviceInfo() const;
  OneKeyValue result() const;
  template <typename T>
  T result() const {
    return std::get<T>(result());
  }

 private:
  enum class Command {
    NONE,
    INITIALIZE,
    XPUB,
    FINGERPRINT,
    ADDRESS,
    MESSAGE,
    PSBT
  };
  enum class Phase {
    NONE,
    FEATURES,
    XPUB,
    FINGERPRINT,
    ACCOUNT_KEY,
    MESSAGE_KEY,
    ADDRESS,
    MESSAGE,
    TX,
    RAW_PSBT,
    CANCEL
  };
  enum class Prompt { NONE, PIN, PASSPHRASE };

  void requireAvailable(bool require_initialized = true) const;
  void begin(Command command);
  void resetCommand();
  OneKeyStep send(uint16_t type,
                  const nlohmann::json& data = nlohmann::json::object());
  OneKeyStep requestPublicKey(const std::vector<uint32_t>& path, Phase phase,
                              bool display = false);
  OneKeyStep handleResponse(uint16_t type, const nlohmann::json& response);
  OneKeyStep continueWallet();
  OneKeyStep finish(OneKeyValue value);
  OneKeyStep fail(OneKeyErrorCode code, const std::string& message,
                  int device_code = 0);

  mutable std::mutex mutex_;
  Chain chain_;
  WireFramer framer_;
  bool initialized_ = false;
  bool reset_required_ = false;
  bool on_device_entry_ = false;
  bool attach_pin_available_ = false;
  bool passphrase_required_on_device_ = false;
  OneKeyDeviceInfo device_info_;
  Command command_ = Command::NONE;
  Phase phase_ = Phase::NONE;
  Prompt prompt_ = Prompt::NONE;
  UserInteraction interaction_ = UserInteraction::NONE;
  std::optional<OneKeyValue> result_;
  std::vector<uint32_t> path_;
  std::string fingerprint_;
  std::optional<Wallet> wallet_;
  uint32_t address_index_ = 0;
  WalletAddressOptions address_options_;
  std::string expected_address_;
  std::string message_;
  std::string message_public_key_;
  std::string psbt_;
  std::optional<PreparedPsbt> prepared_;
  std::vector<std::string> signatures_;
};

}  // namespace nunchuk::onekey
#endif  // NUNCHUK_ONEKEY_SESSION_HPP
