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

#ifndef NUNCHUK_LEDGER_SESSION_H
#define NUNCHUK_LEDGER_SESSION_H

#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "utils/ledger/apdu_framer.hpp"
#include "utils/ledger/continuation.hpp"
#include "utils/ledger/types.hpp"

namespace nunchuk::ledger {

class LedgerSession {
 public:
  explicit LedgerSession(LedgerTransport transport);

  LedgerStep onData(const std::vector<unsigned char>& data);
  LedgerStep resume();

  LedgerValue result() const;

  template <typename T>
  T result() const {
    return std::get<T>(result());
  }

  LedgerStep getExtendedPublicKey(
      const std::string& derivation_path,
      const GetExtendedPublicKeyOptions& options = {});

  LedgerStep getExtendedPublicKey(
      WalletType wallet_type, AddressType address_type, int index,
      const GetExtendedPublicKeyOptions& options = {});

  LedgerStep getMasterFingerprint();

  LedgerStep signMessage(const std::string& derivation_path,
                         const std::string& message);

  LedgerStep signPsbt(const RegisteredWallet& wallet, const std::string& psbt);

  LedgerStep getWalletAddress(const RegisteredWallet& wallet,
                              uint32_t address_index,
                              const WalletAddressOptions& options = {});

  LedgerStep registerWallet(const Bip388Policy& policy,
                            const std::string& wallet_name);

  LedgerStep registerWallet(const Wallet& wallet);

 private:
  friend class LedgerManager;

  enum class ActiveCommand {
    NONE,
    SETUP_BLE_MTU,
    GET_APP_AND_VERSION,
    CLOSE_APP,
    OPEN_APP,
    GET_EXTENDED_PUBLIC_KEY,
    GET_MASTER_FINGERPRINT,
    SIGN_MESSAGE,
    SIGN_PSBT,
    REGISTER_WALLET,
    GET_WALLET_ADDRESS,
  };

  LedgerStep sendBitcoinApdu(
      const std::vector<unsigned char>& apdu, ActiveCommand command,
      UserInteraction interaction = UserInteraction::NONE);
  LedgerStep queueBitcoinApdu(
      const std::vector<unsigned char>& apdu, ActiveCommand command,
      UserInteraction interaction = UserInteraction::NONE);
  LedgerStep beginWrite(const std::vector<unsigned char>& apdu,
                        ActiveCommand command,
                        UserInteraction interaction = UserInteraction::NONE);
  LedgerStep beginBleMtuSetup();
  LedgerStep checkCurrentApp();
  LedgerStep sendCloseApp();
  LedgerStep sendOpenApp();
  LedgerStep sendPendingCommand();
  LedgerStep completeBleMtuSetup(const std::vector<unsigned char>& data);
  LedgerStep completeResponse(const ApduResponse& response);
  LedgerStep completeInterruptedExecution(const ApduResponse& response);
  LedgerStep completeGetAppAndVersion(const ApduResponse& response);
  LedgerStep completeCloseApp(const ApduResponse& response);
  LedgerStep completeOpenApp(const ApduResponse& response);
  LedgerStep fail(const std::string& message, uint16_t status_word = SW_NONE);
  void updateTransport(LedgerTransport transport);
  void resetState();
  bool canResumeAppSwitch() const;
  bool needsBleMtuSetup() const;
  bool isAppSwitchCommand(ActiveCommand command) const;
  bool supportsInterruptedExecution(ActiveCommand command) const;

  mutable std::mutex mutex_;
  LedgerTransport transport_;
  ApduFramer framer_;
  ActiveCommand active_command_ = ActiveCommand::NONE;
  ActiveCommand pending_command_ = ActiveCommand::NONE;
  UserInteraction active_interaction_ = UserInteraction::NONE;
  UserInteraction pending_interaction_ = UserInteraction::NONE;
  std::optional<std::vector<unsigned char>> pending_apdu_;
  std::optional<std::string> pending_psbt_;
  LedgerValue result_;
  LedgerContinuationContext continuation_context_;
  bool has_result_ = false;
  bool awaiting_response_ = false;
  bool awaiting_app_switch_resume_ = false;
  bool ble_mtu_setup_done_ = false;
};

}  // namespace nunchuk::ledger

#endif  // NUNCHUK_LEDGER_SESSION_H
