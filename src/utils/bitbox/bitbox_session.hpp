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

#ifndef NUNCHUK_BITBOX_SESSION_H
#define NUNCHUK_BITBOX_SESSION_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include <nunchuk.h>

#include "utils/bitbox/psbt.hpp"
#include "utils/bitbox/types.hpp"
#include "utils/bitbox/u2f_framer.hpp"

namespace nunchuk::bitbox {

class NoiseHandshake;
class PairingStore;

class BitBoxSession {
 public:
  BitBoxSession(std::shared_ptr<PairingStore> pairing_store, Chain chain,
                BitBoxTransport transport);
  ~BitBoxSession();

  BitBoxStep initialize();
  BitBoxStep onData(std::span<const unsigned char> data);
  BitBoxStep resume();
  BitBoxStep confirmPairing(bool accepted);

  BitBoxStep setDeviceName(const std::string& name);
  BitBoxStep changePassword();
  BitBoxStep setMnemonicPassphraseEnabled(bool enabled);
  BitBoxStep factoryReset();
  BitBoxStep createNewSeed(BitBoxMnemonicLength mnemonic_length);
  BitBoxStep showMnemonic();
  BitBoxStep checkSdCard();
  BitBoxStep insertSdCard();
  BitBoxStep createBackup();
  BitBoxStep listBackups();
  BitBoxStep checkBackup(bool silent = false);
  BitBoxStep restoreBackup(const std::string& id);
  BitBoxStep restoreFromMnemonic();
  BitBoxStep enterFirmwareUpgrade(
      std::span<const unsigned char> signed_firmware);

  BitBoxStep getExtendedPublicKey(
      const std::string& derivation_path,
      const GetExtendedPublicKeyOptions& options = {});
  BitBoxStep getMasterFingerprint();
  BitBoxStep isWalletRegistered(const Wallet& wallet);
  BitBoxStep registerWallet(const Wallet& wallet);
  BitBoxStep getWalletAddress(
      const Wallet& wallet, uint32_t address_index,
      const WalletAddressOptions& options = {});
  BitBoxStep signMessage(const std::string& derivation_path,
                         const std::string& message);
  BitBoxStep signPsbt(const Wallet& wallet, const std::string& psbt);

  bool initialized() const;
  BitBoxDeviceInfo deviceInfo() const;
  BitBoxValue result() const;

  template <typename T>
  T result() const {
    return std::get<T>(result());
  }

 private:
  enum class Command {
    NONE,
    INITIALIZE,
    SET_DEVICE_NAME,
    CHANGE_PASSWORD,
    SET_MNEMONIC_PASSPHRASE,
    FACTORY_RESET,
    CREATE_NEW_SEED,
    SHOW_MNEMONIC,
    CHECK_SD_CARD,
    INSERT_SD_CARD,
    CREATE_BACKUP,
    LIST_BACKUPS,
    CHECK_BACKUP,
    RESTORE_BACKUP,
    RESTORE_FROM_MNEMONIC,
    ENTER_FIRMWARE_UPGRADE,
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
    INFO,
    ATTESTATION,
    UNLOCK,
    HANDSHAKE_START,
    HANDSHAKE_MESSAGE_1,
    HANDSHAKE_MESSAGE_3,
    PAIRING_VERIFY,
    DEVICE_INFO,
    REFRESH_DEVICE_INFO,
    FETCH_FINGERPRINT,
    COMMAND_RESPONSE,
    MESSAGE_COMMITMENT,
    MESSAGE_SIGNATURE,
    PSBT_RESPONSE,
  };

  enum class RequestState {
    IDLE,
    AWAITING_DATA,
    RETRY_POLL,
    RETRY_RESEND,
  };

  struct InitializationContext {
    std::array<unsigned char, 32> attestation_challenge{};
    AttestationStatus attestation = AttestationStatus::NOT_CHECKED;
    std::string attestation_message;
    std::optional<std::string> pairing_code;
    std::optional<bool> app_pairing_confirmed;
    bool device_pairing_confirmed = false;
  };

  struct WalletCommandContext {
    Wallet wallet;
    size_t registration_account_index = 0;
  };

  struct AddressCommandContext {
    Wallet wallet;
    uint32_t address_index = 0;
    WalletAddressOptions options;
  };

  struct AntiKleptoContext {
    std::array<unsigned char, 32> host_nonce{};
    std::vector<unsigned char> signer_commitment;
  };

  struct MessageSigningContext {
    std::optional<AntiKleptoContext> anti_klepto;
  };

  struct PsbtSigningContext {
    Wallet wallet;
    std::string encoded_psbt;
    std::optional<PreparedPsbt> prepared_psbt;
    std::vector<std::vector<uint32_t>> signing_account_keypaths;
    size_t signing_account_keypath_index = 0;
    bool second_pass = false;
    std::optional<size_t> pending_signature_input;
    std::optional<AntiKleptoContext> anti_klepto;
  };

  using CommandContext =
      std::variant<std::monostate, InitializationContext,
                   WalletCommandContext, AddressCommandContext,
                   MessageSigningContext, PsbtSigningContext>;

  BitBoxStep sendRaw(std::vector<unsigned char> payload, Phase phase,
                     UserInteraction interaction = UserInteraction::NONE,
                     const std::optional<std::string>& pairing_code = {});
  BitBoxStep sendInfo();
  BitBoxStep sendEncrypted(std::vector<unsigned char> request, Phase phase,
                           UserInteraction interaction = UserInteraction::NONE);
  BitBoxStep makeWrite(std::span<const unsigned char> transport_payload,
                       UserInteraction interaction,
                       const std::optional<std::string>& pairing_code = {});
  BitBoxStep handleTransportPayload(
      std::span<const unsigned char> transport_payload,
      bool retry_poll_response);
  BitBoxStep handleResponse(std::span<const unsigned char> payload);
  BitBoxStep handleInfo(std::span<const unsigned char> payload);
  BitBoxStep handleInitializeResponse(std::span<const unsigned char> payload);
  BitBoxStep handleEncryptedResponse(std::span<const unsigned char> payload);
  BitBoxStep handleCommandResponse(std::span<const unsigned char> plaintext);
  BitBoxStep continueRegistration(WalletCommandContext& context);
  BitBoxStep startPsbtPass(
      PsbtSigningContext& context,
      const std::optional<std::vector<uint32_t>>& account_keypath =
          std::nullopt);
  BitBoxStep continueAfterFingerprint();
  BitBoxStep finishPairing();
  bool rebootExpected() const;
  BitBoxStep finishReboot();
  BitBoxStep finish(BitBoxValue value);
  BitBoxStep fail(BitBoxErrorCode code, const std::string& message,
                  int device_code = 0);
  void resetCommand();
  void clearCommandContext();
  std::optional<BitBoxStep> requireReady(
      bool allow_firmware_upgrade_required = false);
  std::optional<BitBoxStep> requireDeviceInitialized();
  BitBoxStep requireFingerprintOrContinue();
  const std::optional<std::string>& pairingCode() const;

  mutable std::mutex mutex_;
  std::shared_ptr<PairingStore> pairing_store_;
  const Chain chain_;
  const BitBoxTransport transport_;
  U2fFramer framer_;
  std::unique_ptr<NoiseHandshake> noise_;
  Command command_ = Command::NONE;
  Phase phase_ = Phase::NONE;
  RequestState request_state_ = RequestState::IDLE;
  bool awaiting_retry_poll_response_ = false;
  UserInteraction interaction_ = UserInteraction::NONE;
  std::vector<unsigned char> last_new_request_;
  bool initialized_ = false;
  std::optional<BitBoxValue> result_;
  BitBoxDeviceInfo device_info_;
  CommandContext command_context_;
  std::optional<std::string> root_fingerprint_;
};

}  // namespace nunchuk::bitbox

#endif  // NUNCHUK_BITBOX_SESSION_H
