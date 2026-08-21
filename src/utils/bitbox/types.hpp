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

#ifndef NUNCHUK_BITBOX_TYPES_H
#define NUNCHUK_BITBOX_TYPES_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace nunchuk::bitbox {

enum class BitBoxTransport {
  BLE,
  USB_HID,
};

enum class BitBoxStepType {
  WRITE,
  READ_MORE,
  RETRY_AFTER,
  AWAITING_USER,
  COMPLETE,
  FAILED,
  REBOOT,
};

enum class UserInteraction {
  NONE,
  UNLOCK_DEVICE,
  CONFIRM_PAIRING,
  VERIFY_ADDRESS,
  REGISTER_WALLET,
  SIGN_MESSAGE,
  SIGN_TRANSACTION,
  CONFIRM_DEVICE_NAME,
  SET_DEVICE_PASSWORD,
  SHOW_RECOVERY_WORDS,
  INSERT_SD_CARD,
  CREATE_BACKUP,
  RESTORE_FROM_RECOVERY_WORDS,
  RESTORE_FROM_BACKUP,
  CONFIRM_FIRMWARE_UPGRADE,
  CHANGE_DEVICE_PASSWORD,
  TOGGLE_MNEMONIC_PASSPHRASE,
  CHECK_BACKUP,
  FACTORY_RESET,
};

enum class BitBoxErrorCode {
  NONE = 0,
  INVALID_STATE = 1,
  INVALID_ARGUMENT = 2,
  INVALID_RESPONSE = 3,
  PROTOCOL = 5,
  PAIRING_REJECTED = 6,
  UNSUPPORTED_DEVICE = 8,
  UNSUPPORTED_FIRMWARE = 9,
  UNSUPPORTED_WALLET = 10,
  INVALID_PSBT = 11,
  STORAGE = 12,
  ATTESTATION = 13,
  ANTI_KLEPTO = 14,
  SESSION_LOST = 15,
  DEVICE_UNINITIALIZED = 17,
  INVALID_FIRMWARE = 18,

  // Values returned directly by the BitBox firmware protobuf API.
  DEVICE_INVALID_INPUT = 101,
  DEVICE_MEMORY = 102,
  DEVICE = 103,
  USER_ABORT = 104,
  DEVICE_INVALID_STATE = 105,
  DEVICE_DISABLED = 106,
  DEVICE_DUPLICATE = 107,
  DEVICE_NOISE_ENCRYPT = 108,
  DEVICE_NOISE_DECRYPT = 109,
};

struct BitBoxError {
  BitBoxErrorCode code = BitBoxErrorCode::NONE;
  std::string message;
  int device_code = 0;
};

struct BitBoxStep {
  BitBoxStepType type = BitBoxStepType::READ_MORE;
  UserInteraction interaction = UserInteraction::NONE;
  std::vector<std::vector<unsigned char>> writes;
  uint32_t retry_after_ms = 0;
  std::optional<std::string> pairing_code;
  std::optional<BitBoxError> error;
  std::optional<double> progress;
};

enum class BitBoxProduct {
  UNKNOWN,
  NOVA_MULTI,
  NOVA_BITCOIN_ONLY,
  BITBOX02_MULTI,
  BITBOX02_BITCOIN_ONLY,
};

struct BitBoxEndpoint {
  BitBoxProduct product = BitBoxProduct::UNKNOWN;
  bool bootloader = false;
};

struct BitBoxFirmwareInfo {
  BitBoxProduct product = BitBoxProduct::UNKNOWN;
  uint32_t monotonic_version = 0;
  size_t firmware_size = 0;
};

enum class AttestationStatus {
  NOT_CHECKED,
  VALID,
  INVALID,
};

struct BitBoxDeviceInfo {
  BitBoxProduct product = BitBoxProduct::UNKNOWN;
  std::string firmware_version;
  bool firmware_upgrade_required = false;
  std::string name;
  bool unlocked = false;
  bool initialized = false;
  bool mnemonic_passphrase_enabled = false;
  std::string securechip_model;
  std::string password_stretching_algo;
  bool bluetooth_enabled = false;
  std::string bluetooth_firmware_version;
  std::string bluetooth_firmware_hash;
};

struct InitializeResult {
  BitBoxDeviceInfo device;
  AttestationStatus attestation = AttestationStatus::NOT_CHECKED;
  std::string attestation_message;
};

enum class BitBoxMnemonicLength : uint32_t {
  WORDS_12 = 12,
  WORDS_24 = 24,
};

struct BitBoxBackup {
  std::string id;
  std::string name;
  uint32_t timestamp = 0;
};

struct SdCardStatusResult {
  bool inserted = false;
};

struct ListBackupsResult {
  std::vector<BitBoxBackup> backups;
};

struct CheckBackupResult {
  std::string backup_id;
};

struct GetExtendedPublicKeyOptions {
  bool check_on_device = false;
};

struct WalletAddressOptions {
  bool check_on_device = true;
  bool change = false;
};

struct GetExtendedPublicKeyResult {
  std::string extended_public_key;
};

struct GetMasterFingerprintResult {
  std::string master_fingerprint;
};

struct RegistrationResult {
  bool registered = false;
};

struct WalletAddressResult {
  std::string address;
};

struct SignMessageResult {
  std::string signature;
};

struct SignPsbtResult {
  std::string psbt;
};

using BitBoxValue =
    std::variant<std::monostate, InitializeResult,
                 GetExtendedPublicKeyResult, GetMasterFingerprintResult,
                 RegistrationResult, WalletAddressResult, SignMessageResult,
                 SignPsbtResult, SdCardStatusResult, ListBackupsResult,
                 CheckBackupResult>;

}  // namespace nunchuk::bitbox

#endif  // NUNCHUK_BITBOX_TYPES_H
