/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */

#ifndef NUNCHUK_ONEKEY_TYPES_HPP
#define NUNCHUK_ONEKEY_TYPES_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace nunchuk::onekey {

enum class OneKeyTransport { USB, BLE };
enum class OneKeyProtocol { V1, V2 };
enum class OneKeyStepType { WRITE, READ_MORE, AWAITING_USER, COMPLETE, FAILED };
enum class UserInteraction {
  NONE,
  UNLOCK_DEVICE,
  ENTER_PIN,
  ENTER_PASSPHRASE,
  VERIFY_ADDRESS,
  EXPORT_PUBLIC_KEY,
  SIGN_MESSAGE,
  SIGN_TRANSACTION,
};
enum class OneKeyModel { UNKNOWN, CLASSIC, CLASSIC1S, PRO, PRO2, NEO };
enum class OneKeyErrorCode {
  INVALID_STATE,
  INVALID_ARGUMENT,
  INVALID_RESPONSE,
  UNSUPPORTED_DEVICE,
  UNSUPPORTED_FIRMWARE,
  UNSUPPORTED_WALLET,
  INVALID_PSBT,
  SESSION_LOST,
  USER_CANCELLED,
  DEVICE,
  BLE_UNAVAILABLE_WHILE_USB_CONNECTED,
};

struct OneKeyError {
  OneKeyErrorCode code = OneKeyErrorCode::DEVICE;
  std::string message;
  int device_code = 0;
};

struct OneKeyStep {
  OneKeyStepType type = OneKeyStepType::READ_MORE;
  UserInteraction interaction = UserInteraction::NONE;
  std::vector<std::vector<unsigned char>> writes;
  std::optional<OneKeyError> error;
  uint32_t request_code = 0;
  bool on_device_available = false;
  bool on_device_required = false;
  bool attach_pin_available = false;
};

struct OneKeyDeviceInfo {
  OneKeyModel model = OneKeyModel::UNKNOWN;
  std::string firmware_version;
  std::string device_id;
  std::string label;
  bool initialized = false;
  bool unlocked = false;
  bool pin_protection = false;
  bool passphrase_protection = false;
  bool passphrase_on_device = false;
  bool bootloader = false;
  bool supports_raw_psbt = false;
};

struct GetExtendedPublicKeyOptions {
  bool check_on_device = false;
};
struct WalletAddressOptions {
  bool check_on_device = true;
  bool change = false;
};
struct InitializeResult {
  OneKeyDeviceInfo device;
};
struct GetExtendedPublicKeyResult {
  std::string extended_public_key;
};
struct GetMasterFingerprintResult {
  std::string master_fingerprint;
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

using OneKeyValue =
    std::variant<std::monostate, InitializeResult, GetExtendedPublicKeyResult,
                 GetMasterFingerprintResult, WalletAddressResult,
                 SignMessageResult, SignPsbtResult>;

}  // namespace nunchuk::onekey

#endif  // NUNCHUK_ONEKEY_TYPES_HPP
