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

#ifndef NUNCHUK_LEDGER_TYPES_H
#define NUNCHUK_LEDGER_TYPES_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "utils/bip388.hpp"

namespace nunchuk::ledger {

enum class LedgerTransport {
  BLE,
  USB_HID,
};

enum class LedgerStepType {
  WRITE,
  READ_MORE,
  COMPLETE,
  FAILED,
  APP_SWITCH,
};

enum class UserInteraction {
  NONE,
  UNLOCK_DEVICE,
  CONFIRM_OPEN_APP,
  VERIFY_ADDRESS,
  REGISTER_WALLET,
  SIGN_MESSAGE,
  SIGN_TRANSACTION,
};

enum LedgerStatusWord : uint16_t {
  SW_NONE = 0x0000,
  SW_OK = 0x9000,
  SW_BUSY = 0x6601,
  SW_DEVICE_LOCKED = 0x5515,
  SW_INTERRUPTED_EXECUTION = 0xe000,
  SW_OS_NO_APP_NAME = 0x670a,
  SW_OS_UNKNOWN_APP_NAME = 0x6807,
  SW_INCORRECT_DATA = 0x6a80,
  SW_REQUEST_NOT_SUPPORTED = 0x6a82,
  SW_USER_REJECTED = 0x6985,
  SW_INCORRECT_P1_P2 = 0x6a86,
  SW_INCORRECT_LENGTH = 0x6a87,
  SW_INS_NOT_SUPPORTED = 0x6d00,
  SW_BAD_CLA = 0x6e00,
  SW_WRONG_RESPONSE_LENGTH = 0xb000,
  SW_UNEXPECTED_STATE = 0xb007,
  SW_INVALID_SIGNATURE_OR_HMAC = 0xb008,
};

struct LedgerError {
  int code = 0;
  std::string message;
  uint16_t status_word = SW_NONE;
};

struct LedgerStep {
  LedgerStepType type = LedgerStepType::READ_MORE;
  UserInteraction interaction = UserInteraction::NONE;
  std::vector<std::vector<unsigned char>> writes;
  std::optional<LedgerError> error;
};

struct GetExtendedPublicKeyOptions {
  bool check_on_device = false;
  bool return_chain_code = false;
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

struct SignMessageResult {
  std::string signature;
};

struct SignPsbtResult {
  std::string psbt;
};

struct RegisteredWalletResult {
  std::string hmac;
};

struct WalletAddressResult {
  std::string address;
};

struct RegisteredWallet {
  RegisteredWallet() = default;

  RegisteredWallet(std::string wallet_name, Bip388Policy wallet_policy,
                   std::string wallet_hmac)
      : name(std::move(wallet_name)),
        policy(std::move(wallet_policy)),
        hmac(std::move(wallet_hmac)) {}

  RegisteredWallet(const Wallet& wallet, const std::string& wallet_hmac)
      : RegisteredWallet(wallet.get_name(), GetBip388Policy(wallet),
                         wallet_hmac) {}

  std::string name;
  Bip388Policy policy;
  std::string hmac;
};

using LedgerValue =
    std::variant<std::monostate, GetExtendedPublicKeyResult,
                 GetMasterFingerprintResult, SignMessageResult, SignPsbtResult,
                 RegisteredWalletResult, WalletAddressResult>;

}  // namespace nunchuk::ledger

#endif  // NUNCHUK_LEDGER_TYPES_H
