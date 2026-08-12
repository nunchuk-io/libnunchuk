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

#include "utils/ledger/bitcoin_app.hpp"

#include <crypto/common.h>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <span.h>
#include <tinyformat.h>
#include <util/bip32.h>
#include <util/strencodings.h>

#include "descriptor.h"
#include "utils/ledger/continuation.hpp"

namespace nunchuk::ledger::bitcoin {
namespace {

constexpr uint8_t BTC_CLA = 0xe1;
constexpr uint8_t CONTINUE_CLA = 0xf8;
constexpr uint8_t OS_CLA = 0xe0;
constexpr uint8_t GET_APP_AND_VERSION_CLA = 0xb0;
constexpr uint8_t GET_EXTENDED_PUBLIC_KEY_INS = 0x00;
constexpr uint8_t GET_APP_AND_VERSION_INS = 0x01;
constexpr uint8_t REGISTER_WALLET_INS = 0x02;
constexpr uint8_t GET_WALLET_ADDRESS_INS = 0x03;
constexpr uint8_t SIGN_PSBT_INS = 0x04;
constexpr uint8_t GET_MASTER_FINGERPRINT_INS = 0x05;
constexpr uint8_t SIGN_MESSAGE_INS = 0x10;
constexpr uint8_t CLOSE_APP_CLA = 0xb0;
constexpr uint8_t CLOSE_APP_INS = 0xa7;
constexpr uint8_t OPEN_APP_INS = 0xd8;
constexpr uint8_t CONTINUE_INS = 0x01;
constexpr uint8_t PROTOCOL_VERSION = 0x01;
constexpr size_t MASTER_FINGERPRINT_LENGTH = 4;
constexpr size_t SHA256_LENGTH = 32;
constexpr size_t MESSAGE_SIGNATURE_LENGTH = 65;
constexpr size_t WALLET_ID_LENGTH = 32;
constexpr size_t WALLET_HMAC_LENGTH = 32;
constexpr size_t MERKLE_ROOT_LENGTH = 32;

}  // namespace

std::vector<unsigned char> BuildGetAppAndVersionApdu() {
  return SerializeApdu(GET_APP_AND_VERSION_CLA, GET_APP_AND_VERSION_INS, 0x00,
                       0x00, {});
}

std::vector<unsigned char> BuildCloseAppApdu() {
  return SerializeApdu(CLOSE_APP_CLA, CLOSE_APP_INS, 0x00, 0x00, {});
}

std::vector<unsigned char> BuildOpenAppApdu(const std::string& app_name) {
  return SerializeApdu(OS_CLA, OPEN_APP_INS, 0x00, 0x00,
                       MakeUCharSpan(app_name));
}

void RequireSuccessResponse(const ApduResponse& response) {
  if (response.status_word != SW_OK) {
    throw std::runtime_error(StatusWordMessage(response.status_word));
  }
}

std::vector<unsigned char> BuildGetExtendedPublicKeyApdu(
    const std::string& derivation_path,
    const GetExtendedPublicKeyOptions& options) {
  const auto path = "m" + FormalizePath(derivation_path);
  std::vector<uint32_t> keypath;
  if (!ParseHDKeypath(path, keypath)) {
    throw std::invalid_argument(
        strprintf("Invalid BIP32 derivation path: %s", path));
  }
  if (keypath.size() > 0xff) {
    throw std::invalid_argument("BIP32 derivation path is too long");
  }

  std::vector<unsigned char> data;
  data.reserve(2 + keypath.size() * sizeof(uint32_t));
  data.push_back(options.check_on_device ? 0x01 : 0x00);
  data.push_back(static_cast<unsigned char>(keypath.size()));
  for (const auto element : keypath) {
    const auto offset = data.size();
    data.resize(offset + sizeof(uint32_t));
    WriteBE32(data.data() + offset, element);
  }

  return SerializeApdu(BTC_CLA, GET_EXTENDED_PUBLIC_KEY_INS, 0x00,
                       PROTOCOL_VERSION, data);
}

std::vector<unsigned char> BuildGetMasterFingerprintApdu() {
  return SerializeApdu(BTC_CLA, GET_MASTER_FINGERPRINT_INS, 0x00,
                       PROTOCOL_VERSION, {});
}

std::vector<unsigned char> BuildSignMessageApdu(
    const std::string& derivation_path, size_t message_length,
    const std::vector<unsigned char>& message_merkle_root) {
  if (message_merkle_root.size() != SHA256_LENGTH) {
    throw std::invalid_argument("Message Merkle root must be 32 bytes");
  }

  const auto path = "m" + FormalizePath(derivation_path);
  std::vector<uint32_t> keypath;
  if (!ParseHDKeypath(path, keypath)) {
    throw std::invalid_argument(
        strprintf("Invalid BIP32 derivation path: %s", path));
  }
  if (keypath.size() > 0xff) {
    throw std::invalid_argument("BIP32 derivation path is too long");
  }

  std::vector<unsigned char> data;
  data.reserve(1 + keypath.size() * sizeof(uint32_t) + 9 + SHA256_LENGTH);
  data.push_back(static_cast<unsigned char>(keypath.size()));
  for (const auto element : keypath) {
    const auto offset = data.size();
    data.resize(offset + sizeof(uint32_t));
    WriteBE32(data.data() + offset, element);
  }
  const auto encoded_length =
      EncodeLedgerVarint(static_cast<uint64_t>(message_length));
  data.insert(data.end(), encoded_length.begin(), encoded_length.end());
  data.insert(data.end(), message_merkle_root.begin(),
              message_merkle_root.end());

  return SerializeApdu(BTC_CLA, SIGN_MESSAGE_INS, 0x00, PROTOCOL_VERSION,
                       data);
}

std::vector<unsigned char> BuildRegisterWalletApdu(
    const std::vector<unsigned char>& serialized_wallet_policy) {
  if (serialized_wallet_policy.size() > 0xfe) {
    throw std::invalid_argument("Serialized wallet policy is too large");
  }

  std::vector<unsigned char> data;
  data.reserve(1 + serialized_wallet_policy.size());
  data.push_back(static_cast<unsigned char>(serialized_wallet_policy.size()));
  data.insert(data.end(), serialized_wallet_policy.begin(),
              serialized_wallet_policy.end());

  return SerializeApdu(BTC_CLA, REGISTER_WALLET_INS, 0x00, PROTOCOL_VERSION,
                       data);
}

std::vector<unsigned char> BuildGetWalletAddressApdu(
    bool check_on_device, const std::vector<unsigned char>& wallet_id,
    const std::vector<unsigned char>& wallet_hmac, bool change,
    uint32_t address_index) {
  if (wallet_id.size() != WALLET_ID_LENGTH) {
    throw std::invalid_argument("Wallet ID must be 32 bytes");
  }
  if (wallet_hmac.size() != WALLET_HMAC_LENGTH) {
    throw std::invalid_argument("Wallet HMAC must be 32 bytes");
  }

  std::vector<unsigned char> data;
  data.reserve(1 + WALLET_ID_LENGTH + WALLET_HMAC_LENGTH + 1 +
               sizeof(uint32_t));
  data.push_back(check_on_device ? 0x01 : 0x00);
  data.insert(data.end(), wallet_id.begin(), wallet_id.end());
  data.insert(data.end(), wallet_hmac.begin(), wallet_hmac.end());
  data.push_back(change ? 0x01 : 0x00);
  const auto offset = data.size();
  data.resize(offset + sizeof(uint32_t));
  WriteBE32(data.data() + offset, address_index);

  return SerializeApdu(BTC_CLA, GET_WALLET_ADDRESS_INS, 0x00,
                       PROTOCOL_VERSION, data);
}

std::vector<unsigned char> BuildSignPsbtApdu(
    const std::vector<unsigned char>& global_commitment, size_t inputs_count,
    const std::vector<unsigned char>& inputs_root, size_t outputs_count,
    const std::vector<unsigned char>& outputs_root,
    const std::vector<unsigned char>& wallet_id,
    const std::vector<unsigned char>& wallet_hmac) {
  if (global_commitment.size() < 1 + 2 * MERKLE_ROOT_LENGTH) {
    throw std::invalid_argument("PSBT global commitment is invalid");
  }
  if (inputs_count > 0xff || outputs_count > 0xff) {
    throw std::invalid_argument("Ledger supports at most 255 PSBT inputs and outputs");
  }
  if (inputs_root.size() != MERKLE_ROOT_LENGTH) {
    throw std::invalid_argument("PSBT inputs root must be 32 bytes");
  }
  if (outputs_root.size() != MERKLE_ROOT_LENGTH) {
    throw std::invalid_argument("PSBT outputs root must be 32 bytes");
  }
  if (wallet_id.size() != WALLET_ID_LENGTH) {
    throw std::invalid_argument("Wallet ID must be 32 bytes");
  }
  if (wallet_hmac.size() != WALLET_HMAC_LENGTH) {
    throw std::invalid_argument("Wallet HMAC must be 32 bytes");
  }

  std::vector<unsigned char> data;
  data.reserve(global_commitment.size() + 1 + MERKLE_ROOT_LENGTH + 1 +
               MERKLE_ROOT_LENGTH + WALLET_ID_LENGTH + WALLET_HMAC_LENGTH);
  data.insert(data.end(), global_commitment.begin(), global_commitment.end());
  data.push_back(static_cast<unsigned char>(inputs_count));
  data.insert(data.end(), inputs_root.begin(), inputs_root.end());
  data.push_back(static_cast<unsigned char>(outputs_count));
  data.insert(data.end(), outputs_root.begin(), outputs_root.end());
  data.insert(data.end(), wallet_id.begin(), wallet_id.end());
  data.insert(data.end(), wallet_hmac.begin(), wallet_hmac.end());

  return SerializeApdu(BTC_CLA, SIGN_PSBT_INS, 0x00, PROTOCOL_VERSION, data);
}

std::vector<unsigned char> BuildContinueApdu(
    const std::vector<unsigned char>& payload) {
  return SerializeApdu(CONTINUE_CLA, CONTINUE_INS, 0x00, PROTOCOL_VERSION,
                       payload);
}

GetExtendedPublicKeyResult ParseGetExtendedPublicKeyResponse(
    const ApduResponse& response) {
  RequireSuccessResponse(response);
  if (response.data.empty()) {
    throw std::runtime_error("Ledger returned an empty extended public key");
  }
  return GetExtendedPublicKeyResult{
      std::string(response.data.begin(), response.data.end())};
}

GetMasterFingerprintResult ParseGetMasterFingerprintResponse(
    const ApduResponse& response) {
  RequireSuccessResponse(response);
  if (response.data.size() != MASTER_FINGERPRINT_LENGTH) {
    throw std::runtime_error("Ledger returned an invalid master fingerprint");
  }
  return GetMasterFingerprintResult{HexStr(response.data)};
}

SignMessageResult ParseMessageSignatureResponse(const ApduResponse& response) {
  RequireSuccessResponse(response);
  if (response.data.size() != MESSAGE_SIGNATURE_LENGTH) {
    throw std::runtime_error("Ledger returned an invalid message signature");
  }
  return SignMessageResult{EncodeBase64(response.data)};
}

std::string ParseRegisterWalletResponse(const ApduResponse& response) {
  RequireSuccessResponse(response);
  if (response.data.size() != WALLET_ID_LENGTH + WALLET_HMAC_LENGTH) {
    throw std::runtime_error("Ledger returned an invalid wallet registration");
  }
  const auto hmac =
      std::span<const unsigned char>{response.data}.subspan(WALLET_ID_LENGTH);
  return HexStr(hmac);
}

WalletAddressResult ParseWalletAddressResponse(const ApduResponse& response) {
  RequireSuccessResponse(response);
  if (response.data.empty()) {
    throw std::runtime_error("Ledger returned an empty wallet address");
  }
  return WalletAddressResult{
      std::string(response.data.begin(), response.data.end())};
}

std::string StatusWordMessage(uint16_t status_word) {
  switch (status_word) {
    case SW_INCORRECT_DATA:
      return "Ledger Bitcoin app error: incorrect data";
    case SW_REQUEST_NOT_SUPPORTED:
      return "Ledger Bitcoin app error: request not supported";
    case SW_USER_REJECTED:
      return "Ledger Bitcoin app error: rejected by user";
    case SW_INCORRECT_P1_P2:
      return "Ledger Bitcoin app error: P1 or P2 is incorrect";
    case SW_INCORRECT_LENGTH:
      return "Ledger Bitcoin app error: Lc or minimum APDU length is incorrect";
    case SW_INS_NOT_SUPPORTED:
      return "Ledger Bitcoin app error: no command exists for INS";
    case SW_BAD_CLA:
      return "Ledger Bitcoin app error: bad CLA";
    case SW_DEVICE_LOCKED:
      return "Ledger device is locked. Unlock it and retry.";
    case SW_WRONG_RESPONSE_LENGTH:
      return "Ledger Bitcoin app error: wrong response length";
    case SW_UNEXPECTED_STATE:
      return "Ledger Bitcoin app error: unexpected state";
    case SW_INVALID_SIGNATURE_OR_HMAC:
      return "Ledger Bitcoin app error: invalid signature or HMAC";
    case SW_INTERRUPTED_EXECUTION:
      return "Ledger Bitcoin app requested an interrupted-execution continuation";
    default:
      return strprintf("Ledger Bitcoin app returned status word 0x%04x",
                       status_word);
  }
}

}  // namespace nunchuk::ledger::bitcoin
