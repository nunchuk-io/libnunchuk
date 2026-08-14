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

#ifndef NUNCHUK_BITBOX_PROTOBUF_H
#define NUNCHUK_BITBOX_PROTOBUF_H

#include <cstdint>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include "utils/bitbox/types.hpp"

namespace nunchuk::bitbox::proto {

using Bytes = std::vector<unsigned char>;

enum class Coin : uint32_t {
  BTC = 0,
  TBTC = 1,
  RBTC = 4,
};

struct XPub {
  unsigned char depth = 0;
  Bytes parent_fingerprint;
  uint32_t child_number = 0;
  Bytes chain_code;
  Bytes public_key;
};

struct KeyOrigin {
  Bytes root_fingerprint;
  std::vector<uint32_t> keypath;
  XPub xpub;
};

struct ScriptConfig {
  enum class Kind {
    SIMPLE,
    MULTISIG,
    POLICY,
  };

  enum class SimpleType : uint32_t {
    P2WPKH_P2SH = 0,
    P2WPKH = 1,
    P2TR = 2,
  };

  enum class MultisigType : uint32_t {
    P2WSH = 0,
    P2WSH_P2SH = 1,
  };

  Kind kind = Kind::SIMPLE;
  SimpleType simple_type = SimpleType::P2WPKH;
  uint32_t threshold = 0;
  std::vector<XPub> xpubs;
  uint32_t our_xpub_index = 0;
  MultisigType multisig_type = MultisigType::P2WSH;
  std::string policy;
  std::vector<KeyOrigin> keys;
};

struct ScriptConfigWithKeypath {
  ScriptConfig script_config;
  std::vector<uint32_t> keypath;
};

struct SignInput {
  Bytes previous_output_hash;
  uint32_t previous_output_index = 0;
  uint64_t previous_output_value = 0;
  uint32_t sequence = 0;
  std::vector<uint32_t> keypath;
  uint32_t script_config_index = 0;
  Bytes host_nonce_commitment;
};

enum class OutputType : uint32_t {
  UNKNOWN = 0,
  P2PKH = 1,
  P2SH = 2,
  P2WPKH = 3,
  P2WSH = 4,
  P2TR = 5,
  OP_RETURN = 6,
};

struct SignOutput {
  bool ours = false;
  OutputType type = OutputType::UNKNOWN;
  uint64_t value = 0;
  Bytes payload;
  std::vector<uint32_t> keypath;
  uint32_t script_config_index = 0;
};

struct PreviousTransactionInput {
  Bytes previous_output_hash;
  uint32_t previous_output_index = 0;
  Bytes signature_script;
  uint32_t sequence = 0;
};

struct PreviousTransactionInit {
  uint32_t version = 0;
  uint32_t input_count = 0;
  uint32_t output_count = 0;
  uint32_t locktime = 0;
};

struct PreviousTransactionOutput {
  uint64_t value = 0;
  Bytes public_key_script;
};

struct DeviceError {
  int code = 0;
  std::string message;
};

struct SignNext {
  enum class Type : uint32_t {
    INPUT = 0,
    OUTPUT = 1,
    DONE = 2,
    PREVIOUS_TRANSACTION_INIT = 3,
    PREVIOUS_TRANSACTION_INPUT = 4,
    PREVIOUS_TRANSACTION_OUTPUT = 5,
    HOST_NONCE = 6,
    PAYMENT_REQUEST = 7,
  };

  Type type = Type::INPUT;
  uint32_t index = 0;
  bool has_signature = false;
  Bytes signature;
  uint32_t previous_index = 0;
  Bytes signer_commitment;
};

struct SuccessResponse {};

struct DeviceInfoResponse {
  BitBoxDeviceInfo device;
};

struct PubResponse {
  std::string pub;
};

struct ListBackupsResponse {
  std::vector<BitBoxBackup> backups;
};

struct CheckBackupResponse {
  std::string id;
};

struct CheckSdCardResponse {
  bool inserted = false;
};

struct FingerprintResponse {
  Bytes fingerprint;
};

struct BitcoinSuccessResponse {};

struct RegistrationResponse {
  bool registered = false;
};

struct MessageSignatureResponse {
  Bytes signature;
};

struct SignerCommitmentResponse {
  Bytes commitment;
};

struct BitcoinResponse {
  using Value =
      std::variant<BitcoinSuccessResponse, RegistrationResponse, SignNext,
                   MessageSignatureResponse, SignerCommitmentResponse>;
  Value value;
};

using Response =
    std::variant<SuccessResponse, DeviceError, DeviceInfoResponse, PubResponse,
                 SignNext, ListBackupsResponse, CheckBackupResponse,
                 CheckSdCardResponse, FingerprintResponse, BitcoinResponse>;

Bytes EncodeDeviceInfoRequest();
Bytes EncodeRebootToBootloaderRequest();
Bytes EncodeSetDeviceNameRequest(const std::string& name);
Bytes EncodeSetPasswordRequest(std::span<const unsigned char> entropy);
Bytes EncodeChangePasswordRequest();
Bytes EncodeSetMnemonicPassphraseEnabledRequest(bool enabled);
Bytes EncodeResetRequest();
Bytes EncodeCreateBackupRequest(uint32_t timestamp, int32_t timezone_offset);
Bytes EncodeShowMnemonicRequest();
Bytes EncodeCheckSdCardRequest();
Bytes EncodeInsertSdCardRequest();
Bytes EncodeListBackupsRequest();
Bytes EncodeCheckBackupRequest(bool silent);
Bytes EncodeRestoreBackupRequest(const std::string& id, uint32_t timestamp,
                                 int32_t timezone_offset);
Bytes EncodeRestoreFromMnemonicRequest(uint32_t timestamp,
                                       int32_t timezone_offset);
Bytes EncodeFingerprintRequest();
Bytes EncodeXpubRequest(Coin coin, const std::vector<uint32_t>& keypath,
                        bool display);
Bytes EncodeAddressRequest(Coin coin, const std::vector<uint32_t>& keypath,
                           const ScriptConfig& script_config, bool display);
Bytes EncodeIsRegisteredRequest(Coin coin,
                                const ScriptConfig& script_config,
                                const std::vector<uint32_t>& account_keypath);
Bytes EncodeRegisterRequest(Coin coin, const ScriptConfig& script_config,
                            const std::vector<uint32_t>& account_keypath,
                            const std::string& name);
Bytes EncodeSignMessageRequest(Coin coin,
                               const ScriptConfigWithKeypath& script_config,
                               std::span<const unsigned char> message,
                               std::span<const unsigned char> commitment);
Bytes EncodeAntiKleptoSignatureRequest(
    std::span<const unsigned char> host_nonce);
Bytes EncodeSignInitRequest(
    Coin coin, const std::vector<ScriptConfigWithKeypath>& script_configs,
    uint32_t version, uint32_t input_count, uint32_t output_count,
    uint32_t locktime,
    const std::vector<ScriptConfigWithKeypath>& output_script_configs = {});
Bytes EncodeSignInputRequest(const SignInput& input);
Bytes EncodeSignOutputRequest(const SignOutput& output);
Bytes EncodePreviousTransactionInitRequest(uint32_t version,
                                           uint32_t input_count,
                                           uint32_t output_count,
                                           uint32_t locktime);
Bytes EncodePreviousTransactionInputRequest(
    const PreviousTransactionInput& input);
Bytes EncodePreviousTransactionOutputRequest(
    const PreviousTransactionOutput& output);

Response ParseResponse(std::span<const unsigned char> message,
                       const BitBoxDeviceInfo& base_device_info);

}  // namespace nunchuk::bitbox::proto

#endif  // NUNCHUK_BITBOX_PROTOBUF_H
