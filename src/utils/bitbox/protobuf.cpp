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

#include "utils/bitbox/protobuf.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string_view>
#include <tinyformat.h>
#include <util/strencodings.h>

#include "pb_decode.h"
#include "pb_encode.h"
#include "utils/bitbox/messages/hww.pb.h"

namespace nunchuk::bitbox::proto {
namespace {

using GeneratedRequest = shiftcrypto_bitbox02_Request;
using GeneratedResponse = shiftcrypto_bitbox02_Response;
using GeneratedBitcoinResponse = shiftcrypto_bitbox02_BTCResponse;
using GeneratedScriptConfig = shiftcrypto_bitbox02_BTCScriptConfig;
using GeneratedScriptConfigWithKeypath =
    shiftcrypto_bitbox02_BTCScriptConfigWithKeypath;

struct ByteView {
  const unsigned char* data = nullptr;
  size_t size = 0;
};

std::runtime_error ProtobufError(std::string_view operation,
                                 const char* detail) {
  return std::runtime_error(
      strprintf("BitBox protobuf %s failed: %s", std::string(operation),
                detail == nullptr ? "unknown error" : detail));
}

Bytes EncodeMessage(const pb_msgdesc_t* fields, const void* message) {
  pb_ostream_t sizing = PB_OSTREAM_SIZING;
  if (!pb_encode(&sizing, fields, message)) {
    throw ProtobufError("encoding", PB_GET_ERROR(&sizing));
  }
  if (sizing.bytes_written == 0) return {};

  Bytes result(sizing.bytes_written);
  pb_ostream_t stream = pb_ostream_from_buffer(result.data(), result.size());
  if (!pb_encode(&stream, fields, message)) {
    throw ProtobufError("encoding", PB_GET_ERROR(&stream));
  }
  return result;
}

template <typename Message>
Message DecodeMessage(std::span<const unsigned char> encoded,
                      const pb_msgdesc_t* fields) {
  Message result{};
  pb_istream_t stream = pb_istream_from_buffer(encoded.data(), encoded.size());
  if (!pb_decode(&stream, fields, &result)) {
    throw ProtobufError("decoding", PB_GET_ERROR(&stream));
  }
  return result;
}

template <typename Message>
Bytes EncodeNested(const Message& message, const pb_msgdesc_t* fields) {
  return EncodeMessage(fields, &message);
}

template <typename Field>
void SetBytes(Field& target, std::span<const unsigned char> value,
              std::string_view name) {
  if (value.size() > sizeof(target.bytes)) {
    throw std::invalid_argument(
        strprintf("BitBox %s is too large", std::string(name)));
  }
  target.size = static_cast<pb_size_t>(value.size());
  std::copy(value.begin(), value.end(), target.bytes);
}

template <typename Field>
Bytes GetBytes(const Field& source) {
  return Bytes(source.bytes, source.bytes + source.size);
}

template <size_t Size>
void SetString(char (&target)[Size], std::string_view value,
               std::string_view name) {
  if (value.size() >= Size) {
    throw std::invalid_argument(
        strprintf("BitBox %s is too large", std::string(name)));
  }
  std::copy(value.begin(), value.end(), target);
  target[value.size()] = '\0';
}

void ValidateDeviceName(std::string_view name) {
  if (name.empty() || name.size() > 63 || name.front() == ' ' ||
      name.back() == ' ' ||
      std::any_of(name.begin(), name.end(), [](unsigned char value) {
        return value < 0x20 || value > 0x7e;
      })) {
    throw std::invalid_argument(
        "BitBox device name must be 1-63 printable ASCII characters without "
        "leading or trailing spaces");
  }
}

void ValidateBackupId(std::string_view id) {
  if (id.size() != 64 ||
      !std::all_of(id.begin(), id.end(), [](unsigned char value) {
        return std::isxdigit(value) != 0;
      })) {
    throw std::invalid_argument(
        "BitBox backup ID must be 64 hexadecimal characters");
  }
}

template <size_t Size>
void SetKeypath(pb_size_t& count, uint32_t (&target)[Size],
                const std::vector<uint32_t>& keypath) {
  if (keypath.size() > Size) {
    throw std::invalid_argument("BitBox keypath is too deep");
  }
  count = static_cast<pb_size_t>(keypath.size());
  std::copy(keypath.begin(), keypath.end(), target);
}

shiftcrypto_bitbox02_BTCCoin ToGeneratedCoin(Coin coin) {
  switch (coin) {
    case Coin::BTC:
      return shiftcrypto_bitbox02_BTCCoin_BTC;
    case Coin::TBTC:
      return shiftcrypto_bitbox02_BTCCoin_TBTC;
    case Coin::RBTC:
      return shiftcrypto_bitbox02_BTCCoin_RBTC;
  }
  throw std::invalid_argument("Unsupported BitBox coin");
}

bool EncodeByteView(pb_ostream_t* stream, const pb_field_t* field,
                    void* const* arg) {
  const auto* value = static_cast<const ByteView*>(*arg);
  if (value == nullptr || value->size == 0) return true;
  return pb_encode_tag_for_field(stream, field) &&
         pb_encode_string(stream, value->data, value->size);
}

bool EncodeBytesValue(pb_ostream_t* stream, const pb_field_t* field,
                      void* const* arg) {
  const auto* value = static_cast<const Bytes*>(*arg);
  if (value == nullptr || value->empty()) return true;
  return pb_encode_tag_for_field(stream, field) &&
         pb_encode_string(stream, value->data(), value->size());
}

bool EncodeStringValue(pb_ostream_t* stream, const pb_field_t* field,
                       void* const* arg) {
  const auto* value = static_cast<const std::string*>(*arg);
  if (value == nullptr || value->empty()) return true;
  return pb_encode_tag_for_field(stream, field) &&
         pb_encode_string(
             stream, reinterpret_cast<const unsigned char*>(value->data()),
             value->size());
}

template <typename Value>
void SetCallback(pb_callback_t& callback,
                 bool (*encoder)(pb_ostream_t*, const pb_field_t*,
                                 void* const*),
                 const Value& value) {
  callback.funcs.encode = encoder;
  callback.arg = const_cast<Value*>(&value);
}

void ValidateXpub(const XPub& xpub) {
  if (xpub.parent_fingerprint.size() != 4 || xpub.chain_code.size() != 32 ||
      xpub.public_key.size() != 33) {
    throw std::invalid_argument("BitBox xpub has invalid component lengths");
  }
}

void ValidateScriptConfig(const ScriptConfig& script_config) {
  switch (script_config.kind) {
    case ScriptConfig::Kind::SIMPLE:
      if (script_config.simple_type < ScriptConfig::SimpleType::P2WPKH_P2SH ||
          script_config.simple_type > ScriptConfig::SimpleType::P2TR) {
        throw std::invalid_argument("BitBox simple script type is invalid");
      }
      return;
    case ScriptConfig::Kind::MULTISIG:
      if (script_config.xpubs.size() < 2 ||
          script_config.xpubs.size() > 15 || script_config.threshold == 0 ||
          script_config.threshold > script_config.xpubs.size() ||
          script_config.our_xpub_index >= script_config.xpubs.size() ||
          script_config.multisig_type < ScriptConfig::MultisigType::P2WSH ||
          script_config.multisig_type >
              ScriptConfig::MultisigType::P2WSH_P2SH) {
        throw std::invalid_argument("BitBox multisig configuration is invalid");
      }
      for (const auto& xpub : script_config.xpubs) ValidateXpub(xpub);
      return;
    case ScriptConfig::Kind::POLICY:
      if (script_config.policy.empty() || script_config.keys.empty()) {
        throw std::invalid_argument("BitBox wallet policy is empty");
      }
      for (const auto& key : script_config.keys) {
        if ((!key.root_fingerprint.empty() &&
             key.root_fingerprint.size() != 4) ||
            key.keypath.size() > 32) {
          throw std::invalid_argument("BitBox policy key origin is invalid");
        }
        ValidateXpub(key.xpub);
      }
      return;
  }
  throw std::invalid_argument("BitBox script configuration kind is invalid");
}

shiftcrypto_bitbox02_XPub MakeXpub(const XPub& source) {
  ValidateXpub(source);
  shiftcrypto_bitbox02_XPub result{};
  SetBytes(result.depth,
           std::span<const unsigned char>(&source.depth, size_t{1}),
           "xpub depth");
  SetBytes(result.parent_fingerprint, source.parent_fingerprint,
           "xpub parent fingerprint");
  result.child_num = source.child_number;
  SetBytes(result.chain_code, source.chain_code, "xpub chain code");
  SetBytes(result.public_key, source.public_key, "xpub public key");
  return result;
}

shiftcrypto_bitbox02_KeyOriginInfo MakeKeyOrigin(const KeyOrigin& source) {
  shiftcrypto_bitbox02_KeyOriginInfo result{};
  SetBytes(result.root_fingerprint, source.root_fingerprint,
           "policy root fingerprint");
  SetKeypath(result.keypath_count, result.keypath, source.keypath);
  result.has_xpub = true;
  result.xpub = MakeXpub(source.xpub);
  return result;
}

bool EncodeXpubs(pb_ostream_t* stream, const pb_field_t* field,
                 void* const* arg) {
  try {
    const auto* values = static_cast<const std::vector<XPub>*>(*arg);
    if (values == nullptr) return true;
    for (const auto& value : *values) {
      const auto encoded = MakeXpub(value);
      if (!pb_encode_tag_for_field(stream, field) ||
          !pb_encode_submessage(stream, shiftcrypto_bitbox02_XPub_fields,
                                &encoded)) {
        return false;
      }
    }
    return true;
  } catch (...) {
    return false;
  }
}

bool EncodeKeyOrigins(pb_ostream_t* stream, const pb_field_t* field,
                      void* const* arg) {
  try {
    const auto* values = static_cast<const std::vector<KeyOrigin>*>(*arg);
    if (values == nullptr) return true;
    for (const auto& value : *values) {
      const auto encoded = MakeKeyOrigin(value);
      if (!pb_encode_tag_for_field(stream, field) ||
          !pb_encode_submessage(
              stream, shiftcrypto_bitbox02_KeyOriginInfo_fields, &encoded)) {
        return false;
      }
    }
    return true;
  } catch (...) {
    return false;
  }
}

GeneratedScriptConfig MakeScriptConfig(const ScriptConfig& source) {
  ValidateScriptConfig(source);
  GeneratedScriptConfig result{};
  switch (source.kind) {
    case ScriptConfig::Kind::SIMPLE:
      result.which_config = shiftcrypto_bitbox02_BTCScriptConfig_simple_type_tag;
      result.config.simple_type =
          static_cast<shiftcrypto_bitbox02_BTCScriptConfig_SimpleType>(
              source.simple_type);
      break;
    case ScriptConfig::Kind::MULTISIG: {
      result.which_config = shiftcrypto_bitbox02_BTCScriptConfig_multisig_tag;
      auto& multisig = result.config.multisig;
      multisig.threshold = source.threshold;
      SetCallback(multisig.xpubs, EncodeXpubs, source.xpubs);
      multisig.our_xpub_index = source.our_xpub_index;
      multisig.script_type =
          static_cast<shiftcrypto_bitbox02_BTCScriptConfig_Multisig_ScriptType>(
              source.multisig_type);
      break;
    }
    case ScriptConfig::Kind::POLICY: {
      result.which_config = shiftcrypto_bitbox02_BTCScriptConfig_policy_tag;
      auto& policy = result.config.policy;
      SetCallback(policy.policy, EncodeStringValue, source.policy);
      SetCallback(policy.keys, EncodeKeyOrigins, source.keys);
      break;
    }
  }
  return result;
}

GeneratedScriptConfigWithKeypath MakeScriptConfigWithKeypath(
    const ScriptConfigWithKeypath& source) {
  GeneratedScriptConfigWithKeypath result{};
  result.has_script_config = true;
  result.script_config = MakeScriptConfig(source.script_config);
  SetKeypath(result.keypath_count, result.keypath, source.keypath);
  return result;
}

bool EncodeScriptConfigs(pb_ostream_t* stream, const pb_field_t* field,
                         void* const* arg) {
  try {
    const auto* values =
        static_cast<const std::vector<ScriptConfigWithKeypath>*>(*arg);
    if (values == nullptr) return true;
    for (const auto& value : *values) {
      const auto encoded = MakeScriptConfigWithKeypath(value);
      if (!pb_encode_tag_for_field(stream, field) ||
          !pb_encode_submessage(
              stream,
              shiftcrypto_bitbox02_BTCScriptConfigWithKeypath_fields,
              &encoded)) {
        return false;
      }
    }
    return true;
  } catch (...) {
    return false;
  }
}

shiftcrypto_bitbox02_BTCScriptConfigRegistration MakeRegistration(
    Coin coin, const ScriptConfig& script_config,
    const std::vector<uint32_t>& account_keypath) {
  shiftcrypto_bitbox02_BTCScriptConfigRegistration result{};
  result.coin = ToGeneratedCoin(coin);
  result.has_script_config = true;
  result.script_config = MakeScriptConfig(script_config);
  SetKeypath(result.keypath_count, result.keypath, account_keypath);
  return result;
}

}  // namespace

Bytes EncodeDeviceInfoRequest() {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_device_info_tag;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeRebootToBootloaderRequest() {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_reboot_tag;
  request.request.reboot.purpose =
      shiftcrypto_bitbox02_RebootRequest_Purpose_UPGRADE;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeSetDeviceNameRequest(const std::string& name) {
  ValidateDeviceName(name);
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_device_name_tag;
  SetCallback(request.request.device_name.name, EncodeStringValue, name);
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeSetPasswordRequest(std::span<const unsigned char> entropy) {
  if (entropy.size() != 16 && entropy.size() != 32) {
    throw std::invalid_argument("BitBox seed entropy must be 16 or 32 bytes");
  }
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_set_password_tag;
  const ByteView entropy_view{entropy.data(), entropy.size()};
  SetCallback(request.request.set_password.entropy, EncodeByteView,
              entropy_view);
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeChangePasswordRequest() {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_change_password_tag;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeSetMnemonicPassphraseEnabledRequest(bool enabled) {
  GeneratedRequest request{};
  request.which_request =
      shiftcrypto_bitbox02_Request_set_mnemonic_passphrase_enabled_tag;
  request.request.set_mnemonic_passphrase_enabled.enabled = enabled;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeResetRequest() {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_reset_tag;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeCreateBackupRequest(uint32_t timestamp,
                                int32_t timezone_offset) {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_create_backup_tag;
  request.request.create_backup.timestamp = timestamp;
  request.request.create_backup.timezone_offset = timezone_offset;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeShowMnemonicRequest() {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_show_mnemonic_tag;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeCheckSdCardRequest() {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_check_sdcard_tag;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeInsertSdCardRequest() {
  GeneratedRequest request{};
  request.which_request =
      shiftcrypto_bitbox02_Request_insert_remove_sdcard_tag;
  request.request.insert_remove_sdcard.action =
      shiftcrypto_bitbox02_InsertRemoveSDCardRequest_SDCardAction_INSERT_CARD;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeListBackupsRequest() {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_list_backups_tag;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeCheckBackupRequest(bool silent) {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_check_backup_tag;
  request.request.check_backup.silent = silent;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeRestoreBackupRequest(const std::string& id, uint32_t timestamp,
                                 int32_t timezone_offset) {
  ValidateBackupId(id);
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_restore_backup_tag;
  SetCallback(request.request.restore_backup.id, EncodeStringValue, id);
  request.request.restore_backup.timestamp = timestamp;
  request.request.restore_backup.timezone_offset = timezone_offset;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeRestoreFromMnemonicRequest(uint32_t timestamp,
                                       int32_t timezone_offset) {
  GeneratedRequest request{};
  request.which_request =
      shiftcrypto_bitbox02_Request_restore_from_mnemonic_tag;
  request.request.restore_from_mnemonic.timestamp = timestamp;
  request.request.restore_from_mnemonic.timezone_offset = timezone_offset;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeFingerprintRequest() {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_fingerprint_tag;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeXpubRequest(Coin coin, const std::vector<uint32_t>& keypath,
                        bool display) {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_btc_pub_tag;
  auto& pub = request.request.btc_pub;
  pub.coin = ToGeneratedCoin(coin);
  SetKeypath(pub.keypath_count, pub.keypath, keypath);
  pub.which_output = shiftcrypto_bitbox02_BTCPubRequest_xpub_type_tag;
  pub.output.xpub_type =
      coin == Coin::BTC ? shiftcrypto_bitbox02_BTCPubRequest_XPubType_XPUB
                        : shiftcrypto_bitbox02_BTCPubRequest_XPubType_TPUB;
  pub.display = display;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeAddressRequest(Coin coin, const std::vector<uint32_t>& keypath,
                           const ScriptConfig& script_config, bool display) {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_btc_pub_tag;
  auto& pub = request.request.btc_pub;
  pub.coin = ToGeneratedCoin(coin);
  SetKeypath(pub.keypath_count, pub.keypath, keypath);
  pub.which_output = shiftcrypto_bitbox02_BTCPubRequest_script_config_tag;
  pub.output.script_config = MakeScriptConfig(script_config);
  pub.display = display;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeIsRegisteredRequest(Coin coin,
                                const ScriptConfig& script_config,
                                const std::vector<uint32_t>& account_keypath) {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_btc_tag;
  auto& bitcoin = request.request.btc;
  bitcoin.which_request =
      shiftcrypto_bitbox02_BTCRequest_is_script_config_registered_tag;
  auto& query = bitcoin.request.is_script_config_registered;
  query.has_registration = true;
  query.registration = MakeRegistration(coin, script_config, account_keypath);
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeRegisterRequest(Coin coin, const ScriptConfig& script_config,
                            const std::vector<uint32_t>& account_keypath,
                            const std::string& name) {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_btc_tag;
  auto& bitcoin = request.request.btc;
  bitcoin.which_request =
      shiftcrypto_bitbox02_BTCRequest_register_script_config_tag;
  auto& registration = bitcoin.request.register_script_config;
  registration.has_registration = true;
  registration.registration =
      MakeRegistration(coin, script_config, account_keypath);
  SetString(registration.name, name, "wallet name");
  registration.xpub_type =
      shiftcrypto_bitbox02_BTCRegisterScriptConfigRequest_XPubType_AUTO_XPUB_TPUB;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeSignMessageRequest(Coin coin,
                               const ScriptConfigWithKeypath& script_config,
                               std::span<const unsigned char> message,
                               std::span<const unsigned char> commitment) {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_btc_tag;
  auto& bitcoin = request.request.btc;
  bitcoin.which_request = shiftcrypto_bitbox02_BTCRequest_sign_message_tag;
  auto& sign = bitcoin.request.sign_message;
  sign.coin = ToGeneratedCoin(coin);
  sign.has_script_config = true;
  sign.script_config = MakeScriptConfigWithKeypath(script_config);
  const ByteView message_view{message.data(), message.size()};
  SetCallback(sign.msg, EncodeByteView, message_view);
  if (!commitment.empty()) {
    if (commitment.size() != 32) {
      throw std::invalid_argument(
          "BitBox anti-klepto host commitment must be 32 bytes");
    }
    sign.has_host_nonce_commitment = true;
    SetBytes(sign.host_nonce_commitment.commitment, commitment,
             "anti-klepto host commitment");
  }
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeAntiKleptoSignatureRequest(
    std::span<const unsigned char> host_nonce) {
  if (host_nonce.size() != 32) {
    throw std::invalid_argument("BitBox anti-klepto host nonce must be 32 bytes");
  }
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_btc_tag;
  auto& bitcoin = request.request.btc;
  bitcoin.which_request =
      shiftcrypto_bitbox02_BTCRequest_antiklepto_signature_tag;
  SetBytes(bitcoin.request.antiklepto_signature.host_nonce, host_nonce,
           "anti-klepto host nonce");
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeSignInitRequest(
    Coin coin, const std::vector<ScriptConfigWithKeypath>& script_configs,
    uint32_t version, uint32_t input_count, uint32_t output_count,
    uint32_t locktime,
    const std::vector<ScriptConfigWithKeypath>& output_script_configs) {
  for (const auto& config : script_configs) {
    (void)MakeScriptConfigWithKeypath(config);
  }
  for (const auto& config : output_script_configs) {
    (void)MakeScriptConfigWithKeypath(config);
  }
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_btc_sign_init_tag;
  auto& sign = request.request.btc_sign_init;
  sign.coin = ToGeneratedCoin(coin);
  SetCallback(sign.script_configs, EncodeScriptConfigs, script_configs);
  sign.version = version;
  sign.num_inputs = input_count;
  sign.num_outputs = output_count;
  sign.locktime = locktime;
  sign.format_unit = shiftcrypto_bitbox02_BTCSignInitRequest_FormatUnit_SAT;
  SetCallback(sign.output_script_configs, EncodeScriptConfigs,
              output_script_configs);
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeSignInputRequest(const SignInput& input) {
  if (input.previous_output_hash.size() != 32) {
    throw std::invalid_argument("BitBox previous output hash must be 32 bytes");
  }
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_btc_sign_input_tag;
  auto& sign = request.request.btc_sign_input;
  SetBytes(sign.prevOutHash, input.previous_output_hash,
           "previous output hash");
  sign.prevOutIndex = input.previous_output_index;
  sign.prevOutValue = input.previous_output_value;
  sign.sequence = input.sequence;
  SetKeypath(sign.keypath_count, sign.keypath, input.keypath);
  sign.script_config_index = input.script_config_index;
  if (!input.host_nonce_commitment.empty()) {
    if (input.host_nonce_commitment.size() != 32) {
      throw std::invalid_argument(
          "BitBox anti-klepto host commitment must be 32 bytes");
    }
    sign.has_host_nonce_commitment = true;
    SetBytes(sign.host_nonce_commitment.commitment,
             input.host_nonce_commitment, "anti-klepto host commitment");
  }
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodeSignOutputRequest(const SignOutput& output) {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_btc_sign_output_tag;
  auto& sign = request.request.btc_sign_output;
  sign.ours = output.ours;
  sign.type = static_cast<shiftcrypto_bitbox02_BTCOutputType>(output.type);
  sign.value = output.value;
  SetCallback(sign.payload, EncodeBytesValue, output.payload);
  SetKeypath(sign.keypath_count, sign.keypath, output.keypath);
  sign.script_config_index = output.script_config_index;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodePreviousTransactionInitRequest(uint32_t version,
                                           uint32_t input_count,
                                           uint32_t output_count,
                                           uint32_t locktime) {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_btc_tag;
  auto& bitcoin = request.request.btc;
  bitcoin.which_request = shiftcrypto_bitbox02_BTCRequest_prevtx_init_tag;
  auto& previous = bitcoin.request.prevtx_init;
  previous.version = version;
  previous.num_inputs = input_count;
  previous.num_outputs = output_count;
  previous.locktime = locktime;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodePreviousTransactionInputRequest(
    const PreviousTransactionInput& input) {
  if (input.previous_output_hash.size() != 32) {
    throw std::invalid_argument("BitBox previous output hash must be 32 bytes");
  }
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_btc_tag;
  auto& bitcoin = request.request.btc;
  bitcoin.which_request = shiftcrypto_bitbox02_BTCRequest_prevtx_input_tag;
  auto& previous = bitcoin.request.prevtx_input;
  SetBytes(previous.prev_out_hash, input.previous_output_hash,
           "previous output hash");
  previous.prev_out_index = input.previous_output_index;
  SetCallback(previous.signature_script, EncodeBytesValue,
              input.signature_script);
  previous.sequence = input.sequence;
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

Bytes EncodePreviousTransactionOutputRequest(
    const PreviousTransactionOutput& output) {
  GeneratedRequest request{};
  request.which_request = shiftcrypto_bitbox02_Request_btc_tag;
  auto& bitcoin = request.request.btc;
  bitcoin.which_request = shiftcrypto_bitbox02_BTCRequest_prevtx_output_tag;
  auto& previous = bitcoin.request.prevtx_output;
  previous.value = output.value;
  SetCallback(previous.pubkey_script, EncodeBytesValue,
              output.public_key_script);
  return EncodeNested(request, shiftcrypto_bitbox02_Request_fields);
}

namespace {

BitBoxDeviceInfo MakeDeviceInfo(
    const shiftcrypto_bitbox02_DeviceInfoResponse& decoded,
    const BitBoxDeviceInfo& base) {
  BitBoxDeviceInfo result = base;
  result.name = decoded.name;
  result.initialized = decoded.initialized;
  result.firmware_version = decoded.version;
  result.mnemonic_passphrase_enabled = decoded.mnemonic_passphrase_enabled;
  result.securechip_model = decoded.securechip_model;
  result.password_stretching_algo = decoded.password_stretching_algo;
  if (decoded.has_bluetooth) {
    result.bluetooth_firmware_hash = HexStr(std::span<const unsigned char>(
        decoded.bluetooth.firmware_hash.bytes,
        decoded.bluetooth.firmware_hash.size));
    result.bluetooth_firmware_version = decoded.bluetooth.firmware_version;
    result.bluetooth_enabled = decoded.bluetooth.enabled;
  }
  return result;
}

SignNext MakeSignNext(
    const shiftcrypto_bitbox02_BTCSignNextResponse& decoded) {
  if (decoded.type < shiftcrypto_bitbox02_BTCSignNextResponse_Type_INPUT ||
      decoded.type >
          shiftcrypto_bitbox02_BTCSignNextResponse_Type_PAYMENT_REQUEST) {
    throw std::runtime_error("BitBox sign-next type is invalid");
  }
  SignNext result;
  result.type = static_cast<SignNext::Type>(decoded.type);
  result.index = decoded.index;
  result.has_signature = decoded.has_signature;
  result.signature = GetBytes(decoded.signature);
  result.previous_index = decoded.prev_index;
  if (decoded.has_anti_klepto_signer_commitment) {
    result.signer_commitment =
        GetBytes(decoded.anti_klepto_signer_commitment.commitment);
  }
  return result;
}

BitcoinResponse MakeBitcoinResponse(const GeneratedBitcoinResponse& response) {
  switch (response.which_response) {
    case shiftcrypto_bitbox02_BTCResponse_success_tag:
      return {BitcoinSuccessResponse{}};
    case shiftcrypto_bitbox02_BTCResponse_is_script_config_registered_tag:
      return {RegistrationResponse{
          response.response.is_script_config_registered.is_registered}};
    case shiftcrypto_bitbox02_BTCResponse_sign_next_tag:
      return {MakeSignNext(response.response.sign_next)};
    case shiftcrypto_bitbox02_BTCResponse_sign_message_tag:
      return {MessageSignatureResponse{
          GetBytes(response.response.sign_message.signature)}};
    case shiftcrypto_bitbox02_BTCResponse_antiklepto_signer_commitment_tag:
      return {SignerCommitmentResponse{GetBytes(
          response.response.antiklepto_signer_commitment.commitment)}};
    case 0:
      throw std::runtime_error(
          "BitBox Bitcoin protobuf response has no variant");
    default:
      throw std::runtime_error(strprintf(
          "BitBox Bitcoin protobuf response variant %u is unsupported",
          response.which_response));
  }
}

}  // namespace

Response ParseResponse(std::span<const unsigned char> message,
                       const BitBoxDeviceInfo& base_device_info) {
  const auto response = DecodeMessage<GeneratedResponse>(
      message, shiftcrypto_bitbox02_Response_fields);
  switch (response.which_response) {
    case shiftcrypto_bitbox02_Response_success_tag:
      return SuccessResponse{};
    case shiftcrypto_bitbox02_Response_error_tag: {
      DeviceError error{response.response.error.code,
                        response.response.error.message};
      if (error.message.empty()) {
        error.message = "BitBox device returned an error";
      }
      return error;
    }
    case shiftcrypto_bitbox02_Response_device_info_tag:
      return DeviceInfoResponse{
          MakeDeviceInfo(response.response.device_info, base_device_info)};
    case shiftcrypto_bitbox02_Response_pub_tag:
      return PubResponse{response.response.pub.pub};
    case shiftcrypto_bitbox02_Response_btc_sign_next_tag:
      return MakeSignNext(response.response.btc_sign_next);
    case shiftcrypto_bitbox02_Response_list_backups_tag: {
      ListBackupsResponse result;
      const auto& list = response.response.list_backups;
      result.backups.reserve(list.info_count);
      for (pb_size_t index = 0; index < list.info_count; ++index) {
        const auto& info = list.info[index];
        result.backups.push_back({info.id, info.name, info.timestamp});
      }
      return result;
    }
    case shiftcrypto_bitbox02_Response_check_backup_tag:
      return CheckBackupResponse{response.response.check_backup.id};
    case shiftcrypto_bitbox02_Response_check_sdcard_tag:
      return CheckSdCardResponse{response.response.check_sdcard.inserted};
    case shiftcrypto_bitbox02_Response_fingerprint_tag:
      return FingerprintResponse{
          GetBytes(response.response.fingerprint.fingerprint)};
    case shiftcrypto_bitbox02_Response_btc_tag:
      return MakeBitcoinResponse(response.response.btc);
    case 0:
      throw std::runtime_error("BitBox protobuf response has no variant");
    default:
      throw std::runtime_error(
          strprintf("BitBox protobuf response variant %u is unsupported",
                    response.which_response));
  }
}

}  // namespace nunchuk::bitbox::proto
