/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */
#include "utils/onekey/protobuf.hpp"

#include <algorithm>
#include <stdexcept>
#include <key_io.h>
#include <support/cleanse.h>
#include <util/strencodings.h>
#include "pb_decode.h"
#include "pb_encode.h"
#include "utils/onekey/messages/onekey.pb.h"
#include "utils/onekey/wire_framer.hpp"

namespace nunchuk::onekey::proto {
namespace {
using json = nlohmann::json;
using Bytes = std::vector<unsigned char>;

Bytes EncodeMessage(const pb_msgdesc_t* fields, const void* message) {
  size_t size = 0;
  if (!pb_get_encoded_size(&size, fields, message) ||
      size > WireFramer::MAX_MESSAGE_SIZE) {
    throw std::invalid_argument("Could not size OneKey protobuf message");
  }
  Bytes result(size);
  auto stream = pb_ostream_from_buffer(result.data(), result.size());
  if (!pb_encode(&stream, fields, message)) {
    throw std::runtime_error(std::string("OneKey protobuf encoding: ") +
                             PB_GET_ERROR(&stream));
  }
  return result;
}

template <typename T>
T DecodeMessage(std::span<const unsigned char> data,
                const pb_msgdesc_t* fields) {
  T result{};
  auto stream = pb_istream_from_buffer(data.data(), data.size());
  if (!pb_decode(&stream, fields, &result)) {
    throw std::runtime_error(std::string("OneKey protobuf decoding: ") +
                             PB_GET_ERROR(&stream));
  }
  return result;
}

template <size_t N>
void SetString(char (&field)[N], const std::string& value) {
  if (value.size() >= N || value.find('\0') != std::string::npos) {
    throw std::invalid_argument("Invalid OneKey protobuf string");
  }
  std::copy(value.begin(), value.end(), field);
}

bool IsLegacyV2ProtocolInfo(std::span<const unsigned char> data) {
  auto stream = pb_istream_from_buffer(data.data(), data.size());
  bool has_version = false;
  while (stream.bytes_left) {
    pb_wire_type_t wire_type;
    uint32_t tag;
    bool eof;
    if (!pb_decode_tag(&stream, &wire_type, &tag, &eof)) return false;
    // Distinguish the two layouts by wire types, never by a decode failure.
    if (tag == 1 || tag == 2) {
      if (wire_type != PB_WT_VARINT) return false;
      if (tag == 1) has_version = true;
    } else if (tag != 3 || wire_type != PB_WT_STRING) {
      return false;
    }
    if (!pb_skip_field(&stream, wire_type)) return false;
  }
  return has_version;
}

template <typename T>
void SetBytes(T& field, const std::string& hex) {
  if ((!hex.empty() && !IsHex(hex)) || hex.size() / 2 > sizeof(field.bytes)) {
    throw std::invalid_argument("Invalid OneKey protobuf bytes");
  }
  const auto bytes = ParseHex(hex);
  field.size = bytes.size();
  std::copy(bytes.begin(), bytes.end(), field.bytes);
}

template <typename T>
std::string GetBytes(const T& field) {
  return HexStr(std::span(field.bytes, field.size));
}

template <typename T>
void SetPath(T& message, const json& data) {
  if (!data.contains("address_n")) return;
  const auto& path = data.at("address_n");
  if (!path.is_array() || path.size() > 10) {
    throw std::invalid_argument("OneKey derivation path is too deep");
  }
  // OneKey's V1 schemas use unpacked repeated integers. The shared nanopb
  // encoder otherwise packs scalar arrays, so encode paths explicitly.
  message.address_n.arg = const_cast<json*>(&path);
  message.address_n.funcs.encode =
      [](pb_ostream_t* stream, const pb_field_t* field, void* const* arg) {
        for (const auto& value : *static_cast<const json*>(*arg)) {
          if (!pb_encode_tag_for_field(stream, field) ||
              !pb_encode_varint(stream, value.get<uint32_t>()))
            return false;
        }
        return true;
      };
}

bool EncodeHex(pb_ostream_t* stream, const pb_field_t* field,
               void* const* arg) {
  const auto& hex = *static_cast<const std::string*>(*arg);
  if (!hex.empty() && !IsHex(hex)) return false;
  const auto bytes = ParseHex(hex);
  return pb_encode_tag_for_field(stream, field) &&
         pb_encode_string(stream, bytes.data(), bytes.size());
}

void SetCallback(pb_callback_t& field, const json& data, const char* name) {
  if (!data.contains(name)) return;
  field.funcs.encode = EncodeHex;
  field.arg =
      const_cast<std::string*>(&data.at(name).get_ref<const std::string&>());
}

void SetNode(nunchuk_onekey_HDNode& node, const json& data) {
  if (data.is_string()) {
    const auto xpub = DecodeExtPubKey(data.get<std::string>());
    if (!xpub.pubkey.IsFullyValid())
      throw std::invalid_argument("Invalid OneKey xpub");
    node.depth = xpub.nDepth;
    node.fingerprint = 0;
    for (auto byte : xpub.vchFingerprint)
      node.fingerprint = (node.fingerprint << 8) | byte;
    node.child_num = xpub.nChild;
    SetBytes(node.chain_code, HexStr(xpub.chaincode));
    SetBytes(node.public_key, HexStr(xpub.pubkey));
  } else {
    node.depth = data.at("depth");
    node.fingerprint = data.at("fingerprint");
    node.child_num = data.at("child_num");
    SetBytes(node.chain_code, data.at("chain_code"));
    SetBytes(node.public_key, data.at("public_key"));
  }
}

template <typename T>
void SetMultisig(T& message, const json& data) {
  if (!data.contains("multisig")) return;
  const auto& multisig = data.at("multisig");
  const auto& pubkeys = multisig.at("pubkeys");
  auto& target = message.multisig;
  target.m = multisig.at("m");
  if (pubkeys.empty() || pubkeys.size() > std::size(target.pubkeys) ||
      target.m == 0 || target.m > pubkeys.size()) {
    throw std::invalid_argument("Invalid OneKey multisig policy");
  }
  message.has_multisig = true;
  target.pubkeys_count = pubkeys.size();
  for (size_t i = 0; i < pubkeys.size(); ++i) {
    SetNode(target.pubkeys[i].node, pubkeys[i].at("node"));
    SetPath(target.pubkeys[i], pubkeys[i]);
  }
}

uint32_t ScriptType(const json& data, bool output = false) {
  const auto value =
      data.value("script_type", output ? "PAYTOADDRESS" : "SPENDADDRESS");
  const std::vector<std::string> names =
      output ? std::vector<std::string>{"PAYTOADDRESS",  "PAYTOSCRIPTHASH",
                                        "PAYTOMULTISIG", "PAYTOOPRETURN",
                                        "PAYTOWITNESS",  "PAYTOP2SHWITNESS",
                                        "PAYTOTAPROOT"}
             : std::vector<std::string>{"SPENDADDRESS",     "SPENDMULTISIG",
                                        "EXTERNAL",         "SPENDWITNESS",
                                        "SPENDP2SHWITNESS", "SPENDTAPROOT"};
  const auto it = std::find(names.begin(), names.end(), value);
  if (it == names.end())
    throw std::invalid_argument("Invalid OneKey script type");
  return std::distance(names.begin(), it);
}

Bytes EncodeAck(const json& data) {
  nunchuk_onekey_TxAck message{};
  message.has_tx = true;
  auto& tx = message.tx;
  if (data.contains("version")) {
    tx.has_version = true;
    tx.version = data.at("version");
  }
  if (data.contains("lock_time")) {
    tx.has_lock_time = true;
    tx.lock_time = data.at("lock_time");
  }
  if (data.contains("inputs_cnt")) {
    tx.has_inputs_cnt = true;
    tx.inputs_cnt = data.at("inputs_cnt");
  }
  if (data.contains("outputs_cnt")) {
    tx.has_outputs_cnt = true;
    tx.outputs_cnt = data.at("outputs_cnt");
  }
  if (data.contains("input")) {
    const auto& src = data.at("input");
    auto& input = tx.inputs[0];
    tx.inputs_count = 1;
    SetPath(input, src);
    SetBytes(input.prev_hash, src.at("prev_hash"));
    input.prev_index = src.at("prev_index");
    SetCallback(input.script_sig, src, "script_sig");
    input.has_sequence = true;
    input.sequence = src.value("sequence", uint32_t{0xffffffff});
    input.has_script_type = true;
    input.script_type = ScriptType(src);
    if (src.contains("amount")) {
      input.has_amount = true;
      input.amount = src.at("amount");
    }
    SetMultisig(input, src);
  }
  if (data.contains("output")) {
    const auto& src = data.at("output");
    auto& output = tx.outputs[0];
    tx.outputs_count = 1;
    if (src.contains("address")) {
      output.has_address = true;
      SetString(output.address, src.at("address"));
    }
    SetPath(output, src);
    output.amount = src.at("amount");
    output.has_script_type = true;
    output.script_type = ScriptType(src, true);
    SetMultisig(output, src);
    SetCallback(output.op_return_data, src, "op_return_data");
  }
  if (data.contains("bin_output")) {
    const auto& src = data.at("bin_output");
    tx.bin_outputs_count = 1;
    tx.bin_outputs[0].amount = src.at("amount");
    SetCallback(tx.bin_outputs[0].script_pubkey, src, "script_pubkey");
  }
  return EncodeMessage(nunchuk_onekey_TxAck_fields, &message);
}

}  // namespace

Bytes Encode(uint16_t type, const json& data) {
  switch (type) {
    case INITIALIZE:
    case GET_FEATURES:
    case CANCEL:
    case BUTTON_ACK:
    case PIN_ON_DEVICE:
    case V2_DEVICE_STATUS_GET:
      return {};
    case PIN_MATRIX_ACK: {
      nunchuk_onekey_PinMatrixAck message{};
      SetString(message.pin, data.at("pin"));
      auto result = EncodeMessage(nunchuk_onekey_PinMatrixAck_fields, &message);
      memory_cleanse(&message, sizeof(message));
      return result;
    }
    case PASSPHRASE_ACK: {
      nunchuk_onekey_PassphraseAck message{};
      message.has_on_device = true;
      message.on_device = data.value("on_device", false);
      message.has_on_device_attach_pin = data.contains("on_device_attach_pin");
      message.on_device_attach_pin = data.value("on_device_attach_pin", false);
      if (data.contains("passphrase")) {
        message.has_passphrase = true;
        SetString(message.passphrase, data.at("passphrase"));
      }
      auto result =
          EncodeMessage(nunchuk_onekey_PassphraseAck_fields, &message);
      memory_cleanse(&message, sizeof(message));
      return result;
    }
    case V2_PING: {
      nunchuk_onekey_V2Ping message{};
      message.has_message = true;
      SetString(message.message, data.at("message"));
      return EncodeMessage(nunchuk_onekey_V2Ping_fields, &message);
    }
    case V2_PROTOCOL_INFO_REQUEST: {
      nunchuk_onekey_V2ProtocolInfoRequest message{};
      message.has_eventless_wallet_session = message.eventless_wallet_session =
          true;
      return EncodeMessage(nunchuk_onekey_V2ProtocolInfoRequest_fields,
                           &message);
    }
    case V2_DEVICE_INFO_GET: {
      nunchuk_onekey_V2DeviceInfoGet message{};
      message.has_targets = message.has_types = true;
      message.targets.has_hw = message.targets.hw = true;
      message.targets.has_main_mcu = message.targets.main_mcu = true;
      message.types.has_version = message.types.version = true;
      message.types.has_specific = message.types.specific = true;
      return EncodeMessage(nunchuk_onekey_V2DeviceInfoGet_fields, &message);
    }
    case V2_SESSION_GET: {
      nunchuk_onekey_V2SessionGet message{};
      if (data.contains("session_id")) {
        message.has_session_id = message.has_btc_test_address = true;
        SetBytes(message.session_id, data.at("session_id"));
        SetString(message.btc_test_address, data.at("btc_test_address"));
      }
      auto result = EncodeMessage(nunchuk_onekey_V2SessionGet_fields, &message);
      memory_cleanse(&message, sizeof(message));
      return result;
    }
    case V2_SESSION_ASK_PIN: {
      nunchuk_onekey_V2SessionAskPin message{};
      message.has_type = true;
      message.type = data.at("type");
      return EncodeMessage(nunchuk_onekey_V2SessionAskPin_fields, &message);
    }
    case V2_SESSION_ASK_PASSPHRASE: {
      nunchuk_onekey_V2SessionAskPassphrase message{};
      message.on_device = data.at("on_device");
      if (data.contains("passphrase")) {
        message.has_passphrase = true;
        SetString(message.passphrase, data.at("passphrase"));
      }
      // Standard Bitcoin seed domain, unpacked as specified by the V2 schema.
      message.seed_domains.funcs.encode =
          [](pb_ostream_t* stream, const pb_field_t* field, void* const*) {
            return pb_encode_tag_for_field(stream, field) &&
                   pb_encode_varint(stream, 1);
          };
      auto result =
          EncodeMessage(nunchuk_onekey_V2SessionAskPassphrase_fields, &message);
      memory_cleanse(&message, sizeof(message));
      return result;
    }
    case GET_PUBLIC_KEY: {
      nunchuk_onekey_GetPublicKey message{};
      SetPath(message, data);
      message.has_show_display = message.has_coin_name = true;
      message.show_display = data.value("show_display", false);
      SetString(message.coin_name, data.at("coin_name"));
      message.has_ignore_xpub_magic = message.ignore_xpub_magic = true;
      return EncodeMessage(nunchuk_onekey_GetPublicKey_fields, &message);
    }
    case GET_ADDRESS: {
      nunchuk_onekey_GetAddress message{};
      SetPath(message, data);
      SetMultisig(message, data);
      message.has_coin_name = message.has_show_display =
          message.has_script_type = true;
      SetString(message.coin_name, data.at("coin_name"));
      message.show_display = data.value("show_display", true);
      message.script_type = ScriptType(data);
      return EncodeMessage(nunchuk_onekey_GetAddress_fields, &message);
    }
    case SIGN_MESSAGE: {
      nunchuk_onekey_SignMessage message{};
      SetPath(message, data);
      SetCallback(message.message, data, "message");
      message.has_coin_name = message.has_no_script_type = true;
      message.no_script_type = true;
      SetString(message.coin_name, data.at("coin_name"));
      return EncodeMessage(nunchuk_onekey_SignMessage_fields, &message);
    }
    case SIGN_TX: {
      nunchuk_onekey_SignTx message{};
      message.inputs_count = data.at("inputs").size();
      message.outputs_count = data.at("outputs").size();
      message.has_coin_name = message.has_version = message.has_lock_time =
          message.has_serialize = true;
      SetString(message.coin_name, data.at("coin_name"));
      message.version = data.at("version");
      message.lock_time = data.at("locktime");
      message.serialize = false;
      return EncodeMessage(nunchuk_onekey_SignTx_fields, &message);
    }
    case TX_ACK:
      return EncodeAck(data);
    case SIGN_PSBT: {
      nunchuk_onekey_SignPsbt message{};
      SetCallback(message.psbt, data, "psbt");
      message.has_coin_name = true;
      SetString(message.coin_name, data.at("coin_name"));
      return EncodeMessage(nunchuk_onekey_SignPsbt_fields, &message);
    }
    default:
      throw std::invalid_argument("Unsupported OneKey request type");
  }
}

json Decode(uint16_t type, std::span<const unsigned char> data) {
  switch (type) {
    case V2_SUCCESS: {
      const auto m = DecodeMessage<nunchuk_onekey_V2Success>(
          data, nunchuk_onekey_V2Success_fields);
      return {{"message", m.message}};
    }
    case V2_FAILURE: {
      const auto m = DecodeMessage<nunchuk_onekey_V2Failure>(
          data, nunchuk_onekey_V2Failure_fields);
      return {{"code", m.code}, {"subcode", m.subcode}, {"message", m.message}};
    }
    case V2_PROTOCOL_INFO: {
      if (IsLegacyV2ProtocolInfo(data)) {
        const auto m = DecodeMessage<nunchuk_onekey_LegacyV2ProtocolInfo>(
            data, nunchuk_onekey_LegacyV2ProtocolInfo_fields);
        return {{"version", m.version},
                {"legacy", true},
                {"supported_messages",
                 std::vector<uint32_t>(
                     m.supported_messages,
                     m.supported_messages + m.supported_messages_count)}};
      }
      const auto m = DecodeMessage<nunchuk_onekey_V2ProtocolInfo>(
          data, nunchuk_onekey_V2ProtocolInfo_fields);
      return {{"version", m.version},
              {"legacy", false},
              {"supported_messages",
               std::vector<uint32_t>(
                   m.supported_messages,
                   m.supported_messages + m.supported_messages_count)}};
    }
    case V2_DEVICE_INFO: {
      const auto m = DecodeMessage<nunchuk_onekey_V2DeviceInfo>(
          data, nunchuk_onekey_V2DeviceInfo_fields);
      if (!m.has_hw || !m.hw.has_device_type || !m.has_main_mcu ||
          !m.main_mcu.has_application || !m.main_mcu.application.has_version)
        throw std::runtime_error(
            "Incomplete OneKey Protocol V2 device information");
      return {{"device_type", m.hw.device_type},
              {"device_id", m.hw.serial_no},
              {"firmware_version", m.main_mcu.application.version}};
    }
    case V2_DEVICE_STATUS: {
      const auto m = DecodeMessage<nunchuk_onekey_V2DeviceStatus>(
          data, nunchuk_onekey_V2DeviceStatus_fields);
      if (!m.has_unlocked || !m.has_init_states || !m.has_passphrase_enabled)
        throw std::runtime_error("Incomplete OneKey Protocol V2 wallet status");
      return {{"device_id", m.device_id},
              {"unlocked", m.unlocked},
              {"initialized", m.init_states},
              {"passphrase_protection", m.passphrase_enabled},
              {"attach_pin_available", m.attach_to_pin_enabled},
              {"unlocked_by_attach_pin", m.unlocked_by_attach_to_pin}};
    }
    case V2_SESSION: {
      auto m = DecodeMessage<nunchuk_onekey_V2Session>(
          data, nunchuk_onekey_V2Session_fields);
      if (!m.session_id.size || !m.btc_test_address[0]) {
        memory_cleanse(&m, sizeof(m));
        throw std::runtime_error(
            "Incomplete OneKey Protocol V2 wallet session");
      }
      json result{{"session_id", GetBytes(m.session_id)},
                  {"btc_test_address", m.btc_test_address}};
      memory_cleanse(&m, sizeof(m));
      return result;
    }

    case FEATURES: {
      const auto m = DecodeMessage<nunchuk_onekey_Features>(
          data, nunchuk_onekey_Features_fields);
      json result{
          {"vendor", m.vendor},
          {"major", m.major_version},
          {"minor", m.minor_version},
          {"patch", m.patch_version},
          {"bootloader", m.bootloader_mode},
          {"device_id", m.device_id},
          {"pin_protection", m.pin_protection},
          {"passphrase_protection", m.passphrase_protection},
          {"initialized", m.initialized},
          {"unlocked", m.unlocked},
          {"label", m.label},
          {"onekey_version", m.onekey_version},
          {"firmware_version", m.onekey_firmware_version},
          {"serial",
           m.onekey_serial_no[0]
               ? m.onekey_serial_no
               : (m.onekey_serial[0] ? m.onekey_serial : m.serial_no)},
          {"passphrase_on_device",
           m.passphrase_always_on_device ||
               std::find(m.capabilities, m.capabilities + m.capabilities_count,
                         17) != m.capabilities + m.capabilities_count}};
      if (m.has_onekey_device_type)
        result["device_type"] = m.onekey_device_type;
      return result;
    }
    case FAILURE: {
      const auto m = DecodeMessage<nunchuk_onekey_Failure>(
          data, nunchuk_onekey_Failure_fields);
      return {{"code", m.code}, {"message", m.message}};
    }
    case BUTTON_REQUEST: {
      const auto m = DecodeMessage<nunchuk_onekey_ButtonRequest>(
          data, nunchuk_onekey_ButtonRequest_fields);
      return {{"code", m.code}};
    }
    case PIN_MATRIX_REQUEST: {
      const auto m = DecodeMessage<nunchuk_onekey_PinMatrixRequest>(
          data, nunchuk_onekey_PinMatrixRequest_fields);
      return {{"type", m.type}};
    }
    case PASSPHRASE_REQUEST: {
      const auto m = DecodeMessage<nunchuk_onekey_PassphraseRequest>(
          data, nunchuk_onekey_PassphraseRequest_fields);
      return {{"on_device", m.on_device},
              {"exists_attach_pin_user", m.exists_attach_pin_user}};
    }
    case PUBLIC_KEY: {
      const auto m = DecodeMessage<nunchuk_onekey_PublicKey>(
          data, nunchuk_onekey_PublicKey_fields);
      json result{{"xpub", m.xpub},
                  {"node",
                   {{"depth", m.node.depth},
                    {"fingerprint", m.node.fingerprint},
                    {"child_num", m.node.child_num},
                    {"chain_code", GetBytes(m.node.chain_code)},
                    {"public_key", GetBytes(m.node.public_key)}}}};
      if (m.has_root_fingerprint)
        result["root_fingerprint"] = m.root_fingerprint;
      return result;
    }
    case ADDRESS: {
      const auto m = DecodeMessage<nunchuk_onekey_Address>(
          data, nunchuk_onekey_Address_fields);
      return {{"address", m.address}};
    }
    case MESSAGE_SIGNATURE: {
      const auto m = DecodeMessage<nunchuk_onekey_MessageSignature>(
          data, nunchuk_onekey_MessageSignature_fields);
      return {{"address", m.address}, {"signature", GetBytes(m.signature)}};
    }
    case TX_REQUEST: {
      const auto m = DecodeMessage<nunchuk_onekey_TxRequest>(
          data, nunchuk_onekey_TxRequest_fields);
      if (!m.has_request_type)
        throw std::runtime_error("Missing OneKey transaction request type");
      json result{{"request_type", m.request_type}};
      if (m.has_details) {
        if (m.details.has_request_index)
          result["request_index"] = m.details.request_index;
        if (m.details.has_tx_hash)
          result["tx_hash"] = GetBytes(m.details.tx_hash);
      }
      if (m.has_serialized) {
        if (m.serialized.has_signature_index != m.serialized.has_signature) {
          throw std::runtime_error("Incomplete OneKey transaction signature");
        }
        if (m.serialized.has_signature_index) {
          result["signature_index"] = m.serialized.signature_index;
          result["signature"] = GetBytes(m.serialized.signature);
        }
      }
      return result;
    }
    case SIGNED_PSBT: {
      Bytes bytes;
      nunchuk_onekey_SignedPsbt message{};
      message.psbt.arg = &bytes;
      message.psbt.funcs.decode = [](pb_istream_t* stream, const pb_field_t*,
                                     void** arg) {
        auto& result = *static_cast<Bytes*>(*arg);
        if (!result.empty() ||
            stream->bytes_left > WireFramer::MAX_MESSAGE_SIZE)
          return false;
        result.resize(stream->bytes_left);
        return pb_read(stream, result.data(), result.size());
      };
      auto stream = pb_istream_from_buffer(data.data(), data.size());
      if (!pb_decode(&stream, nunchuk_onekey_SignedPsbt_fields, &message) ||
          bytes.empty()) {
        throw std::runtime_error("Invalid OneKey signed PSBT");
      }
      return {{"psbt", HexStr(bytes)}};
    }
    default:
      throw std::runtime_error("Unexpected OneKey response type");
  }
}

}  // namespace nunchuk::onekey::proto
