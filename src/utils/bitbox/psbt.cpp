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

#include "utils/bitbox/psbt.hpp"

#include <algorithm>
#include <pubkey.h>
#include <script/script.h>
#include <stdexcept>
#include <utility>

#include <nunchuk.h>

#include "utils/bitbox/bitcoin.hpp"
#include "utils/bitbox/crypto.hpp"
#include "utils/txutils.hpp"

namespace nunchuk::bitbox {
namespace {

bool SameFingerprint(const unsigned char fingerprint[4],
                     std::span<const unsigned char> expected) {
  return expected.size() == 4 &&
         std::equal(fingerprint, fingerprint + 4, expected.begin());
}

std::vector<unsigned char> HashBytes(const Txid& hash) {
  const auto bytes = MakeUCharSpan(hash.ToUint256());
  return {bytes.begin(), bytes.end()};
}

bool MatchesAccountKeypath(const std::vector<uint32_t>& keypath,
                           const std::vector<uint32_t>& account_keypath) {
  return keypath.size() == account_keypath.size() + 2 &&
         std::equal(account_keypath.begin(), account_keypath.end(),
                    keypath.begin());
}

bool IsChangeKeypath(const std::vector<uint32_t>& keypath) {
  if (keypath.size() < 2) {
    throw std::invalid_argument("BitBox output keypath is invalid");
  }
  return keypath[keypath.size() - 2] == 1;
}

bool IsSimpleTaproot(const proto::ScriptConfig& config) {
  return config.kind == proto::ScriptConfig::Kind::SIMPLE &&
         config.simple_type == proto::ScriptConfig::SimpleType::P2TR;
}

std::optional<PsbtInputKey> FindKey(
    const PSBTInput& input, std::span<const unsigned char> fingerprint,
    const std::vector<uint32_t>& account_keypath) {
  for (const auto& [xonly, leaf_origin] : input.m_tap_bip32_paths) {
    const auto& [leaf_hashes, origin] = leaf_origin;
    if (!SameFingerprint(origin.fingerprint, fingerprint) ||
        !MatchesAccountKeypath(origin.path, account_keypath)) {
      continue;
    }
    const bool internal = !input.m_tap_internal_key.IsNull() &&
                          input.m_tap_internal_key == xonly;
    if (internal) {
      if (!leaf_hashes.empty()) {
        throw std::invalid_argument(
            "BitBox PSBT key cannot be internal and a tapleaf key");
      }
      return PsbtInputKey{
          PsbtInputKey::Type::TAPROOT_KEY_PATH, origin.path,
          std::vector<unsigned char>(xonly.begin(), xonly.end()),
          std::nullopt};
    }
    if (leaf_hashes.size() != 1) {
      throw std::invalid_argument(
          "BitBox requires a Taproot key to belong to exactly one leaf");
    }
    return PsbtInputKey{
        PsbtInputKey::Type::TAPROOT_SCRIPT_PATH, origin.path,
        std::vector<unsigned char>(xonly.begin(), xonly.end()),
        *leaf_hashes.begin()};
  }
  for (const auto& [pubkey, origin] : input.hd_keypaths) {
    if (SameFingerprint(origin.fingerprint, fingerprint) &&
        MatchesAccountKeypath(origin.path, account_keypath)) {
      return PsbtInputKey{
          PsbtInputKey::Type::ECDSA, origin.path,
          std::vector<unsigned char>(pubkey.begin(), pubkey.end()),
          std::nullopt};
    }
  }
  return std::nullopt;
}

std::optional<PsbtInputKey> FindOutputKey(
    const PSBTOutput& output, std::span<const unsigned char> fingerprint,
    const std::vector<uint32_t>& account_keypath) {
  for (const auto& [xonly, leaf_origin] : output.m_tap_bip32_paths) {
    const auto& [leaf_hashes, origin] = leaf_origin;
    if (!SameFingerprint(origin.fingerprint, fingerprint) ||
        !MatchesAccountKeypath(origin.path, account_keypath)) {
      continue;
    }
    const bool internal = !output.m_tap_internal_key.IsNull() &&
                          output.m_tap_internal_key == xonly;
    if (internal) {
      if (!leaf_hashes.empty()) {
        throw std::invalid_argument(
            "BitBox PSBT output key cannot be internal and a tapleaf key");
      }
      return PsbtInputKey{PsbtInputKey::Type::TAPROOT_KEY_PATH, origin.path,
                          std::vector<unsigned char>(xonly.begin(), xonly.end()),
                          std::nullopt};
    }
    if (leaf_hashes.size() != 1) {
      throw std::invalid_argument(
          "BitBox requires a Taproot output key to belong to exactly one "
          "leaf");
    }
    return PsbtInputKey{PsbtInputKey::Type::TAPROOT_SCRIPT_PATH, origin.path,
                        std::vector<unsigned char>(xonly.begin(), xonly.end()),
                        *leaf_hashes.begin()};
  }
  for (const auto& [pubkey, origin] : output.hd_keypaths) {
    if (SameFingerprint(origin.fingerprint, fingerprint) &&
        MatchesAccountKeypath(origin.path, account_keypath)) {
      return PsbtInputKey{PsbtInputKey::Type::ECDSA, origin.path,
                          std::vector<unsigned char>(pubkey.begin(), pubkey.end()),
                          std::nullopt};
    }
  }
  return std::nullopt;
}

std::pair<proto::OutputType, std::vector<unsigned char>> OutputPayload(
    const CScript& script, const std::string& firmware_version) {
  if (script.size() == 25 && script[0] == OP_DUP &&
      script[1] == OP_HASH160 && script[2] == 20 &&
      script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG) {
    return {proto::OutputType::P2PKH, {script.begin() + 3, script.begin() + 23}};
  }
  if (script.IsPayToScriptHash()) {
    return {proto::OutputType::P2SH, {script.begin() + 2, script.begin() + 22}};
  }
  if (script.IsPayToWitnessScriptHash()) {
    return {proto::OutputType::P2WSH, {script.begin() + 2, script.end()}};
  }
  if (script.size() == 22 && script[0] == OP_0 && script[1] == 20) {
    return {proto::OutputType::P2WPKH, {script.begin() + 2, script.end()}};
  }
  if (script.IsPayToTaproot()) {
    return {proto::OutputType::P2TR, {script.begin() + 2, script.end()}};
  }
  if (!script.empty() && script.front() == OP_RETURN) {
    if (!FirmwareAtLeast(firmware_version, 9, 24, 0)) {
      throw std::invalid_argument(
          "BitBox OP_RETURN signing requires firmware 9.24.0 or newer");
    }
    CScript::const_iterator iterator = script.begin();
    std::vector<unsigned char> data;
    opcodetype opcode;
    if (!script.GetOp(iterator, opcode) || opcode != OP_RETURN ||
        !script.GetOp(iterator, opcode, data) || opcode > OP_PUSHDATA4 ||
        iterator != script.end() ||
        CScript() << OP_RETURN << data != script) {
      throw std::invalid_argument(
          "BitBox supports one data push after OP_RETURN");
    }
    return {proto::OutputType::OP_RETURN, std::move(data)};
  }
  throw std::invalid_argument("BitBox PSBT output script is unsupported");
}

}  // namespace

PreparedPsbt PreparePsbt(const std::string& encoded, const Wallet& wallet,
                         const std::string& root_fingerprint,
                         const std::string& firmware_version,
                         const std::optional<std::vector<uint32_t>>&
                             account_keypath) {
  PreparedPsbt result;
  result.psbt = DecodePsbt(encoded);
  if (!result.psbt.tx.has_value()) {
    throw std::invalid_argument("BitBox PSBT has no unsigned transaction");
  }
  const auto& transaction = *result.psbt.tx;
  if (transaction.vin.empty() || transaction.vout.empty()) {
    throw std::invalid_argument(
        "BitBox transactions require at least one input and one output");
  }
  const auto fingerprint = ParseHex(root_fingerprint);
  const auto wallet_config = BuildWalletConfig(wallet, root_fingerprint);
  auto candidates = wallet_config.accounts;
  if (account_keypath.has_value()) {
    const auto requested = std::find_if(
        candidates.begin(), candidates.end(), [&](const WalletAccount& account) {
          return account.keypath == *account_keypath;
        });
    if (requested == candidates.end()) {
      throw std::invalid_argument(
          "BitBox signing account keypath is not in the wallet policy");
    }
    candidates = {*requested};
  }
  for (const auto& candidate : candidates) {
    bool found_in_all_inputs = true;
    for (size_t index = 0; index < result.psbt.tx->vin.size(); ++index) {
      if (!FindKey(result.psbt.inputs.at(index), fingerprint,
                   candidate.keypath)
               .has_value()) {
        found_in_all_inputs = false;
        break;
      }
    }
    if (found_in_all_inputs) {
      result.signing_account_keypaths.push_back(candidate.keypath);
    }
  }
  if (result.signing_account_keypaths.empty()) {
    throw std::invalid_argument(
        "BitBox account key was not found in every PSBT input");
  }
  const auto& signing_account_keypath =
      result.signing_account_keypaths.front();
  const auto signing_account = std::find_if(
      wallet_config.accounts.begin(), wallet_config.accounts.end(),
      [&](const WalletAccount& account) {
        return account.keypath == signing_account_keypath;
      });
  if (signing_account == wallet_config.accounts.end()) {
    throw std::logic_error("BitBox PSBT signing account disappeared");
  }
  const auto signing_account_index = static_cast<size_t>(
      std::distance(wallet_config.accounts.begin(), signing_account));
  proto::ScriptConfigWithKeypath script_config{
      ScriptConfigForAccount(wallet_config, signing_account_index),
      signing_account_keypath};
  const bool simple_taproot = IsSimpleTaproot(script_config.script_config);
  if (simple_taproot && FirmwareBefore(firmware_version, 9, 10, 0)) {
    throw std::invalid_argument(
        "BitBox Taproot signing requires firmware 9.10.0 or newer");
  }
  result.script_configs.push_back(script_config);
  if (transaction.version != 1 && transaction.version != 2) {
    throw std::invalid_argument("BitBox transaction version must be 1 or 2");
  }
  if (transaction.nLockTime >= 500000000) {
    throw std::invalid_argument("BitBox does not support timestamp locktimes");
  }

  for (size_t index = 0; index < transaction.vin.size(); ++index) {
    auto& psbt_input = result.psbt.inputs.at(index);
    if (psbt_input.sighash_type.has_value() &&
        *psbt_input.sighash_type != SIGHASH_ALL &&
        *psbt_input.sighash_type != SIGHASH_DEFAULT) {
      throw std::invalid_argument("BitBox supports default sighash types only");
    }
    const auto key =
        FindKey(psbt_input, fingerprint, signing_account_keypath);
    if (!key.has_value()) {
      throw std::logic_error("BitBox PSBT signing key disappeared");
    }
    CTxOut utxo;
    if (!result.psbt.GetInputUTXO(utxo, index)) {
      throw std::invalid_argument("BitBox PSBT input is missing its UTXO");
    }
    const bool taproot = key->type != PsbtInputKey::Type::ECDSA;
    if (taproot && psbt_input.sighash_type.has_value() &&
        *psbt_input.sighash_type != SIGHASH_DEFAULT) {
      throw std::invalid_argument(
          "BitBox Taproot inputs require SIGHASH_DEFAULT");
    }
    if (!taproot && psbt_input.sighash_type.has_value() &&
        *psbt_input.sighash_type != SIGHASH_ALL) {
      throw std::invalid_argument(
          "BitBox ECDSA inputs require SIGHASH_ALL");
    }
    if (utxo.nValue <= 0) {
      throw std::invalid_argument(
          "BitBox PSBT inputs must have a nonzero value");
    }
    // Match BTCSignNeedsPrevTxs() in the official SDK. Only a simple P2TR
    // transaction is guaranteed not to need previous transactions across
    // supported firmware versions.
    if (!simple_taproot && !psbt_input.non_witness_utxo) {
      throw std::invalid_argument(
          "BitBox requires non-witness UTXOs for this wallet type");
    }
    proto::SignInput input;
    input.previous_output_hash = HashBytes(transaction.vin[index].prevout.hash);
    input.previous_output_index = transaction.vin[index].prevout.n;
    input.previous_output_value = utxo.nValue;
    input.sequence = transaction.vin[index].nSequence;
    input.keypath = key->keypath;
    input.script_config_index = 0;
    result.inputs.push_back(std::move(input));
    result.keys.push_back(*key);
  }

  for (size_t index = 0; index < transaction.vout.size(); ++index) {
    const auto& tx_output = transaction.vout[index];
    const auto& psbt_output = result.psbt.outputs.at(index);
    proto::SignOutput output;
    if (tx_output.nValue < 0) {
      throw std::invalid_argument("BitBox PSBT output has a negative value");
    }
    output.value = tx_output.nValue;
    const auto key =
        FindOutputKey(psbt_output, fingerprint, signing_account_keypath);
    const bool same_account = key.has_value();
    if (same_account &&
        wallet_config.script_config.kind == proto::ScriptConfig::Kind::POLICY &&
        FirmwareBefore(firmware_version, 9, 15, 0)) {
      throw std::invalid_argument(
          "BitBox wallet-policy outputs require firmware 9.15.0 or newer");
    }
    const bool internal =
        same_account &&
        (!FirmwareBefore(firmware_version, 9, 15, 0) ||
         IsChangeKeypath(key->keypath));
    if (internal) {
      if (tx_output.nValue == 0) {
        throw std::invalid_argument(
            "BitBox regular outputs must have a nonzero value");
      }
      output.ours = true;
      output.keypath = key->keypath;
      output.script_config_index = 0;
    } else {
      const auto [type, payload] =
          OutputPayload(tx_output.scriptPubKey, firmware_version);
      if (type == proto::OutputType::OP_RETURN) {
        if (tx_output.nValue != 0) {
          throw std::invalid_argument(
              "BitBox OP_RETURN outputs must have zero value");
        }
      } else if (tx_output.nValue == 0) {
        throw std::invalid_argument(
            "BitBox regular outputs must have a nonzero value");
      }
      output.type = type;
      output.payload = payload;
    }
    result.outputs.push_back(std::move(output));
  }
  return result;
}

proto::PreviousTransactionInit PreviousTransactionInit(
    const PreparedPsbt& prepared, size_t input_index) {
  const auto& transaction = prepared.psbt.inputs.at(input_index).non_witness_utxo;
  if (!transaction) {
    throw std::invalid_argument("BitBox previous transaction is missing");
  }
  return {static_cast<uint32_t>(transaction->version),
          static_cast<uint32_t>(transaction->vin.size()),
          static_cast<uint32_t>(transaction->vout.size()),
          transaction->nLockTime};
}

proto::PreviousTransactionInput PreviousTransactionInput(
    const PreparedPsbt& prepared, size_t input_index, size_t previous_index) {
  const auto& transaction = prepared.psbt.inputs.at(input_index).non_witness_utxo;
  if (!transaction || previous_index >= transaction->vin.size()) {
    throw std::invalid_argument("BitBox previous transaction input is invalid");
  }
  const auto& input = transaction->vin[previous_index];
  return {HashBytes(input.prevout.hash), input.prevout.n,
          std::vector<unsigned char>(input.scriptSig.begin(),
                                     input.scriptSig.end()),
          input.nSequence};
}

proto::PreviousTransactionOutput PreviousTransactionOutput(
    const PreparedPsbt& prepared, size_t input_index, size_t previous_index) {
  const auto& transaction = prepared.psbt.inputs.at(input_index).non_witness_utxo;
  if (!transaction || previous_index >= transaction->vout.size()) {
    throw std::invalid_argument("BitBox previous transaction output is invalid");
  }
  const auto& output = transaction->vout[previous_index];
  return {static_cast<uint64_t>(output.nValue),
          std::vector<unsigned char>(output.scriptPubKey.begin(),
                                     output.scriptPubKey.end())};
}

void ApplyPsbtSignature(PreparedPsbt& prepared, size_t input_index,
                        std::span<const unsigned char> signature) {
  auto& input = prepared.psbt.inputs.at(input_index);
  const auto& key = prepared.keys.at(input_index);
  if (signature.size() != 64) {
    throw std::invalid_argument("BitBox PSBT signature must be 64 bytes");
  }
  switch (key.type) {
    case PsbtInputKey::Type::ECDSA: {
      CPubKey pubkey(key.public_key);
      if (!pubkey.IsFullyValid()) {
        throw std::invalid_argument("BitBox PSBT public key is invalid");
      }
      auto encoded_signature = EncodeSecp256k1Signature(signature);
      if (encoded_signature.empty()) {
        throw std::invalid_argument("BitBox ECDSA signature is invalid");
      }
      encoded_signature.push_back(SIGHASH_ALL);
      input.partial_sigs[pubkey.GetID()] = {
          pubkey, std::move(encoded_signature)};
      break;
    }
    case PsbtInputKey::Type::TAPROOT_KEY_PATH:
      input.m_tap_key_sig.assign(signature.begin(), signature.end());
      break;
    case PsbtInputKey::Type::TAPROOT_SCRIPT_PATH:
      if (!key.leaf_hash.has_value()) {
        throw std::logic_error("BitBox tapleaf hash is missing");
      }
      input.m_tap_script_sigs[
          {XOnlyPubKey(std::span<const unsigned char>(key.public_key)),
           *key.leaf_hash}] =
          std::vector<unsigned char>(signature.begin(), signature.end());
      break;
  }
}

SignPsbtResult FinishPsbt(const PreparedPsbt& prepared) {
  return {EncodePsbt(prepared.psbt)};
}

}  // namespace nunchuk::bitbox
