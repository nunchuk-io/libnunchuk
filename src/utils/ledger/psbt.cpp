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

#include "utils/ledger/psbt.hpp"

#include "utils/txutils.hpp"

#include <algorithm>
#include <crypto/common.h>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tinyformat.h>
#include <variant>

namespace nunchuk::ledger {
namespace {

// BIP370 PSBTv2 keys missing from this Bitcoin Core snapshot
// (PSBT_HIGHEST_VERSION is 0). Ledger SIGN_PSBT expects commitments to maps
// normalized with these fields.
namespace bip370 {
enum : uint64_t {
  GLOBAL_TX_VERSION = 0x02,
  GLOBAL_FALLBACK_LOCKTIME = 0x03,
  GLOBAL_INPUT_COUNT = 0x04,
  GLOBAL_OUTPUT_COUNT = 0x05,
  INPUT_PREVIOUS_TXID = 0x0e,
  INPUT_OUTPUT_INDEX = 0x0f,
  INPUT_SEQUENCE = 0x10,
  OUTPUT_AMOUNT = 0x03,
  OUTPUT_SCRIPT = 0x04,
};
}  // namespace bip370

constexpr uint64_t MUSIG_PUBNONCE_TAG = 0xffffffffULL;
constexpr uint64_t MUSIG_PARTIAL_SIGNATURE_TAG = 0xfffffffeULL;
constexpr uint64_t PARTIAL_SIGNATURE_MAX_TAG = 0xffff;
constexpr size_t PUBKEY_LENGTH = 32;
constexpr size_t PUBKEY_LENGTH_COMPRESSED = 33;
constexpr size_t PUBKEY_LENGTH_TAPLEAF = 64;
constexpr size_t PARTIAL_SIGNATURE_LENGTH = 32;
constexpr size_t PUBNONCE_LENGTH = 66;

struct PsbtMapEntry {
  std::vector<unsigned char> key;
  std::vector<unsigned char> value;
};

struct ParsedPsbt {
  std::vector<PsbtMapEntry> global_map;
  std::vector<std::vector<PsbtMapEntry>> input_maps;
  std::vector<std::vector<PsbtMapEntry>> output_maps;
};

struct LedgerMerkleMap {
  std::vector<unsigned char> commitment;
  LedgerMerkleTree keys_tree;
  LedgerMerkleTree values_tree;
};

struct PartialSignature {
  uint32_t input_index = 0;
  std::vector<unsigned char> pubkey;
  std::vector<unsigned char> signature;
  std::vector<unsigned char> tapleaf_hash;
};

struct MusigPubNonce {
  uint32_t input_index = 0;
  std::vector<unsigned char> participant_pubkey;
  std::vector<unsigned char> aggregated_pubkey;
  std::vector<unsigned char> tapleaf_hash;
  std::vector<unsigned char> pubnonce;
};

struct MusigPartialSignature {
  uint32_t input_index = 0;
  std::vector<unsigned char> participant_pubkey;
  std::vector<unsigned char> aggregated_pubkey;
  std::vector<unsigned char> tapleaf_hash;
  std::vector<unsigned char> partial_signature;
};

using PsbtSignature =
    std::variant<PartialSignature, MusigPubNonce, MusigPartialSignature>;

std::vector<unsigned char> KeyForType(uint64_t key_type) {
  return EncodeLedgerVarint(key_type);
}

std::vector<unsigned char> EncodeUint32Le(uint32_t value) {
  std::vector<unsigned char> result(sizeof(uint32_t));
  WriteLE32(result.data(), value);
  return result;
}

std::vector<unsigned char> EncodeInt64Le(int64_t value) {
  std::vector<unsigned char> result(sizeof(uint64_t));
  WriteLE64(result.data(), static_cast<uint64_t>(value));
  return result;
}

bool LessBytes(const std::vector<unsigned char>& lhs,
               const std::vector<unsigned char>& rhs) {
  return std::lexicographical_compare(lhs.begin(), lhs.end(), rhs.begin(),
                                      rhs.end());
}

std::vector<PsbtMapEntry> ParsePsbtMap(SpanReader& reader) {
  std::vector<PsbtMapEntry> entries;
  while (true) {
    std::vector<unsigned char> key;
    reader >> key;
    if (key.empty()) {
      return entries;
    }
    std::vector<unsigned char> value;
    reader >> value;
    if (std::any_of(entries.begin(), entries.end(),
                    [&key](const PsbtMapEntry& entry) {
                      return entry.key == key;
                    })) {
      throw std::runtime_error("PSBT parser: duplicate PSBT key");
    }
    entries.push_back({std::move(key), std::move(value)});
  }
}

void SetValue(std::vector<PsbtMapEntry>& map, uint64_t key_type,
              std::vector<unsigned char> value) {
  const auto key = KeyForType(key_type);
  for (auto& entry : map) {
    if (entry.key == key) {
      entry.value = std::move(value);
      return;
    }
  }
  map.push_back({key, std::move(value)});
}

void DeleteValue(std::vector<PsbtMapEntry>& map, uint64_t key_type) {
  const auto key = KeyForType(key_type);
  map.erase(std::remove_if(map.begin(), map.end(),
                           [&key](const PsbtMapEntry& entry) {
                             return entry.key == key;
                           }),
            map.end());
}

ParsedPsbt ParsePsbt(const PartiallySignedTransaction& psbt) {
  const auto serialized_psbt = DecodeBase64(EncodePsbt(psbt));
  if (!serialized_psbt.has_value()) {
    throw std::runtime_error("PSBT parser: failed to serialize PSBT");
  }

  SpanReader reader{MakeByteSpan(*serialized_psbt)};
  uint8_t magic[5];
  reader >> magic;
  if (!std::equal(magic, magic + 5, PSBT_MAGIC_BYTES)) {
    throw std::runtime_error("PSBT parser: invalid magic bytes");
  }

  ParsedPsbt parsed;
  parsed.global_map = ParsePsbtMap(reader);
  parsed.input_maps.reserve(psbt.inputs.size());
  parsed.output_maps.reserve(psbt.outputs.size());
  for (size_t i = 0; i < psbt.inputs.size(); ++i) {
    parsed.input_maps.push_back(ParsePsbtMap(reader));
  }
  for (size_t i = 0; i < psbt.outputs.size(); ++i) {
    parsed.output_maps.push_back(ParsePsbtMap(reader));
  }
  if (!reader.empty()) {
    throw std::runtime_error("PSBT parser: trailing data after PSBT");
  }
  return parsed;
}

std::vector<unsigned char> BytesFromTxid(const Txid& txid) {
  const auto bytes = MakeUCharSpan(txid.ToUint256());
  return std::vector<unsigned char>(bytes.begin(), bytes.end());
}

ParsedPsbt NormalizePsbt(ParsedPsbt psbt,
                         const PartiallySignedTransaction& core_psbt) {
  const auto& tx = core_psbt.tx.value();
  if (tx.vin.size() != psbt.input_maps.size() ||
      tx.vout.size() != psbt.output_maps.size()) {
    throw std::runtime_error(
        "PSBT parser: unsigned transaction count does not match maps");
  }

  SetValue(psbt.global_map, ::PSBT_GLOBAL_VERSION, EncodeUint32Le(2));
  SetValue(psbt.global_map, bip370::GLOBAL_TX_VERSION,
           EncodeUint32Le(tx.version));
  SetValue(psbt.global_map, bip370::GLOBAL_FALLBACK_LOCKTIME,
           EncodeUint32Le(tx.nLockTime));
  SetValue(psbt.global_map, bip370::GLOBAL_INPUT_COUNT,
           EncodeLedgerVarint(tx.vin.size()));
  SetValue(psbt.global_map, bip370::GLOBAL_OUTPUT_COUNT,
           EncodeLedgerVarint(tx.vout.size()));

  for (size_t i = 0; i < tx.vin.size(); ++i) {
    const auto& input = tx.vin[i];
    SetValue(psbt.input_maps[i], bip370::INPUT_PREVIOUS_TXID,
             BytesFromTxid(input.prevout.hash));
    SetValue(psbt.input_maps[i], bip370::INPUT_OUTPUT_INDEX,
             EncodeUint32Le(input.prevout.n));
    SetValue(psbt.input_maps[i], bip370::INPUT_SEQUENCE,
             EncodeUint32Le(input.nSequence));
  }
  for (size_t i = 0; i < tx.vout.size(); ++i) {
    const auto& output = tx.vout[i];
    SetValue(psbt.output_maps[i], bip370::OUTPUT_AMOUNT,
             EncodeInt64Le(output.nValue));
    SetValue(psbt.output_maps[i], bip370::OUTPUT_SCRIPT,
             std::vector<unsigned char>(output.scriptPubKey.begin(),
                                        output.scriptPubKey.end()));
  }

  DeleteValue(psbt.global_map, ::PSBT_GLOBAL_UNSIGNED_TX);
  return psbt;
}

LedgerMerkleMap BuildLedgerMerkleMap(
    std::vector<PsbtMapEntry> map) {
  std::sort(map.begin(), map.end(),
            [](const PsbtMapEntry& lhs, const PsbtMapEntry& rhs) {
              return LessBytes(lhs.key, rhs.key);
            });
  for (size_t i = 1; i < map.size(); ++i) {
    if (map[i - 1].key == map[i].key) {
      throw std::runtime_error("PSBT parser: duplicate PSBT key");
    }
  }

  std::vector<std::vector<unsigned char>> keys;
  std::vector<std::vector<unsigned char>> values;
  keys.reserve(map.size());
  values.reserve(map.size());
  for (auto& entry : map) {
    keys.push_back(std::move(entry.key));
    values.push_back(std::move(entry.value));
  }

  LedgerMerkleMap result;
  result.keys_tree = BuildLedgerMerkleTree(keys);
  result.values_tree = BuildLedgerMerkleTree(values);
  result.commitment = EncodeLedgerVarint(map.size());
  result.commitment.insert(result.commitment.end(), result.keys_tree.root.begin(),
                           result.keys_tree.root.end());
  result.commitment.insert(result.commitment.end(),
                           result.values_tree.root.begin(),
                           result.values_tree.root.end());
  return result;
}

void AddMerkleMap(LedgerContinuationContext& context,
                  const LedgerMerkleMap& map) {
  context.addMerkleTree(map.keys_tree);
  context.addMerkleTree(map.values_tree);
}

std::vector<unsigned char> ExtractSignPsbtField(
    const std::vector<unsigned char>& data, size_t& offset, size_t length,
    std::string_view field_name) {
  if (offset + length > data.size()) {
    throw std::runtime_error(strprintf("Ledger sign PSBT result is missing %s",
                                       std::string(field_name)));
  }
  std::vector<unsigned char> result(data.begin() + offset,
                                    data.begin() + offset + length);
  offset += length;
  return result;
}

uint32_t ParseSignPsbtInputIndex(const std::vector<unsigned char>& data,
                                 size_t& offset) {
  const auto value = ReadLedgerVarint(data, offset, "Ledger sign PSBT result");
  if (value > std::numeric_limits<uint32_t>::max()) {
    throw std::runtime_error("Ledger sign PSBT result input index is too large");
  }
  return static_cast<uint32_t>(value);
}

PsbtSignature DecodePartialSignature(
    const std::vector<unsigned char>& data, size_t offset,
    uint64_t input_index) {
  if (input_index > PARTIAL_SIGNATURE_MAX_TAG) {
    throw std::runtime_error("Ledger sign PSBT result input index is invalid");
  }
  if (offset >= data.size()) {
    throw std::runtime_error(
        "Ledger sign PSBT result is missing pubkey length");
  }
  const auto pubkey_length = static_cast<size_t>(data[offset++]);
  const auto pubkey_augmented =
      ExtractSignPsbtField(data, offset, pubkey_length, "pubkey");
  PartialSignature signature;
  signature.input_index = static_cast<uint32_t>(input_index);
  if (pubkey_augmented.size() == PUBKEY_LENGTH_TAPLEAF) {
    signature.pubkey.assign(pubkey_augmented.begin(),
                            pubkey_augmented.begin() + PUBKEY_LENGTH);
    signature.tapleaf_hash.assign(pubkey_augmented.begin() + PUBKEY_LENGTH,
                                  pubkey_augmented.end());
  } else if (pubkey_augmented.size() == PUBKEY_LENGTH ||
             pubkey_augmented.size() == PUBKEY_LENGTH_COMPRESSED) {
    signature.pubkey = pubkey_augmented;
  } else {
    throw std::runtime_error(
        "Ledger sign PSBT result has an invalid pubkey length");
  }
  signature.signature =
      ExtractSignPsbtField(data, offset, data.size() - offset, "signature");
  return signature;
}

PsbtSignature DecodeMusigPubNonce(
    const std::vector<unsigned char>& data, size_t offset) {
  MusigPubNonce pubnonce;
  pubnonce.input_index = ParseSignPsbtInputIndex(data, offset);
  pubnonce.pubnonce =
      ExtractSignPsbtField(data, offset, PUBNONCE_LENGTH, "pubnonce");
  pubnonce.participant_pubkey =
      ExtractSignPsbtField(data, offset, PUBKEY_LENGTH_COMPRESSED,
                           "participant pubkey");
  pubnonce.aggregated_pubkey =
      ExtractSignPsbtField(data, offset, PUBKEY_LENGTH_COMPRESSED,
                           "aggregated pubkey");
  pubnonce.tapleaf_hash =
      ExtractSignPsbtField(data, offset, data.size() - offset, "tapleaf hash");
  return pubnonce;
}

PsbtSignature DecodeMusigPartialSignature(
    const std::vector<unsigned char>& data, size_t offset) {
  MusigPartialSignature signature;
  signature.input_index = ParseSignPsbtInputIndex(data, offset);
  signature.partial_signature =
      ExtractSignPsbtField(data, offset, PARTIAL_SIGNATURE_LENGTH,
                           "partial signature");
  signature.participant_pubkey =
      ExtractSignPsbtField(data, offset, PUBKEY_LENGTH_COMPRESSED,
                           "participant pubkey");
  signature.aggregated_pubkey =
      ExtractSignPsbtField(data, offset, PUBKEY_LENGTH_COMPRESSED,
                           "aggregated pubkey");
  signature.tapleaf_hash =
      ExtractSignPsbtField(data, offset, data.size() - offset, "tapleaf hash");
  return signature;
}

std::vector<PsbtSignature> DecodeSignPsbtYieldedResults(
    const std::vector<std::vector<unsigned char>>& yielded_results) {
  std::vector<PsbtSignature> signatures;
  signatures.reserve(yielded_results.size());
  for (const auto& yielded_result : yielded_results) {
    size_t offset = 0;
    const auto input_index_or_tag =
        ReadLedgerVarint(yielded_result, offset, "Ledger sign PSBT result");
    if (input_index_or_tag == MUSIG_PUBNONCE_TAG) {
      signatures.push_back(DecodeMusigPubNonce(yielded_result, offset));
    } else if (input_index_or_tag == MUSIG_PARTIAL_SIGNATURE_TAG) {
      signatures.push_back(DecodeMusigPartialSignature(yielded_result, offset));
    } else if (input_index_or_tag <= PARTIAL_SIGNATURE_MAX_TAG) {
      signatures.push_back(
          DecodePartialSignature(yielded_result, offset, input_index_or_tag));
    } else {
      throw std::runtime_error("Ledger sign PSBT result has an unknown tag");
    }
  }
  return signatures;
}

PSBTInput& MutableInput(PartiallySignedTransaction& psbt,
                        uint32_t input_index) {
  if (input_index >= psbt.inputs.size()) {
    throw std::runtime_error("Ledger sign PSBT result input index is invalid");
  }
  return psbt.inputs[input_index];
}

CPubKey ParseCompressedPubKey(const std::vector<unsigned char>& data,
                              std::string_view field_name) {
  if (data.size() != PUBKEY_LENGTH_COMPRESSED) {
    throw std::runtime_error(
        strprintf("Ledger sign PSBT result has an invalid %s length",
                  std::string(field_name)));
  }
  CPubKey pubkey(MakeUCharSpan(data));
  if (!pubkey.IsFullyValid()) {
    throw std::runtime_error(
        strprintf("Ledger sign PSBT result has an invalid %s",
                  std::string(field_name)));
  }
  return pubkey;
}

uint256 ParseHash(const std::vector<unsigned char>& data,
                  std::string_view field_name) {
  if (data.size() != PUBKEY_LENGTH) {
    throw std::runtime_error(
        strprintf("Ledger sign PSBT result has an invalid %s length",
                  std::string(field_name)));
  }
  return uint256(MakeUCharSpan(data));
}

uint256 ParseOptionalTapleafHash(const std::vector<unsigned char>& data) {
  if (data.empty()) {
    return uint256{};
  }
  return ParseHash(data, "tapleaf hash");
}

void RequireTaprootSignature(const std::vector<unsigned char>& signature) {
  if (signature.size() < 64 || signature.size() > 65) {
    throw std::runtime_error(
        "Ledger sign PSBT result has an invalid taproot signature length");
  }
}

void RequireEcdsaSignature(const std::vector<unsigned char>& signature) {
  if (signature.empty() ||
      !CheckSignatureEncoding(signature,
                              SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC,
                              nullptr)) {
    throw std::runtime_error(
        "Ledger sign PSBT result has an invalid ECDSA signature");
  }
}

void ApplySignature(PartiallySignedTransaction& psbt,
                    PartialSignature signature) {
  auto& input = MutableInput(psbt, signature.input_index);
  if (!signature.tapleaf_hash.empty()) {
    RequireTaprootSignature(signature.signature);
    input.m_tap_script_sigs.insert_or_assign(
        std::make_pair(XOnlyPubKey(MakeUCharSpan(signature.pubkey)),
                       ParseHash(signature.tapleaf_hash, "tapleaf hash")),
        std::move(signature.signature));
    return;
  }

  if (signature.pubkey.size() == PUBKEY_LENGTH) {
    RequireTaprootSignature(signature.signature);
    input.m_tap_key_sig = std::move(signature.signature);
    return;
  }

  const auto pubkey = ParseCompressedPubKey(signature.pubkey, "pubkey");
  RequireEcdsaSignature(signature.signature);
  input.partial_sigs.insert_or_assign(
      pubkey.GetID(), SigPair(pubkey, std::move(signature.signature)));
}

void ApplySignature(PartiallySignedTransaction& psbt, MusigPubNonce pubnonce) {
  auto& input = MutableInput(psbt, pubnonce.input_index);
  const auto participant_pubkey =
      ParseCompressedPubKey(pubnonce.participant_pubkey, "participant pubkey");
  const auto aggregated_pubkey =
      ParseCompressedPubKey(pubnonce.aggregated_pubkey, "aggregated pubkey");
  input.m_musig2_pubnonces[std::make_pair(
                               aggregated_pubkey,
                               ParseOptionalTapleafHash(pubnonce.tapleaf_hash))]
      .insert_or_assign(participant_pubkey, std::move(pubnonce.pubnonce));
}

void ApplySignature(PartiallySignedTransaction& psbt,
                    MusigPartialSignature signature) {
  auto& input = MutableInput(psbt, signature.input_index);
  const auto participant_pubkey =
      ParseCompressedPubKey(signature.participant_pubkey,
                            "participant pubkey");
  const auto aggregated_pubkey =
      ParseCompressedPubKey(signature.aggregated_pubkey, "aggregated pubkey");
  input.m_musig2_partial_sigs[std::make_pair(
                                  aggregated_pubkey,
                                  ParseOptionalTapleafHash(signature.tapleaf_hash))]
      .insert_or_assign(
          participant_pubkey,
          ParseHash(signature.partial_signature, "partial signature"));
}

}  // namespace

LedgerPsbtCommitment PreparePsbtSigningContext(
    LedgerContinuationContext& context,
    const std::string& psbt) {
  const auto core_psbt = DecodePsbt(psbt);
  auto parsed = NormalizePsbt(ParsePsbt(core_psbt), core_psbt);

  const auto global_map = BuildLedgerMerkleMap(parsed.global_map);
  AddMerkleMap(context, global_map);

  std::vector<std::vector<unsigned char>> input_commitments;
  input_commitments.reserve(parsed.input_maps.size());
  for (const auto& input_map : parsed.input_maps) {
    const auto merkle_map = BuildLedgerMerkleMap(input_map);
    AddMerkleMap(context, merkle_map);
    input_commitments.push_back(merkle_map.commitment);
  }

  std::vector<std::vector<unsigned char>> output_commitments;
  output_commitments.reserve(parsed.output_maps.size());
  for (const auto& output_map : parsed.output_maps) {
    const auto merkle_map = BuildLedgerMerkleMap(output_map);
    AddMerkleMap(context, merkle_map);
    output_commitments.push_back(merkle_map.commitment);
  }

  auto inputs_tree = BuildLedgerMerkleTree(input_commitments);
  auto outputs_tree = BuildLedgerMerkleTree(output_commitments);
  context.addMerkleTree(inputs_tree);
  context.addMerkleTree(outputs_tree);

  return {global_map.commitment, parsed.input_maps.size(), inputs_tree.root,
          parsed.output_maps.size(), outputs_tree.root};
}

SignPsbtResult BuildSignedPsbtResult(
    const std::string& psbt,
    const std::vector<std::vector<unsigned char>>& yielded_results) {
  auto signed_psbt = DecodePsbt(psbt);
  auto signatures = DecodeSignPsbtYieldedResults(yielded_results);
  for (auto& signature : signatures) {
    std::visit(
        [&signed_psbt](auto& value) {
          ApplySignature(signed_psbt, std::move(value));
        },
        signature);
  }
  return SignPsbtResult{EncodePsbt(signed_psbt)};
}

}  // namespace nunchuk::ledger
