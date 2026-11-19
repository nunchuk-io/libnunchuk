/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */
#include "utils/onekey/psbt.hpp"

#include <algorithm>
#include <set>
#include <stdexcept>
#include <core_io.h>
#include <consensus/amount.h>
#include "descriptor.h"
#include "utils/onekey/bitcoin.hpp"
#include "utils/trezor.hpp"
#include "utils/txutils.hpp"

namespace nunchuk::onekey {
namespace {
using json = nlohmann::json;

bool SameFingerprint(const KeyOriginInfo& origin,
                     const std::string& fingerprint) {
  return HexStr(origin.fingerprint) == HexStr(ParseHex(fingerprint));
}

std::optional<std::pair<bool, uint32_t>> AddressIndex(
    const SingleSigner& signer, const KeyOriginInfo& origin,
    std::span<const unsigned char> public_key, bool taproot) {
  const auto account = ParseKeypath(signer.get_derivation_path());
  if (!SameFingerprint(origin, signer.get_master_fingerprint()) ||
      origin.path.size() != account.size() + 2 ||
      !std::equal(account.begin(), account.end(), origin.path.begin()))
    return std::nullopt;
  const auto branches = signer.get_external_internal_index();
  const uint32_t branch = origin.path[account.size()];
  const uint32_t index = origin.path.back();
  if ((branch != static_cast<uint32_t>(branches.first) &&
       branch != static_cast<uint32_t>(branches.second)) ||
      index >= 0x80000000)
    return std::nullopt;
  auto xpub = DecodeExtPubKey(signer.get_xpub());
  if (!xpub.Derive(xpub, branch) || !xpub.Derive(xpub, index))
    return std::nullopt;
  const auto expected = std::span(xpub.pubkey.begin(), xpub.pubkey.size())
                            .subspan(taproot ? 1 : 0);
  if (!std::equal(expected.begin(), expected.end(), public_key.begin(),
                  public_key.end()))
    return std::nullopt;
  return {{branch == static_cast<uint32_t>(branches.second), index}};
}

template <typename T>
std::optional<std::pair<bool, uint32_t>> FindAddress(const SingleSigner& signer,
                                                     const T& item) {
  std::optional<std::pair<bool, uint32_t>> result;
  auto accept = [&](const auto& candidate) {
    if (!candidate) return;
    if (result && result != candidate)
      throw std::invalid_argument("Conflicting OneKey derivation paths");
    result = candidate;
  };
  for (const auto& [key, origin] : item.hd_keypaths) {
    accept(AddressIndex(signer, origin, std::span(key.begin(), key.size()),
                        false));
  }
  for (const auto& [key, leaf_origin] : item.m_tap_bip32_paths) {
    if (!leaf_origin.first.empty() || item.m_tap_internal_key != key) continue;
    accept(AddressIndex(signer, leaf_origin.second,
                        std::span(key.begin(), key.size()), true));
  }
  return result;
}

FlatSigningProvider Provider(const Wallet& wallet, bool change, uint32_t index,
                             const CScript& expected_script) {
  FlatSigningProvider provider, result;
  std::string error;
  auto descriptors =
      Parse(wallet.get_descriptor(change ? DescriptorPath::INTERNAL_ALL
                                         : DescriptorPath::EXTERNAL_ALL),
            provider, error, true);
  std::vector<CScript> scripts;
  if (descriptors.size() != 1 ||
      !descriptors[0]->Expand(index, provider, scripts, result) ||
      scripts.size() != 1 || scripts[0] != expected_script) {
    throw std::invalid_argument("OneKey PSBT script does not match the wallet");
  }
  return result;
}

}  // namespace

PreparedPsbt PreparePsbt(const Wallet& wallet, const std::string& base64_psbt,
                         const std::string& fingerprint, Chain chain) {
  ValidateWallet(wallet);
  const auto& signer = WalletSigner(wallet, fingerprint);
  auto psbt = DecodePsbt(base64_psbt);
  if (!psbt.tx || psbt.tx->vin.empty() || psbt.tx->vout.empty() ||
      psbt.inputs.size() != psbt.tx->vin.size() ||
      psbt.outputs.size() != psbt.tx->vout.size()) {
    throw std::invalid_argument("Invalid OneKey PSBT transaction");
  }
  if (psbt.tx->version != 1 && psbt.tx->version != 2) {
    throw std::invalid_argument("OneKey supports transaction versions 1 and 2");
  }
  const bool taproot = wallet.get_address_type() == AddressType::TAPROOT;
  const auto txdata = PrecomputePSBTData(psbt);
  psbt.m_xpubs.clear();
  for (const auto& cosigner : wallet.get_signers()) {
    KeyOriginInfo origin;
    const auto fp = ParseHex(cosigner.get_master_fingerprint());
    if (fp.size() != 4)
      throw std::invalid_argument("Invalid OneKey cosigner fingerprint");
    std::copy(fp.begin(), fp.end(), origin.fingerprint);
    origin.path = ParseKeypath(cosigner.get_derivation_path());
    psbt.m_xpubs[origin].insert(DecodeExtPubKey(cosigner.get_xpub()));
  }
  std::set<COutPoint> outpoints;
  CAmount total_in = 0, total_out = 0;
  for (size_t i = 0; i < psbt.inputs.size(); ++i) {
    auto& input = psbt.inputs[i];
    CTxOut utxo;
    if (!psbt.GetInputUTXO(utxo, i) || !MoneyRange(utxo.nValue) ||
        !MoneyRange(total_in + utxo.nValue) ||
        psbt.tx->vin[i].prevout.IsNull() ||
        !outpoints.insert(psbt.tx->vin[i].prevout).second ||
        !input.final_script_sig.empty() ||
        !input.final_script_witness.IsNull()) {
      throw std::invalid_argument("Invalid OneKey PSBT input or UTXO");
    }
    total_in += utxo.nValue;
    if (!input.witness_utxo.IsNull() && input.witness_utxo != utxo) {
      throw std::invalid_argument("Conflicting OneKey PSBT UTXOs");
    }
    if (!taproot && !input.non_witness_utxo) {
      throw std::invalid_argument(
          "OneKey requires full previous transactions for legacy/SegWit "
          "signing");
    }
    if (taproot &&
        (!input.m_tap_scripts.empty() || !input.m_tap_merkle_root.IsNull())) {
      throw std::invalid_argument(
          "OneKey supports Taproot key-path wallets without a script tree");
    }
    const int sighash = taproot ? SIGHASH_DEFAULT : SIGHASH_ALL;
    if (input.sighash_type && *input.sighash_type != sighash) {
      throw std::invalid_argument("Unsupported OneKey signature hash type");
    }
    const auto address = FindAddress(signer, input);
    if (!address)
      throw std::invalid_argument(
          "OneKey input does not belong to this wallet account");
    auto provider =
        Provider(wallet, address->first, address->second, utxo.scriptPubKey);
    // Fill scripts/key origins using the actual wallet descriptor, not
    // untrusted PSBT change metadata. No private keys are present in this
    // provider.
    input.redeem_script.clear();
    input.witness_script.clear();
    input.hd_keypaths.clear();
    input.m_tap_bip32_paths.clear();
    input.partial_sigs.clear();
    input.m_tap_key_sig.clear();
    (void)SignPSBTInput(provider, psbt, i, &txdata, sighash, nullptr, false);
    if (!FindAddress(signer, input))
      throw std::invalid_argument("Missing OneKey input key origin");
  }
  for (size_t i = 0; i < psbt.outputs.size(); ++i) {
    auto& output = psbt.outputs[i];
    const auto& txout = psbt.tx->vout[i];
    if (!MoneyRange(txout.nValue) || !MoneyRange(total_out + txout.nValue)) {
      throw std::invalid_argument("Invalid OneKey output amount");
    }
    total_out += txout.nValue;
    auto address = FindAddress(signer, output);
    output.hd_keypaths.clear();
    output.m_tap_bip32_paths.clear();
    if (address) {
      auto provider =
          Provider(wallet, address->first, address->second, txout.scriptPubKey);
      output.redeem_script.clear();
      output.witness_script.clear();
      UpdatePSBTOutput(provider, psbt, i);
    }
  }
  if (total_out > total_in)
    throw std::invalid_argument("OneKey outputs exceed input value");
  PreparedPsbt result;
  result.original = base64_psbt;
  result.signing_psbt = EncodePsbt(psbt);
  result.fingerprint = fingerprint;
  result.transaction =
      TrezorSignParams(wallet, result.signing_psbt, fingerprint).second;
  result.transaction["coin_name"] = CoinName(chain);
  if (taproot) {
    // Classic rejects global XPUBs in raw PSBTs; the input/output key origins
    // already identify this singlesig wallet. Keep XPUBs in signing_psbt.
    psbt.m_xpubs.clear();
    for (size_t i = 0; i < psbt.inputs.size(); ++i) {
      CTxOut utxo;
      if (!psbt.GetInputUTXO(utxo, i))
        throw std::invalid_argument("Missing OneKey Taproot UTXO");
      psbt.inputs[i].witness_utxo = utxo;
      psbt.inputs[i].non_witness_utxo.reset();
    }
    result.raw_psbt = HexStr(*DecodeBase64(EncodePsbt(psbt)));
  }
  return result;
}

nlohmann::json TransactionAck(const PreparedPsbt& prepared,
                              const nlohmann::json& request) {
  const auto type = request.at("request_type").get<uint32_t>();
  const auto& current = prepared.transaction;
  const json* transaction = &current;
  bool previous = request.contains("tx_hash") &&
                  !request.at("tx_hash").get<std::string>().empty();
  if (previous) {
    const auto hash = request.at("tx_hash").get<std::string>();
    auto it =
        std::find_if(current.at("refTxs").begin(), current.at("refTxs").end(),
                     [&](const auto& tx) { return tx.at("hash") == hash; });
    if (it == current.at("refTxs").end())
      throw std::invalid_argument(
          "OneKey requested an unknown previous transaction");
    transaction = &*it;
  }
  if (type == 2) {
    if (!previous)
      throw std::invalid_argument(
          "Unexpected OneKey transaction metadata request");
    return {{"version", transaction->at("version")},
            {"lock_time", transaction->at("lock_time")},
            {"inputs_cnt", transaction->at("inputs").size()},
            {"outputs_cnt", transaction->at("bin_outputs").size()}};
  }
  if (type != 0 && type != 1)
    throw std::invalid_argument("Unsupported OneKey transaction request");
  const size_t index = request.at("request_index").get<uint32_t>();
  if (type == 0) return {{"input", transaction->at("inputs").at(index)}};
  if (previous)
    return {{"bin_output", transaction->at("bin_outputs").at(index)}};
  return {{"output", transaction->at("outputs").at(index)}};
}

std::string MergeSignatures(const PreparedPsbt& prepared,
                            const std::vector<std::string>& signatures) {
  if (!prepared.raw_psbt.empty() &&
      std::any_of(
          signatures.begin(), signatures.end(),
          [](const auto& signature) { return signature.size() != 128; })) {
    throw std::invalid_argument(
        "OneKey Taproot signatures must use SIGHASH_DEFAULT");
  }
  auto verified = DecodePsbt(TrezorMergeSignatures(
      prepared.signing_psbt, prepared.fingerprint, signatures));
  auto original = DecodePsbt(prepared.original);
  for (size_t i = 0; i < original.inputs.size(); ++i) {
    for (const auto& [key, signature] : verified.inputs[i].partial_sigs)
      original.inputs[i].partial_sigs[key] = signature;
    if (!verified.inputs[i].m_tap_key_sig.empty())
      original.inputs[i].m_tap_key_sig = verified.inputs[i].m_tap_key_sig;
  }
  return EncodePsbt(original);
}

std::string MergeSignedPsbt(const PreparedPsbt& prepared,
                            const std::string& hex) {
  if (!IsHex(hex))
    throw std::invalid_argument("Invalid OneKey signed PSBT encoding");
  PartiallySignedTransaction returned;
  std::string error;
  const auto bytes = ParseHex(hex);
  if (!DecodeRawPSBT(returned, MakeByteSpan(bytes), error) || !returned.tx) {
    throw std::invalid_argument("Invalid OneKey signed PSBT");
  }
  const auto original = DecodePsbt(prepared.original);
  if (returned.tx->GetHash() != original.tx->GetHash() ||
      returned.inputs.size() != original.inputs.size()) {
    throw std::invalid_argument("OneKey changed the unsigned transaction");
  }
  std::vector<std::string> signatures;
  for (const auto& input : returned.inputs)
    signatures.push_back(HexStr(input.m_tap_key_sig));
  return MergeSignatures(prepared, signatures);
}

}  // namespace nunchuk::onekey
