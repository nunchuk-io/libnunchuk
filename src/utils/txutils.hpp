/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (c) 2020 Enigmo.
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * libnunchuk is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libnunchuk. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NUNCHUK_TXUTILS_H
#define NUNCHUK_TXUTILS_H

#include <nunchuk.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <utils/addressutils.hpp>
#include <utils/errorutils.hpp>
#include <utils/stringutils.hpp>
#include <string>
#include <vector>
#include <psbt.h>
#include <core_io.h>
#include <descriptor.h>

#include <signingprovider.h>
#include <script/sign.h>
#include <boost/algorithm/string.hpp>

namespace {

inline int64_t GetBlockTime(const std::string& raw_header) {
  using namespace nunchuk;
  CBlockHeader header;
  if (!DecodeHexBlockHeader(header, raw_header)) {
    throw NunchukException(NunchukException::INVALID_FORMAT,
                           "Invalid raw header");
  } else {
    return header.GetBlockTime();
  }
}

inline PartiallySignedTransaction DecodePsbt(const std::string& base64_psbt) {
  using namespace nunchuk;
  PartiallySignedTransaction psbtx;
  std::string error;
  if (!DecodeBase64PSBT(psbtx, base64_psbt, error)) {
    throw NunchukException(NunchukException::INVALID_PSBT,
                           NormalizeErrorMessage(std::move(error)));
  }
  return psbtx;
}

inline std::string EncodePsbt(const PartiallySignedTransaction& psbtx) {
  DataStream ssTx{};
  ssTx << psbtx;
  return EncodeBase64(MakeUCharSpan(ssTx));
}

inline std::string GetTxIdFromPsbt(const std::string& base64_psbt) {
  return DecodePsbt(base64_psbt).tx.value().GetHash().GetHex();
}

inline CMutableTransaction DecodeRawTransaction(const std::string& hex_tx) {
  using namespace nunchuk;
  CMutableTransaction mtx;
  if (!DecodeHexTx(mtx, hex_tx, true, true)) {
    throw NunchukException(NunchukException::INVALID_RAW_TX,
                           "TX decode failed");
  }
  return mtx;
}

inline nunchuk::Transaction GetTransactionFromCMutableTransaction(
    const CMutableTransaction& mtx, int height) {
  using namespace nunchuk;

  Transaction tx{};
  tx.set_txid(mtx.GetHash().GetHex());
  tx.set_height(height);
  tx.set_lock_time(mtx.nLockTime);
  for (auto& input : mtx.vin) {
    tx.add_input(
        {input.prevout.hash.GetHex(), input.prevout.n, input.nSequence});
  }
  for (auto& output : mtx.vout) {
    std::string address = ScriptPubKeyToAddress(output.scriptPubKey);
    tx.add_output({address, output.nValue});
  }
  if (height == 0) {
    tx.set_status(TransactionStatus::PENDING_CONFIRMATION);
  } else if (height == -2) {
    tx.set_status(TransactionStatus::NETWORK_REJECTED);
  } else if (height == -1) {
    tx.set_status(TransactionStatus::READY_TO_BROADCAST);
  } else if (height > 0) {
    tx.set_status(TransactionStatus::CONFIRMED);
  }
  return tx;
}

inline nunchuk::Transaction ParseCMutableTransaction(
    const CMutableTransaction& mtx, const nunchuk::Wallet& wallet, int height) {
  using namespace nunchuk;

  Transaction tx = GetTransactionFromCMutableTransaction(mtx, height);
  auto signers = wallet.get_signers();
  if (wallet.get_wallet_type() == WalletType::MULTI_SIG &&
      wallet.get_address_type() == AddressType::TAPROOT) {
    if (mtx.vin[0].scriptWitness.stack.size() < 2) {  // value keyset
      for (int i = 0; i < wallet.get_n(); i++) {
        tx.set_signer(signers[i].get_master_fingerprint(), i < wallet.get_m());
      }
    } else {
      for (auto&& signer : signers) {
        tx.set_signer(signer.get_master_fingerprint(), false);
      }
      auto agg = mtx.vin[0].scriptWitness.stack[1];
      agg.erase(agg.begin());
      agg.pop_back();

      auto maxIdx =
          SigningProviderCache::getInstance().GetMaxIndex(wallet.get_id());
      FlatSigningProvider provider;
      std::string error;
      std::vector<CScript> output_scripts;
      auto external_desc = wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL);
      auto desc0 = Parse(external_desc, provider, error, true);
      for (int i = 0; i <= maxIdx; i++) {
        desc0.front()->Expand(i, provider, output_scripts, provider);
      }
      auto internal_desc = wallet.get_descriptor(DescriptorPath::INTERNAL_ALL);
      auto desc1 = Parse(internal_desc, provider, error, true);
      for (int i = 0; i <= maxIdx; i++) {
        desc1.front()->Expand(i, provider, output_scripts, provider);
      }
      for (auto&& agg_pubkeys : provider.aggregate_pubkeys) {
        if (HexStr(agg_pubkeys.first).substr(2) == HexStr(agg)) {
          for (auto&& pubkey : agg_pubkeys.second) {
            auto s = provider.origins[pubkey.GetID()];
            tx.set_signer(strprintf("%08x", ReadBE32(s.second.fingerprint)),
                          true);
          }
          break;
        }
      }
    }

  } else {
    for (auto&& signer : signers) {
      tx.set_signer(signer.get_master_fingerprint(), true);
    }
  }
  return tx;
}

inline std::vector<nunchuk::KeysetStatus> GetKeysetStatus(
    const PartiallySignedTransaction& psbtx, const nunchuk::Wallet& wallet) {
  using namespace nunchuk;
  const PSBTInput& input = psbtx.inputs[0];
  auto getXfp = [&input](const CPubKey& pub) -> std::string {
    auto leaf_origin = input.m_tap_bip32_paths.at(XOnlyPubKey(pub));
    const auto& [leaf_hashes, origin] = leaf_origin;
    return strprintf("%08x", ReadBE32(origin.fingerprint));
  };
  auto getName = [](std::vector<std::string>& xfps) -> std::string {
    std::sort(xfps.begin(), xfps.end());
    return join(xfps, ',');
  };

  // init keyset status
  std::map<std::string, KeysetStatus> keysets{};
  int n = wallet.get_n();
  auto signers = wallet.get_signers();
  std::vector<bool> v(n);
  std::fill(v.begin(), v.begin() + wallet.get_m(), true);
  std::string valuekeyset{};
  bool enableValueKeyset =
      wallet.get_wallet_template() != WalletTemplate::DISABLE_KEY_PATH;
  do {
    KeyStatus status{};
    std::vector<std::string> xfps{};
    for (int i = 0; i < n; i++) {
      if (v[i]) {
        status[signers[i].get_master_fingerprint()] = false;
        xfps.push_back(signers[i].get_master_fingerprint());
      }
    }
    if (enableValueKeyset && valuekeyset.empty()) valuekeyset = getName(xfps);
    keysets.insert(
        {getName(xfps), {TransactionStatus::PENDING_NONCE, std::move(status)}});
  } while (std::prev_permutation(v.begin(), v.end()));

  // mapping aggkey to name
  std::map<CPubKey, std::string> keysetname{};
  for (const auto& [agg, parts] : input.m_musig2_participants) {
    std::vector<std::string> xfps{};
    for (const auto& pub : parts) {
      xfps.push_back(getXfp(pub));
    }
    keysetname.insert({agg, getName(xfps)});
  }

  // check pubnonces
  for (const auto& [agg_lh, part_pubnonce] : input.m_musig2_pubnonces) {
    if (part_pubnonce.size() == wallet.get_m()) {
      keysets[keysetname[agg_lh.first]].first =
          TransactionStatus::PENDING_SIGNATURES;
    } else {
      for (const auto& [part, pubnonce] : part_pubnonce) {
        keysets[keysetname[agg_lh.first]].second[getXfp(part)] = true;
      }
    }
  }

  // check partial sigs
  for (const auto& [agg_lh, part_psig] : input.m_musig2_partial_sigs) {
    if (part_psig.size() == wallet.get_m()) {
      keysets[keysetname[agg_lh.first]].first =
          TransactionStatus::READY_TO_BROADCAST;
    } else {
      for (const auto& [part, psig] : part_psig) {
        keysets[keysetname[agg_lh.first]].second[getXfp(part)] = true;
      }
    }
  }

  std::vector<nunchuk::KeysetStatus> rs{};
  for (const auto& [agg, keyset] : keysets) {
    if (valuekeyset == agg) {
      rs.insert(rs.begin(), keyset);
    } else {
      rs.push_back(keyset);
    }
  }
  return rs;
}

inline nunchuk::Transaction GetTransactionFromPartiallySignedTransaction(
    const PartiallySignedTransaction& psbtx,
    const nunchuk::Wallet& wallet = {}) {
  using namespace nunchuk;
  auto signers = wallet.get_signers();
  auto tx = GetTransactionFromCMutableTransaction(psbtx.tx.value(), -1);
  tx.set_m(wallet.get_m());

  for (auto&& signer : signers) {
    tx.set_signer(signer.get_master_fingerprint(), false);
  }

  // Parse partial sigs
  const PSBTInput& input = psbtx.inputs[0];

  if (!input.m_tap_key_sig.empty()) {
    for (int i = 0; i < wallet.get_m(); i++) {
      tx.set_signer(signers[i].get_master_fingerprint(), true);
    }
    tx.set_status(TransactionStatus::READY_TO_BROADCAST);
    return tx;
  }
  if (!input.m_tap_script_sigs.empty()) {
    auto getXfp = [&input](const XOnlyPubKey& xonly) -> std::string {
      auto leaf_origin = input.m_tap_bip32_paths.at(xonly);
      const auto& [leaf_hashes, origin] = leaf_origin;
      return strprintf("%08x", ReadBE32(origin.fingerprint));
    };
    for (const auto& [pubkey_leaf, sig] : input.m_tap_script_sigs) {
      const auto& [xonly, leaf_hash] = pubkey_leaf;
      tx.set_signer(getXfp(xonly), true);
    }
  }
  if (!input.final_script_witness.IsNull() || !input.final_script_sig.empty()) {
    if (signers.size() == 1) {
      tx.set_signer(signers[0].get_master_fingerprint(), true);
      tx.set_status(TransactionStatus::READY_TO_BROADCAST);
      return tx;
    }

    auto psbt = DecodePsbt(EncodePsbt(psbtx));

    auto txCredit = psbt.tx.value();
    auto input = psbt.inputs[0];
    auto ctxout = input.witness_utxo;
    if (input.non_witness_utxo) {
      auto txIn = input.non_witness_utxo.get();
      auto txSpend = CMutableTransaction(*txIn);
      ctxout = txSpend.vout[txCredit.vin[0].prevout.n];
    }
    txCredit.vin[0].scriptSig = input.final_script_sig;
    txCredit.vin[0].scriptWitness = input.final_script_witness;
    auto extract = DataFromTransaction(txCredit, 0, ctxout);
    for (auto&& sig : extract.signatures) {
      KeyOriginInfo info;
      if (SigningProviderCache::getInstance().GetKeyOrigin(sig.first, info)) {
        std::string master_fingerprint =
            strprintf("%08x", ReadBE32(info.fingerprint));
        tx.set_signer(master_fingerprint, true);
      }
    }

    tx.set_status(FinalizePSBT(psbt) ? TransactionStatus::READY_TO_BROADCAST
                                     : TransactionStatus::PENDING_SIGNATURES);
    return tx;
  }

  if (wallet.get_wallet_type() == WalletType::MULTI_SIG &&
      wallet.get_address_type() == AddressType::TAPROOT) {
    tx.set_keyset_status(GetKeysetStatus(psbtx, wallet));
    tx.set_status(TransactionStatus::PENDING_SIGNATURES);
    for (const auto& keyset : tx.get_keyset_status()) {
      if (keyset.first == TransactionStatus::READY_TO_BROADCAST) {
        tx.set_status(TransactionStatus::READY_TO_BROADCAST);
        break;
      }
    }
    return tx;
  }

  if (wallet.get_address_type() != AddressType::TAPROOT) {
    std::set<std::string> signed_pubkey;
    if (!input.partial_sigs.empty()) {
      for (const auto& sig : input.partial_sigs) {
        signed_pubkey.insert(HexStr(sig.second.first));
      }
    }
    if (!input.hd_keypaths.empty()) {
      for (auto entry : input.hd_keypaths) {
        std::string pubkey = HexStr(entry.first);
        std::string master_fingerprint =
            strprintf("%08x", ReadBE32(entry.second.fingerprint));
        tx.set_signer(master_fingerprint, signed_pubkey.contains(pubkey));
      }
    } else {
      // Hotfix: decode dummy tx sign by SeedSigner
      for (auto signer : signers) {
        std::string pubkey = signer.get_public_key();
        if (pubkey.empty()) {
          auto xpub = DecodeExtPubKey(signer.get_xpub());
          CExtPubKey xpub0;
          CExtPubKey xpub01;
          if (!xpub.Derive(xpub0, 0) || !xpub0.Derive(xpub01, 1)) {
            throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                                   "Invalid path");
          }
          pubkey = HexStr(xpub01.pubkey);
        }
        tx.set_signer(signer.get_master_fingerprint(),
                      signed_pubkey.contains(pubkey));
      }
    }
  }

  auto psbt = DecodePsbt(EncodePsbt(psbtx));
  tx.set_status(FinalizePSBT(psbt) ? TransactionStatus::READY_TO_BROADCAST
                                   : TransactionStatus::PENDING_SIGNATURES);
  return tx;
}
inline std::pair<nunchuk::Transaction, bool /* is hex_tx */>
GetTransactionFromStr(const std::string& str, const nunchuk::Wallet& wallet,
                      int height) {
  using namespace nunchuk;
  using namespace boost::algorithm;

  if (height == -1) {
    constexpr auto is_hex_tx = [](const std::string& str) {
      return boost::starts_with(str, "01000000") ||
             boost::starts_with(str, "02000000");
    };
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!is_hex_tx(boost::trim_copy(str))) {
      if (DecodeBase64PSBT(psbtx, str, error)) {
        auto tx = GetTransactionFromPartiallySignedTransaction(psbtx, wallet);
        tx.set_psbt(str);
        return {tx, false};
      }
    }

    CMutableTransaction mtx;
    if (DecodeHexTx(mtx, str, true, true)) {
      auto tx = ParseCMutableTransaction(mtx, wallet, height);
      tx.set_raw(str);
      return {tx, true};
    }

    throw NunchukException(NunchukException::INVALID_PSBT,
                           NormalizeErrorMessage(std::move(error)));
  }
  auto tx = ParseCMutableTransaction(DecodeRawTransaction(str), wallet, height);
  tx.set_raw(str);
  return {tx, true};
}

inline std::string GetPartialSignature(const std::string& base64_psbt,
                                       const nunchuk::SingleSigner& signer) {
  using namespace nunchuk;

  std::string xfp = signer.get_master_fingerprint();

  auto psbt = DecodePsbt(base64_psbt);
  // Parse partial sigs
  const PSBTInput& input = psbt.inputs[0];
  std::map<std::string, std::string> signed_pubkey;
  if (!input.partial_sigs.empty()) {
    for (const auto& sig : input.partial_sigs) {
      signed_pubkey[HexStr(sig.second.first)] = HexStr(sig.second.second);
    }
  }

  if (!input.hd_keypaths.empty()) {
    for (auto entry : input.hd_keypaths) {
      std::string master_fingerprint =
          strprintf("%08x", ReadBE32(entry.second.fingerprint));
      if (master_fingerprint == xfp) {
        return signed_pubkey[HexStr(entry.first)];
      }
    }
  } else {
    // Hotfix: decode dummy tx sign by SeedSigner
    std::string pubkey = signer.get_public_key();
    if (pubkey.empty()) {
      auto xpub = DecodeExtPubKey(signer.get_xpub());
      CExtPubKey xpub0;
      CExtPubKey xpub01;
      if (!xpub.Derive(xpub0, 0) || !xpub0.Derive(xpub01, 1)) {
        throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                               "Invalid path");
      }
      pubkey = HexStr(xpub01.pubkey);
    }
    return signed_pubkey[pubkey];
  }

  return "";
}

inline std::string GetPartialSignature(const std::string& base64_psbt,
                                       const std::string& xfp) {
  using namespace nunchuk;

  auto psbt = DecodePsbt(base64_psbt);
  // Parse partial sigs
  const PSBTInput& input = psbt.inputs[0];
  std::map<std::string, std::string> signed_pubkey;
  if (!input.partial_sigs.empty()) {
    for (const auto& sig : input.partial_sigs) {
      signed_pubkey[HexStr(sig.second.first)] = HexStr(sig.second.second);
    }
  }

  if (!input.hd_keypaths.empty()) {
    for (auto entry : input.hd_keypaths) {
      std::string master_fingerprint =
          strprintf("%08x", ReadBE32(entry.second.fingerprint));
      if (master_fingerprint == xfp) {
        return signed_pubkey[HexStr(entry.first)];
      }
    }
  }
  return "";
}

}  // namespace

#endif  //  NUNCHUK_TXUTILS_H
