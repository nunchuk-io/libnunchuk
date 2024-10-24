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
#include <string>
#include <vector>
#include <psbt.h>
#include <core_io.h>

#include <signingprovider.h>
#include <script/sign.h>

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
    const CMutableTransaction& mtx,
    const std::vector<nunchuk::SingleSigner>& signers, int height) {
  using namespace nunchuk;

  Transaction tx{};
  tx.set_txid(mtx.GetHash().GetHex());
  tx.set_height(height);
  for (auto& input : mtx.vin) {
    tx.add_input({input.prevout.hash.GetHex(), input.prevout.n});
  }
  for (auto& output : mtx.vout) {
    std::string address = ScriptPubKeyToAddress(output.scriptPubKey);
    tx.add_output({address, output.nValue});
  }
  for (auto&& signer : signers) {
    tx.set_signer(signer.get_master_fingerprint(), true);
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

inline nunchuk::Transaction GetTransactionFromPartiallySignedTransaction(
    const PartiallySignedTransaction& psbtx,
    const nunchuk::Wallet& wallet = {}) {
  using namespace nunchuk;
  auto signers = wallet.get_signers();
  auto tx = GetTransactionFromCMutableTransaction(psbtx.tx.value(), signers, -1);
  tx.set_m(wallet.get_m());

  for (auto&& signer : signers) {
    tx.set_signer(signer.get_master_fingerprint(), false);
  }

  // Parse partial sigs
  const PSBTInput& input = psbtx.inputs[0];

  if (!input.m_tap_key_sig.empty()) {
    if (signers.size() == 1) {
      tx.set_signer(signers[0].get_master_fingerprint(), true);
      tx.set_status(TransactionStatus::READY_TO_BROADCAST);
      return tx;
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

    if (FinalizePSBT(psbt)) {
      tx.set_status(TransactionStatus::READY_TO_BROADCAST);
    } else {
      tx.set_status(TransactionStatus::PENDING_SIGNATURES);
    }
    return tx;
  }

  if (wallet.get_wallet_type() == WalletType::MUSIG) {
    std::vector<std::string> parts;
    if (!input.m_musig2_partial_sigs.empty()) {
      for (const auto& [agg_lh, part_psig] : input.m_musig2_partial_sigs) {
        for (const auto& [part, psig] : part_psig) {
          parts.push_back(HexStr(XOnlyPubKey(part)));
        }
      }
      tx.set_status(parts.size() == wallet.get_m()
                    ? TransactionStatus::READY_TO_BROADCAST
                    : TransactionStatus::PENDING_SIGNATURES);
    } else {
      for (const auto& [agg_lh, part_pubnonce] : input.m_musig2_pubnonces) {
        for (const auto& [part, pubnonce] : part_pubnonce) {
          parts.push_back(HexStr(XOnlyPubKey(part)));
        }
      }
      tx.set_status(TransactionStatus::PENDING_NONCE);
      if (parts.size() == wallet.get_m()) {
        parts.clear();
        tx.set_status(TransactionStatus::PENDING_SIGNATURES);
      }
    }

    if (!input.m_tap_bip32_paths.empty()) {
      for (const auto& [xonly, leaf_origin] : input.m_tap_bip32_paths) {
        const auto& [leaf_hashes, origin] = leaf_origin;
        std::string master_fingerprint =
          strprintf("%08x", ReadBE32(origin.fingerprint));
        std::string pubkey = HexStr(xonly);
        if (std::find(parts.begin(), parts.end(), pubkey) != parts.end()) {
          tx.set_signer(master_fingerprint, true);
        }
      }
    }
    return tx;
  }

  std::vector<std::string> signed_pubkey;
  if (!input.partial_sigs.empty()) {
    for (const auto& sig : input.partial_sigs) {
      signed_pubkey.push_back(HexStr(sig.second.first));
    }
  }

  if (!input.hd_keypaths.empty()) {
    for (auto entry : input.hd_keypaths) {
      std::string pubkey = HexStr(entry.first);
      std::string master_fingerprint =
          strprintf("%08x", ReadBE32(entry.second.fingerprint));
      if (std::find(signed_pubkey.begin(), signed_pubkey.end(), pubkey) !=
          signed_pubkey.end()) {
        tx.set_signer(master_fingerprint, true);
      } else {
        tx.set_signer(master_fingerprint, false);
      }
    }
  } else {
    // Hotfix: decode dummy tx sign by SeedSigner
    for (auto signer : signers) {
      std::string pubkey = signer.get_public_key();
      if (pubkey.empty()) {
        auto xpub = DecodeExtPubKey(signer.get_xpub());
        CExtPubKey xpub0;
        if (!xpub.Derive(xpub0, 0)) {
          throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                                 "Invalid path");
        }
        CExtPubKey xpub01;
        if (!xpub0.Derive(xpub01, 1)) {
          throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                                 "Invalid path");
        }
        pubkey = HexStr(xpub01.pubkey);
      }
      if (std::find(signed_pubkey.begin(), signed_pubkey.end(), pubkey) !=
          signed_pubkey.end()) {
        tx.set_signer(signer.get_master_fingerprint(), true);
      } else {
        tx.set_signer(signer.get_master_fingerprint(), false);
      }
    }
  }

  tx.set_status(signed_pubkey.size() == wallet.get_m()
                    ? TransactionStatus::READY_TO_BROADCAST
                    : TransactionStatus::PENDING_SIGNATURES);
  return tx;
}
inline std::pair<nunchuk::Transaction, bool /* is hex_tx */>
GetTransactionFromStr(const std::string& str, const nunchuk::Wallet& wallet, int height) {
  using namespace nunchuk;
  if (height == -1) {
    PartiallySignedTransaction psbtx;
    std::string error;
    if (DecodeBase64PSBT(psbtx, str, error)) {
      auto tx = GetTransactionFromPartiallySignedTransaction(psbtx, wallet);
      tx.set_psbt(str);
      return {tx, false};
    }

    CMutableTransaction mtx;
    if (DecodeHexTx(mtx, str, true, true)) {
      auto tx = GetTransactionFromCMutableTransaction(mtx, wallet.get_signers(), height);
      tx.set_raw(str);
      return {tx, true};
    }

    throw NunchukException(NunchukException::INVALID_PSBT,
                           NormalizeErrorMessage(std::move(error)));
  }
  auto tx = GetTransactionFromCMutableTransaction(DecodeRawTransaction(str), wallet.get_signers(), height);
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
      if (!xpub.Derive(xpub0, 0)) {
        throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                               "Invalid path");
      }
      CExtPubKey xpub01;
      if (!xpub0.Derive(xpub01, 1)) {
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
