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

#include <algorithm>
#include <atomic>
#include "nunchuk.h"
#include "tinyformat.h"
#include "utils/httplib.h"
#include "descriptor.h"
#include "txutils.hpp"

namespace nunchuk {
static const std::string_view TREZOR_DEEPLINK =
    "https://connect.trezor.io/9/deeplink/1/";
static const std::string_view NUNCHUK_TREZOR_CALLBACK = "nunchuk://trezor";

static std::string TrezorAddManifest(std::string url) {
  return url +
         "&appName=Nunchuk&appIcon=https%3A%2F%2Fstatic-assets.nunchuk.io%2F"
         "assets_v1%2Ffavicon.png";
}

static int TrezorNextId() {
  static int id = 1;
  return id++;
}

static json TrezorGetPayload(const std::string &response) {
  try {
    json parsed = json::parse(response);
    if (!parsed.value("success", false)) {
      const json error = parsed.value("error", json::object());
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             strprintf("[Trezor] %s: %s",
                                       error.value("code", "UnknownCode"),
                                       error.value("message", "Unknown error")));
    }
    return parsed.at("payload");
  } catch (const json::exception &e) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, e.what());
  }
}

static bool is_my_key(const std::vector<unsigned char> &my_xfp,
                      const KeyOriginInfo &key_origin) {
  return my_xfp.size() == sizeof(key_origin.fingerprint) &&
         std::equal(std::begin(key_origin.fingerprint),
                    std::end(key_origin.fingerprint), my_xfp.begin());
}

static json get_input_script_type(const PSBTInput &input, const CTxOut &utxo) {
  bool is_p2sh = utxo.scriptPubKey.IsPayToScriptHash();
  CScript script = is_p2sh ? input.redeem_script : utxo.scriptPubKey;
  int version{};
  std::vector<unsigned char> program;
  bool is_witness = script.IsWitnessProgram(version, program);
  if (is_witness) {
    if (version == 0) {
      return is_p2sh ? "SPENDP2SHWITNESS" : "SPENDWITNESS";
    }
    if (version == 1) {
      return "SPENDTAPROOT";
    }
    return "SPENDADDRESS";
  }
  return "SPENDADDRESS";
}

static std::string get_output_script_type(const CScript &script,
                                          const CScript &redeem_script) {
  bool is_p2sh = script.IsPayToScriptHash();
  int version{};
  std::vector<unsigned char> program;
  bool is_witness = script.IsWitnessProgram(version, program);
  if (is_witness) {
    if (version == 0) {
      return is_p2sh ? "PAYTOP2SHWITNESS" : "PAYTOWITNESS";
    }
    if (version == 1) {
      return "PAYTOTAPROOT";
    }
    return "PAYTOADDRESS";
  } else if (is_p2sh && !redeem_script.empty()) {
    int version2{};
    std::vector<unsigned char> program2;
    bool is_witness2 = redeem_script.IsWitnessProgram(version2, program2);
    if (is_witness2 && (program2.size() == 20 || program2.size() == 32)) {
      return "PAYTOP2SHWITNESS";
    }
  }
  return "PAYTOADDRESS";
}

std::string TrezorGetPublicKey(WalletType wallet_type, AddressType address_type,
                               int index) {
  int id = TrezorNextId();
  auto path = Utils::GetBip32Path(wallet_type, address_type, index);
  std::replace(path.begin(), path.end(), 'h', '\'');
  json params = {
      {"path", path},
      {"coin", Utils::GetChain() == Chain::MAIN ? "btc" : "test"},
  };
  auto params_encoded = httplib::detail::encode_query_param(params.dump());
  auto callback = httplib::detail::encode_query_param(
      strprintf("%s?method=getPublicKey&id=%d", NUNCHUK_TREZOR_CALLBACK, id));
  return TrezorAddManifest(strprintf(
      "%s?method=getPublicKey&params=%s&callback=%s", TREZOR_DEEPLINK,
      params_encoded, callback));
}

SingleSigner TrezorParsePublicKeyResponse(const std::string &response) {
  auto payload = TrezorGetPayload(response);
  if (auto it = payload.find("descriptor"); it != payload.end()) {
    std::string error;
    auto wallet = ParseDescriptors(*it, error);
    if (!wallet) {
      throw NunchukException(NunchukException::INVALID_PARAMETER, error);
    }
    auto signer = wallet->get_signers()[0];
    signer.set_name("trezor");
    return signer;
  }
  throw NunchukException(NunchukException::INVALID_PARAMETER,
                         "[Trezor] Unsupport trezor model.");
}

static std::pair<std::string, json> TrezorSignParams(
    const Wallet &wallet, const std::string &base64_psbt,
    const std::string &xfp) {
  PartiallySignedTransaction psbt;
  if (std::string error; !DecodeBase64PSBT(psbt, base64_psbt, error)) {
    throw NunchukException(NunchukException::INVALID_PSBT, error);
  }
  if (!psbt.tx) {
    throw NunchukException(NunchukException::INVALID_PSBT,
                           "PSBT missing unsigned transaction");
  }
  if (psbt.inputs.size() != psbt.tx->vin.size() ||
      psbt.outputs.size() != psbt.tx->vout.size()) {
    throw NunchukException(NunchukException::INVALID_PSBT,
                           "PSBT input/output count mismatch");
  }

  const auto my_xfp = ParseHex(xfp);
  const CMutableTransaction &mtx = *psbt.tx;

  json out = {
      {"coin", Utils::GetChain() == Chain::MAIN ? "btc" : "test"},
      {"version", mtx.version},
      {"locktime", mtx.nLockTime},
      {"serialize", false},
  };

  std::set<std::string> wallet_xpubs;
  for (const auto &signer : wallet.get_signers()) {
    wallet_xpubs.insert(signer.get_xpub());
  }

  auto get_multisig_pubkeys =
      [&](const std::map<CPubKey, KeyOriginInfo> &hd_keypaths,
          const std::vector<std::vector<unsigned char>> &solns) {
        json ret = json::array();
        for (size_t i = 1; i + 1 < solns.size(); ++i) {
          auto hd_keypath = std::find_if(
              hd_keypaths.begin(), hd_keypaths.end(),
              [&](const std::pair<CPubKey, KeyOriginInfo> &p) {
                return std::equal(p.first.begin(), p.first.end(),
                                  solns[i].begin(), solns[i].end());
              });
          if (hd_keypath == hd_keypaths.end()) continue;
          auto xpubs = std::find_if(
              psbt.m_xpubs.begin(), psbt.m_xpubs.end(),
              [&](const std::pair<KeyOriginInfo, std::set<CExtPubKey>> &p) {
                return std::equal(std::begin(p.first.fingerprint),
                                  std::end(p.first.fingerprint),
                                  std::begin(hd_keypath->second.fingerprint),
                                  std::end(hd_keypath->second.fingerprint)) &&
                       p.first.path.size() <= hd_keypath->second.path.size() &&
                       std::equal(p.first.path.begin(), p.first.path.end(),
                                  hd_keypath->second.path.begin());
              });
          if (xpubs == psbt.m_xpubs.end()) continue;
          for (auto &&xpub : xpubs->second) {
            if (!wallet_xpubs.count(EncodeExtPubKey(xpub))) continue;
            std::vector<uint32_t> address_n(
                hd_keypath->second.path.begin() + xpubs->first.path.size(),
                hd_keypath->second.path.end());
            ret.push_back({
                {"node", EncodeExtPubKey(xpub)},
                {"address_n", address_n},
            });
          }
        }
        if (ret.size() != static_cast<size_t>(wallet.get_n())) {
          throw NunchukException(
              NunchukException::INVALID_PSBT,
              "[Trezor] Multisig keys do not match the wallet");
        }
        return ret;
      };

  out["inputs"] = json::array();
  for (size_t i = 0; i < mtx.vin.size(); ++i) {
    PSBTInput &input = psbt.inputs[i];
    CTxOut utxo;
    if (!psbt.GetInputUTXO(utxo, i) || utxo.IsNull()) {
      throw NunchukException(NunchukException::INVALID_PSBT,
                             "[Trezor] Input is missing its UTXO");
    }

    json jin = {
        {"prev_hash", mtx.vin[i].prevout.hash.GetHex()},
        {"prev_index", mtx.vin[i].prevout.n},
        {"sequence", mtx.vin[i].nSequence},
        {"amount", utxo.nValue},
        {"script_sig", HexStr(mtx.vin[i].scriptSig)},
        {"script_type", get_input_script_type(input, utxo)},
    };

    CScript script = utxo.scriptPubKey.IsPayToScriptHash() ? input.redeem_script
                                                           : utxo.scriptPubKey;
    int version{};
    std::vector<unsigned char> program;
    bool is_witness = script.IsWitnessProgram(version, program);
    if (is_witness) {
      if (script.IsPayToWitnessScriptHash()) {
        std::vector<std::vector<unsigned char>> solns;
        TxoutType type{Solver(input.witness_script, solns)};

        if (type == TxoutType::MULTISIG) {
          const int m = int(solns.at(0).at(0));
          const int n = int(solns.back().at(0));
          if (wallet.get_wallet_type() != WalletType::MULTI_SIG ||
              m != wallet.get_m() || n != wallet.get_n()) {
            throw NunchukException(
                NunchukException::INVALID_PSBT,
                "[Trezor] Multisig policy does not match the wallet");
          }
          jin["multisig"] = {
              {"m", m},
              {"pubkeys", get_multisig_pubkeys(input.hd_keypaths, solns)},
              {"signatures", std::vector<std::string>(n)},
          };
        }
      }
    }

    for (auto &&[pubkey, key_origin] : input.hd_keypaths) {
      if (!is_my_key(my_xfp, key_origin)) {
        continue;
      }
      if (input.partial_sigs.find(pubkey.GetID()) != input.partial_sigs.end()) {
        continue;
      }
      jin["address_n"] = key_origin.path;
    }
    for (const auto &[xonly_pub, leaf_pair] : input.m_tap_bip32_paths) {
      const auto &[leaf_hashes, key_origin] = leaf_pair;
      if (!is_my_key(my_xfp, key_origin)) continue;
      bool single_key_path = (input.m_tap_internal_key == xonly_pub);
      if (single_key_path && leaf_hashes.empty()) {
        jin["address_n"] = key_origin.path;
      }
    }
    if (!jin.contains("address_n")) {
      throw NunchukException(
          NunchukException::INVALID_PSBT,
          "[Trezor] Input has no unsigned key for this device");
    }

    out["inputs"].push_back(jin);
  }

  out["outputs"] = json::array();
  for (size_t i = 0; i < mtx.vout.size(); ++i) {
    const CTxOut &txout = mtx.vout[i];
    const PSBTOutput &psbt_out = psbt.outputs.at(i);

    json jout = {
        {"amount", txout.nValue},
        {"script_type", "PAYTOADDRESS"},
    };
    CTxDestination address;
    if (ExtractDestination(txout.scriptPubKey, address)) {
      jout["address"] = EncodeDestination(address);
    } else {
      CScript::const_iterator pc = txout.scriptPubKey.begin();
      opcodetype opcode;
      std::vector<unsigned char> data;
      if (txout.nValue != 0 ||
          !txout.scriptPubKey.GetOp(pc, opcode) || opcode != OP_RETURN ||
          !txout.scriptPubKey.GetOp(pc, opcode, data) ||
          opcode > OP_PUSHDATA4 || pc != txout.scriptPubKey.end() ||
          CScript() << OP_RETURN << data != txout.scriptPubKey) {
        throw NunchukException(NunchukException::INVALID_PSBT,
                               "[Trezor] Unsupported output script");
      }
      jout["script_type"] = "PAYTOOPRETURN";
      jout["op_return_data"] = HexStr(data);
    }
    for (auto &&[pubkey, key_origin] : psbt_out.hd_keypaths) {
      if (!is_my_key(my_xfp, key_origin)) {
        continue;
      }
      jout.erase("address");
      jout["address_n"] = key_origin.path;
      jout["script_type"] =
          get_output_script_type(txout.scriptPubKey, psbt_out.redeem_script);
    }
    for (auto &&[xonly_pub, leaf_pair] : psbt_out.m_tap_bip32_paths) {
      const auto &[leaf_hashes, key_origin] = leaf_pair;
      if (!is_my_key(my_xfp, key_origin)) {
        continue;
      }
      bool single_key_path = (psbt_out.m_tap_internal_key == xonly_pub);
      if (single_key_path) {
        jout.erase("address");
        jout["address_n"] = key_origin.path;
        jout["script_type"] =
            get_output_script_type(txout.scriptPubKey, psbt_out.redeem_script);
      }
    }
    std::vector<std::vector<unsigned char>> solns;
    TxoutType type{Solver(psbt_out.witness_script, solns)};
    if (type == TxoutType::MULTISIG && jout.contains("address_n")) {
      const int m = int(solns.at(0).at(0));
      const int n = int(solns.back().at(0));
      if (wallet.get_wallet_type() != WalletType::MULTI_SIG ||
          m != wallet.get_m() || n != wallet.get_n()) {
        throw NunchukException(
            NunchukException::INVALID_PSBT,
            "[Trezor] Multisig change does not match the wallet");
      }
      jout["multisig"] = {
          {"m", m},
          {"pubkeys", get_multisig_pubkeys(psbt_out.hd_keypaths, solns)},
          {"signatures", std::vector<std::string>(n)},
      };
    }
    out["outputs"].push_back(jout);
  }

  out["refTxs"] = json::array();
  std::set<Txid> seen_txids;
  for (const PSBTInput &psbt_in : psbt.inputs) {
    if (!psbt_in.non_witness_utxo) continue;
    const CTransactionRef &prev = psbt_in.non_witness_utxo;
    const Txid &txid = prev->GetHash();
    if (seen_txids.insert(txid).second) {
      json r = {
          {"version", prev->version},
          {"lock_time", prev->nLockTime},
          {"hash", txid.GetHex()},
      };

      r["inputs"] = json::array();
      for (const CTxIn &vin : prev->vin) {
        r["inputs"].push_back(json{
            {"prev_hash", vin.prevout.hash.GetHex()},
            {"prev_index", vin.prevout.n},
            {"script_sig", HexStr(vin.scriptSig)},
            {"sequence", vin.nSequence},
            {"script_type", "SPENDADDRESS"},
        });
      }

      r["bin_outputs"] = json::array();
      for (const CTxOut &vout : prev->vout) {
        r["bin_outputs"].push_back(json{
            {"amount", vout.nValue},
            {"script_pubkey", HexStr(vout.scriptPubKey)},
        });
      }
      out["refTxs"].push_back(r);
    }
  }

  return {psbt.tx->GetHash().GetHex(), out};
}

std::string TrezorSignTransaction(const Wallet &wallet, const std::string &psbt,
                                  const std::string &xfp) {
  int id = TrezorNextId();
  auto [txid, params] = TrezorSignParams(wallet, psbt, xfp);
  auto params_encoded = httplib::detail::encode_query_param(params.dump());
  std::string wallet_id;
  try {
    wallet_id = wallet.get_id();
  } catch (...) {
    // ignored
  }
  auto callback = httplib::detail::encode_query_param(
      strprintf("%s?method=signTransaction&xfp=%s&id=%d&wallet_id=%s&txid=%s",
                NUNCHUK_TREZOR_CALLBACK, xfp, id, wallet_id, txid));
  return TrezorAddManifest(strprintf(
      "%s?method=signTransaction&params=%s&callback=%s", TREZOR_DEEPLINK,
      params_encoded, callback));
}

static bool is_p2wpkh(const CScript &script) {
  return script.size() == 22 && script[0] == OP_0 && script[1] == 0x14;
}

static std::pair<CScript, SigVersion> get_segwit_scriptcode(
    const CTxOut &utxo, const PSBTInput &in) {
  CScript script = utxo.scriptPubKey.IsPayToScriptHash() ? in.redeem_script
                                                         : utxo.scriptPubKey;
  int version{};
  std::vector<unsigned char> program;
  bool is_witness = script.IsWitnessProgram(version, program);
  if (is_witness) {
    if (script.IsPayToWitnessScriptHash()) {
      return {in.witness_script, SigVersion::WITNESS_V0};
    }
    if (is_p2wpkh(script)) {
      return {CScript() << OP_DUP << OP_HASH160 << program << OP_EQUALVERIFY
                        << OP_CHECKSIG,
              SigVersion::WITNESS_V0};
    }
  }
  return {script, SigVersion::BASE};
}

std::string TrezorParseSignTransactionResponse(const Wallet &wallet,
                                               const std::string &base64_psbt,
                                               const std::string &xfp,
                                               const std::string &response) {
  auto payload = TrezorGetPayload(response);
  const std::vector<std::string> signatures = payload.at("signatures");

  PartiallySignedTransaction psbt;
  if (std::string error; !DecodeBase64PSBT(psbt, base64_psbt, error)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, error);
  }
  if (!psbt.tx || psbt.inputs.size() != psbt.tx->vin.size() ||
      signatures.size() != psbt.tx->vin.size()) {
    throw NunchukException(NunchukException::INVALID_PSBT,
                           "[Trezor] Invalid signature response");
  }

  const CMutableTransaction &mtx = *psbt.tx;
  const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);
  const auto my_xfp = ParseHex(xfp);

  for (size_t i = 0; i < mtx.vin.size(); ++i) {
    PSBTInput &input = psbt.inputs[i];
    CTxOut utxo;
    if (!psbt.GetInputUTXO(utxo, i) || utxo.IsNull()) {
      throw NunchukException(NunchukException::INVALID_PSBT,
                             "[Trezor] Input is missing its UTXO");
    }
    if (signatures[i].empty() || !IsHex(signatures[i])) {
      throw NunchukException(NunchukException::INVALID_PSBT,
                             "[Trezor] Invalid signature encoding");
    }
    auto sig = ParseHex(signatures[i]);
    bool inserted = false;
    int sighashType = input.sighash_type.value_or(SIGHASH_ALL);
    auto [scriptCode, sigversion] = get_segwit_scriptcode(utxo, input);
    auto hash = SignatureHash(scriptCode, *psbt.tx, i, sighashType,
                              utxo.nValue, sigversion, &txdata);
    for (auto &&[pubkey, key_origin] : input.hd_keypaths) {
      if (!is_my_key(my_xfp, key_origin)) {
        continue;
      }
      auto pubkey_id = pubkey.GetID();
      if (input.partial_sigs.find(pubkey_id) != input.partial_sigs.end()) {
        continue;
      }
      if (pubkey.Verify(hash, sig)) {
        sig.push_back(sighashType);
        input.partial_sigs[pubkey_id] = SigPair{pubkey, sig};
        inserted = true;
        break;
      }
    }

    bool taproot_key = false;
    for (const auto &[xonly_pub, leaf_pair] : input.m_tap_bip32_paths) {
      const auto &[leaf_hashes, key_origin] = leaf_pair;
      if (is_my_key(my_xfp, key_origin) && leaf_hashes.empty() &&
          input.m_tap_internal_key == xonly_pub) {
        taproot_key = true;
        break;
      }
    }
    if (!inserted && taproot_key && input.m_tap_key_sig.empty()) {
      int version{};
      std::vector<unsigned char> program;
      ScriptExecutionData execdata;
      execdata.m_annex_init = true;
      execdata.m_annex_present = false;
      MutableTransactionSignatureChecker checker(
          &mtx, i, utxo.nValue, txdata, MissingDataBehavior::FAIL);
      if (utxo.scriptPubKey.IsWitnessProgram(version, program) && version == 1 &&
          program.size() == WITNESS_V1_TAPROOT_SIZE &&
          checker.CheckSchnorrSignature(sig, program, SigVersion::TAPROOT,
                                        execdata)) {
        input.m_tap_key_sig = sig;
        inserted = true;
      }
    }
    if (!inserted) {
      throw NunchukException(NunchukException::INVALID_PSBT,
                             "[Trezor] Signature does not match its input");
    }
  }
  return EncodePsbt(psbt);
}

std::string TrezorSignMessage(const SingleSigner &signer,
                              const std::string &message) {
  int id = TrezorNextId();
  std::string formalized_path = signer.get_derivation_path();
  std::replace(formalized_path.begin(), formalized_path.end(), 'h', '\'');
  formalized_path += "/0/0";
  json params = {
      {"path", formalized_path},
      {"coin", Utils::GetChain() == Chain::MAIN ? "btc" : "test"},
      {"message", message},
  };
  auto params_encoded = httplib::detail::encode_query_param(params.dump());
  auto message_encoded = httplib::detail::encode_query_param(message);
  auto callback = httplib::detail::encode_query_param(
      strprintf("%s?method=signMessage&id=%d&xfp=%s&path=%s&message=%s",
                NUNCHUK_TREZOR_CALLBACK, id, signer.get_master_fingerprint(),
                signer.get_derivation_path(), message_encoded));
  return TrezorAddManifest(strprintf(
      "%s?method=signMessage&params=%s&callback=%s", TREZOR_DEEPLINK,
      params_encoded, callback));
}

std::string TrezorGetSignMessagePath(const SingleSigner &signer) {
  std::string formalized_path = signer.get_derivation_path();
  std::replace(formalized_path.begin(), formalized_path.end(), 'h', '\'');
  return formalized_path + "/0/0";
}

std::pair<std::string, std::string> TrezorParseSignMessage(
    const std::string &response) {
  auto payload = TrezorGetPayload(response);
  return {payload["address"], payload["signature"]};
}

static json get_multisig_pubkeys(const Wallet &wallet,
                                 const std::string &address_path) {
  std::vector<uint32_t> address_path_n;
  if (!ParseHDKeypath(address_path, address_path_n)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid derivation path");
  }

  auto convert_fingerprint =
      [](const unsigned char vchFingerprint[4]) -> uint32_t {
    return (uint32_t(vchFingerprint[0]) << 24) |
           (uint32_t(vchFingerprint[1]) << 16) |
           (uint32_t(vchFingerprint[2]) << 8) | (uint32_t(vchFingerprint[3]));
    ;
  };

  auto convert_xpub = [&](const CExtPubKey &xpub) {
    return json{
        {"depth", (int)xpub.nDepth},
        {"fingerprint", convert_fingerprint(xpub.vchFingerprint)},
        {"child_num", xpub.nChild},
        {"chain_code", HexStr(xpub.chaincode)},
        {"public_key", HexStr(xpub.pubkey)},
    };
  };
  auto derive_pubkey = [&](CExtPubKey xpub, const std::vector<uint32_t> &path) {
    for (auto &&child_num : path) {
      if (!xpub.Derive(xpub, child_num)) {
        throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                               "Invalid derivation path");
      }
    }
    return std::vector<unsigned char>(xpub.pubkey.begin(), xpub.pubkey.end());
  };
  auto signers = wallet.get_signers();

  auto get_address_n = [&](const SingleSigner &signer) {
    std::string signer_path = signer.get_derivation_path();
    std::replace(signer_path.begin(), signer_path.end(), 'h', '\'');
    std::vector<uint32_t> signer_path_n;
    if (!ParseHDKeypath(signer_path, signer_path_n)) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid derivation path");
    }
    if (address_path_n.size() < signer_path_n.size()) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid derivation path");
    }
    return std::vector<uint32_t>(address_path_n.begin() + signer_path_n.size(),
                                 address_path_n.end());
  };

  auto get_derived_pubkey = [&](const SingleSigner &signer) {
    return derive_pubkey(DecodeExtPubKey(signer.get_xpub()),
                         get_address_n(signer));
  };

  std::sort(signers.begin(), signers.end(),
            [&](const SingleSigner &a, const SingleSigner &b) {
              return get_derived_pubkey(a) < get_derived_pubkey(b);
            });

  json pubkeys = json::array();
  for (auto &&signer : signers) {
    auto address_n = get_address_n(signer);
    auto xpub = DecodeExtPubKey(signer.get_xpub());

    pubkeys.push_back({
        {"node", convert_xpub(xpub)},
        {"address_n", address_n},
    });
  }
  return pubkeys;
}

static std::string get_script_type(AddressType address_type,
                                   WalletType wallet_type) {
  switch (address_type) {
    case AddressType::NATIVE_SEGWIT:
      return "SPENDWITNESS";
    case AddressType::NESTED_SEGWIT:
      return "SPENDP2SHWITNESS";
    case AddressType::LEGACY:
      if (wallet_type == WalletType::MULTI_SIG) return "SPENDMULTISIG";
      return "SPENDADDRESS";
    case AddressType::ANY:
      return "SPENDADDRESS";
    case AddressType::TAPROOT:
      return "SPENDTAPROOT";
  };
  return "SPENDADDRESS";
}

std::string TrezorGetAddress(const Wallet &wallet, const std::string &address,
                             const std::string &path) {
  int id = TrezorNextId();
  std::string formalized_path = path;
  std::replace(formalized_path.begin(), formalized_path.end(), 'h', '\'');
  json params = {
      {"address", address},
      {"path", formalized_path},
      {"coin", Utils::GetChain() == Chain::MAIN ? "btc" : "test"},
      {"scriptType",
       get_script_type(wallet.get_address_type(), wallet.get_wallet_type())},
  };

  if (wallet.get_wallet_type() == WalletType::MULTI_SIG) {
    params["multisig"] = {
        {"m", wallet.get_m()},
        {"pubkeys", get_multisig_pubkeys(wallet, formalized_path)},
        {"signatures", std::vector<std::string>(wallet.get_n())},
    };
  }
  std::string wallet_id;
  try {
    wallet_id = wallet.get_id();
  } catch (...) {
    // ignored
  }

  auto params_encoded = httplib::detail::encode_query_param(params.dump());
  auto callback = httplib::detail::encode_query_param(
      strprintf("%s?method=getAddress&id=%d&wallet_id=%s",
                NUNCHUK_TREZOR_CALLBACK, id, wallet_id));
  return TrezorAddManifest(
      strprintf("%s?method=getAddress&params=%s&callback=%s", TREZOR_DEEPLINK,
                params_encoded, callback));
}

std::string TrezorParseGetAddress(const std::string &response) {
  auto payload = TrezorGetPayload(response);
  std::string address = payload["address"];
  return address;
}

}  // namespace nunchuk
