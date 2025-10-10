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
#include <embeddedrpc.h>

#include "softwaresigner.h"

#include <exception>
#include <iostream>
#include <mutex>
#include <sstream>
#include <iomanip>

#include <utils/txutils.hpp>
#include <utils/secretbox.h>

#include <key_io.h>
#include <random.h>
#include <common/signmessage.h>
#include <util/bip32.h>
#include <script/signingprovider.h>
#include <rpc/util.h>
#include <descriptor.h>
#include <coreutils.h>

#include <secp256k1_musig.h>

extern "C" {
#include <pbkdf2.h>
#include <bip39.h>
#include <bip39_english.h>
#include <hmac.h>
void random_buffer(uint8_t* buf, size_t len) {
  // Core's GetStrongRandBytes
  // https://github.com/bitcoin/bitcoin/commit/6e6b3b944d12a252a0fd9a1d68fec9843dd5b4f8
  std::span<unsigned char> bytes(buf, len);
  GetStrongRandBytes(bytes);
}
}

namespace nunchuk {

std::string hexStr(const uint8_t* data, int len) {
  std::stringstream ss;
  ss << std::hex;

  for (int i(0); i < len; ++i)
    ss << std::setw(2) << std::setfill('0') << (int)data[i];

  return ss.str();
}

std::string SoftwareSigner::GenerateMnemonic(int words) {
  return std::string(mnemonic_generate(words * 32 / 3));
}

bool SoftwareSigner::CheckMnemonic(const std::string& mnemonic) {
  return mnemonic_check(mnemonic.c_str());
}

std::mutex* SoftwareSigner::mu_ = new std::mutex;

std::vector<std::string> SoftwareSigner::GetBIP39WordList() {
  std::vector<std::string> list{};
  for (auto&& word : wordlist) {
    if (word) list.push_back(word);
  }
  return list;
}

SoftwareSigner::SoftwareSigner(const std::string& mnemonic,
                               const std::string& passphrase)
    : bip32rootkey_(GetBip32RootKey(mnemonic, passphrase)) {}

SoftwareSigner::SoftwareSigner(const std::string& master_xprv)
    : bip32rootkey_(DecodeExtKey(master_xprv)) {
  if (!bip32rootkey_.key.IsValid()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid master xprv");
  }
}

SoftwareSigner::SoftwareSigner(const Wallet& group_wallet) {
  // Must use ANY here for backward compatibility
  auto desc = group_wallet.get_descriptor(DescriptorPath::ANY);
  uint8_t seed[512 / 8];
  std::string salt = "entropy-from-descriptor";
  PBKDF2_HMAC_SHA512_CTX pctx;
  pbkdf2_hmac_sha512_Init(&pctx, (const uint8_t*)desc.c_str(), desc.size(),
                          (const uint8_t*)salt.c_str(), salt.size(), 1);
  pbkdf2_hmac_sha512_Update(&pctx, 2048);
  pbkdf2_hmac_sha512_Final(&pctx, seed);

  std::vector<std::byte> spanSeed;
  for (size_t i = 0; i < 64; i++) spanSeed.push_back(std::byte{seed[i]});
  bip32rootkey_.SetSeed(spanSeed);
}

static const std::string BIP85_HASH_KEY = "bip-entropy-from-k";

void SoftwareSigner::SetupBoxKey(const std::string& path) {
  auto xkey = GetExtKeyAtPath(path);

  std::vector<uint8_t> key(BIP85_HASH_KEY.begin(), BIP85_HASH_KEY.end());
  std::vector<uint8_t> data((uint8_t*)xkey.key.begin(),
                            (uint8_t*)xkey.key.end());
  uint8_t hmac[512 / 8];
  hmac_sha512(&key[0], key.size(), &data[0], data.size(), hmac);
  boxKey_ = std::vector<uint8_t>(hmac, hmac + 32);
}

std::string SoftwareSigner::HashMessage(const std::string& message) {
  if (boxKey_.empty()) {
    throw NunchukException(NunchukException::INVALID_STATE,
                           "Box key is not setup");
  }
  std::vector<uint8_t> data(message.begin(), message.end());
  uint8_t hmac[512 / 8];
  hmac_sha512(&boxKey_[0], boxKey_.size(), &data[0], data.size(), hmac);
  return hexStr(hmac, 512 / 8);
}

std::string SoftwareSigner::EncryptMessage(const std::string& plaintext) {
  if (boxKey_.empty()) {
    throw NunchukException(NunchukException::INVALID_STATE,
                           "Box key is not setup");
  }
  return Secretbox(boxKey_).Box(plaintext);
}

std::string SoftwareSigner::DecryptMessage(const std::string& ciphertext) {
  if (boxKey_.empty()) {
    throw NunchukException(NunchukException::INVALID_STATE,
                           "Box key is not setup");
  }
  return Secretbox(boxKey_).Open(ciphertext);
}

CExtKey SoftwareSigner::GetExtKeyAtPath(const std::string& path) const {
  std::vector<uint32_t> keypath;
  std::string formalized = path;
  std::replace(formalized.begin(), formalized.end(), 'h', '\'');
  if (!ParseHDKeypath(formalized, keypath)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid hd keypath");
  }

  CExtKey xkey = bip32rootkey_;
  for (auto&& i : keypath) {
    CExtKey child;
    if (!xkey.Derive(child, i)) {
      throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                             "Invalid path");
    }
    xkey = child;
  }
  return xkey;
}

std::string SoftwareSigner::GetXpubAtPath(const std::string& path) const {
  auto xkey = GetExtKeyAtPath(path);
  return EncodeExtPubKey(xkey.Neuter());
}

std::string SoftwareSigner::GetAddressAtPath(const std::string& path) const {
  auto xkey = GetExtKeyAtPath(path);
  return EncodeDestination(PKHash(xkey.Neuter().pubkey.GetID()));
}

std::string SoftwareSigner::GetMasterFingerprint() const {
  CExtKey masterkey{};
  if (!bip32rootkey_.Derive(masterkey, 0)) {
    throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                           "Invalid path");
  }
  return hexStr(masterkey.vchFingerprint, 4);
}

std::string SoftwareSigner::SignTx(const std::string& base64_psbt) const {
  auto psbtx = DecodePsbt(base64_psbt);
  auto master_fingerprint = GetMasterFingerprint();
  FillableSigningProvider provider{};

  const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
  for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
    const PSBTInput& input = psbtx.inputs[i];
    if (!input.hd_keypaths.empty()) {
      for (auto entry : input.hd_keypaths) {
        if (master_fingerprint ==
            strprintf("%08x", ReadBE32(entry.second.fingerprint))) {
          auto path = WriteHDKeypath(entry.second.path);
          auto xkey = GetExtKeyAtPath(path);
          provider.AddKey(xkey.key);
        }
      }
    }
  }

  for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
    SignPSBTInput(provider, psbtx, i, &txdata);
  }
  return EncodePsbt(psbtx);
}

std::string SoftwareSigner::SignTaprootTx(const NunchukLocalDb& db,
                                          const std::string& base64_psbt,
                                          const Wallet& wallet,
                                          int external_index,
                                          int internal_index) {
  auto psbtx = DecodePsbt(base64_psbt);
  auto master_fingerprint = GetMasterFingerprint();
  FlatSigningProvider provider;

  std::string error;
  std::vector<CScript> output_scripts;
  auto addPath = [&](const std::string& path) {
    auto key = GetExtKeyAtPath(path);
    XOnlyPubKey internal_key(key.Neuter().pubkey);
    auto cpubkeys = internal_key.GetCPubKeys();
    for (auto&& fullpubkey : cpubkeys) {
      provider.keys[fullpubkey.GetID()] = key.key;
    }
  };

  std::set<std::string> input_addr;
  for (size_t i = 0; i < psbtx.inputs.size(); i++) {
    auto& input = psbtx.inputs[i];
    auto ctxout = input.witness_utxo;
    if (input.non_witness_utxo) {
      auto txIn = input.non_witness_utxo.get();
      auto txSpend = CMutableTransaction(*txIn);
      ctxout = txSpend.vout[psbtx.tx.value().vin[i].prevout.n];
    }
    if (ctxout.IsNull()) continue;
    CTxDestination address;
    ExtractDestination(ctxout.scriptPubKey, address);
    input_addr.insert(EncodeDestination(address));
  }
  std::set<std::string> basepaths;
  auto external_desc = wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL);
  auto desc0 = Parse(external_desc, provider, error, true);
  if (external_index < 0) external_index = 0;
  auto external_addr = CoreUtils::getInstance().DeriveAddresses(
      external_desc, 0, external_index);
  std::set<std::string> external_basepaths;
  for (auto&& signer : wallet.get_signers()) {
    if (signer.get_master_fingerprint() == master_fingerprint) {
      basepaths.insert(signer.get_derivation_path());
      external_basepaths.insert(
          signer.get_derivation_path() + "/" +
          std::to_string(signer.get_external_internal_index().first) + "/");
    }
  }
  for (int i = 0; i <= external_index; i++) {
    if (!input_addr.contains(external_addr[i])) continue;
    desc0.front()->Expand(i, provider, output_scripts, provider);
    for (auto&& basepath : external_basepaths) {
      addPath(basepath + std::to_string(i));
    }
  }
  auto internal_desc = wallet.get_descriptor(DescriptorPath::INTERNAL_ALL);
  auto desc1 = Parse(internal_desc, provider, error, true);
  if (internal_index < 0) internal_index = 0;
  auto internal_addr = CoreUtils::getInstance().DeriveAddresses(
      internal_desc, 0, internal_index);
  std::set<std::string> internal_basepaths;
  for (auto&& signer : wallet.get_signers()) {
    if (signer.get_master_fingerprint() == master_fingerprint) {
      internal_basepaths.insert(
          signer.get_derivation_path() + "/" +
          std::to_string(signer.get_external_internal_index().second) + "/");
    }
  }
  for (int i = 0; i <= internal_index; i++) {
    if (!input_addr.contains(internal_addr[i])) continue;
    desc1.front()->Expand(i, provider, output_scripts, provider);
    for (auto&& basepath : internal_basepaths) {
      addPath(basepath + std::to_string(i));
    }
  }

  for (auto&& basepath : basepaths) {
    addPath(basepath);
  }

  std::map<uint256, MuSig2SecNonce> musig2_secnonces{};
  provider.musig2_secnonces = &musig2_secnonces;

  const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
  const CMutableTransaction& tx = *psbtx.tx;
  // bool preferScriptPath = db.IsPreferScriptPath(tx.GetHash().GetHex());
  for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
    const PSBTInput& input = psbtx.inputs[i];

    for (const auto& [agg_lh, part_pubnonce] : input.m_musig2_pubnonces) {
      const auto& [agg, lh] = agg_lh;
      for (const auto& [part, pubnonce] : part_pubnonce) {
        if (input.m_musig2_partial_sigs.count(agg_lh)) {
          auto partial_sigs = input.m_musig2_partial_sigs.at(agg_lh);
          if (partial_sigs.count(part)) continue;
        }
        SigVersion sigversion =
            lh.IsNull() ? SigVersion::TAPROOT : SigVersion::TAPSCRIPT;
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        // Only support annex-less signing for now.
        execdata.m_annex_present = false;

        if (sigversion == SigVersion::TAPSCRIPT) {
          execdata.m_codeseparator_pos_init = true;
          // Only support non-OP_CODESEPARATOR BIP342 signing for now.
          execdata.m_codeseparator_pos = 0xFFFFFFFF;
          execdata.m_tapleaf_hash_init = true;
          execdata.m_tapleaf_hash = lh;
        }
        uint256 hash;
        SignatureHashSchnorr(hash, execdata, tx, i, SIGHASH_DEFAULT, sigversion,
                             txdata, MissingDataBehavior::FAIL);

        HashWriter hasher;
        hasher << agg << part << hash;
        uint256 session_id = hasher.GetSHA256();

        XOnlyPubKey xpart(part);
        std::string pubkey = HexStr(xpart);
        for (const auto& [xonly, leaf_origin] : input.m_tap_bip32_paths) {
          const auto& [leaf_hashes, origin] = leaf_origin;
          std::string xfp = strprintf("%08x", ReadBE32(origin.fingerprint));
          if (xfp == master_fingerprint && HexStr(xonly) == pubkey) {
            musig2_secnonces.emplace(session_id,
                                     db.GetMuSig2SecNonce(session_id));
          }
        }
      }
    }

    SignatureData sigdata;
    psbtx.inputs[i].FillSignatureData(sigdata);
    SignPSBTInput(provider, psbtx, i, &txdata, SIGHASH_DEFAULT, nullptr, false);

    for (auto&& [session_id, secnonce] : musig2_secnonces) {
      db.SetMuSig2SecNonce(session_id, std::move(secnonce));
    }
    musig2_secnonces.clear();
  }
  return EncodePsbt(psbtx);
}

std::string SoftwareSigner::SignMessage(const std::string& message,
                                        const std::string& path) const {
  std::string signature;
  auto xkey = GetExtKeyAtPath(path);
  MessageSign(xkey.key, message, signature);
  return signature;
}

CExtKey SoftwareSigner::GetBip32RootKey(const std::string& mnemonic,
                                        const std::string& passphrase) const {
  uint8_t seed[512 / 8];
  try {
    std::scoped_lock<std::mutex> lock(*mu_);
    mnemonic_to_seed(mnemonic.c_str(), passphrase.c_str(), seed, nullptr);
  } catch (std::exception& e) {
    // TODO: find out why
    mnemonic_to_seed(mnemonic.c_str(), passphrase.c_str(), seed, nullptr);
  }

  std::vector<std::byte> spanSeed;
  for (size_t i = 0; i < 64; i++) spanSeed.push_back(std::byte{seed[i]});
  CExtKey bip32rootkey;
  bip32rootkey.SetSeed(spanSeed);
  return bip32rootkey;
}

}  // namespace nunchuk
