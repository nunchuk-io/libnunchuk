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

#include <key_io.h>
#include <random.h>
#include <util/message.h>
#include <util/bip32.h>
#include <script/signingprovider.h>
#include <rpc/util.h>
#include <descriptor.h>

extern "C" {
#include <bip39.h>
#include <bip39_english.h>
void random_buffer(uint8_t* buf, size_t len) {
  // Core's GetStrongRandBytes
  // https://github.com/bitcoin/bitcoin/commit/6e6b3b944d12a252a0fd9a1d68fec9843dd5b4f8
  Span<unsigned char> bytes(buf, len);
  GetStrongRandBytes(bytes);
}
}

namespace nunchuk {

std::map<uint256, MuSig2SecNonce> m_musig2_secnonces{};

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

std::string SoftwareSigner::SignTaprootTx(const std::string& base64_psbt,
                                          const std::string& basepath,
                                          const std::string& external_desc,
                                          const std::string& internal_desc,
                                          int external_index,
                                          int internal_index) const {
  auto psbtx = DecodePsbt(base64_psbt);
  auto master_fingerprint = GetMasterFingerprint();
  FlatSigningProvider provider;
  provider.musig2_secnonces = &m_musig2_secnonces;

  std::string error;
  std::vector<CScript> output_scripts;
  auto addPath = [&](const std::string& path) {
    auto key = GetExtKeyAtPath(path);
    XOnlyPubKey internal_key(key.Neuter().pubkey);
    auto cpubkeys = internal_key.GetCPubKeys();
    for (auto && fullpubkey: cpubkeys) {
        provider.keys[fullpubkey.GetID()] = key.key;
    }
  };

  auto desc0 = Parse(external_desc, provider, error, true);
  for (int i = 0; i <= external_index; i++) {
    desc0->Expand(i, provider, output_scripts, provider);
    addPath(basepath + "/0/" + std::to_string(i));
  }
  auto desc1 = Parse(internal_desc, provider, error, true);
  for (int i = 0; i <= internal_index; i++) {
    desc1->Expand(i, provider, output_scripts, provider);
    addPath(basepath + "/1/" + std::to_string(i));
  }

  const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
  for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
    SignatureData sigdata;
    psbtx.inputs[i].FillSignatureData(sigdata);
    SignPSBTInput(provider, psbtx, i, &txdata, SIGHASH_DEFAULT);
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
