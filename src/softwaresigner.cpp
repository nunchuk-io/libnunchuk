// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "softwaresigner.h"

#include <iostream>
#include <sstream>
#include <iomanip>

#include <utils/txutils.hpp>

#include <key_io.h>
#include <random.h>
#include <util/message.h>
#include <util/bip32.h>
#include <script/signingprovider.h>

extern "C" {
#include <bip39.h>
#include <bip39_english.h>
void random_buffer(uint8_t* buf, size_t len) { GetStrongRandBytes(buf, len); }
}

namespace nunchuk {

std::string hexStr(const uint8_t* data, int len) {
  std::stringstream ss;
  ss << std::hex;

  for (int i(0); i < len; ++i)
    ss << std::setw(2) << std::setfill('0') << (int)data[i];

  return ss.str();
}

std::string SoftwareSigner::GenerateMnemonic() {
  return std::string(mnemonic_generate(256));
}

bool SoftwareSigner::CheckMnemonic(const std::string& mnemonic) {
  return mnemonic_check(mnemonic.c_str());
}

std::vector<std::string> SoftwareSigner::GetBip39WordList() {
  std::vector<std::string> list{};
  for (auto&& word : wordlist) {
    if (word) list.push_back(word);
  }
  return list;
}

SoftwareSigner::SoftwareSigner(const std::string& mnemonic,
                               const std::string& passphrase)
    : bip32rootkey_(GetBip32RootKey(mnemonic, passphrase)) {}

CExtKey SoftwareSigner::GetExtKeyAtPath(const std::string& path) const {
  std::vector<uint32_t> keypath;
  std::string formalized = path;
  std::replace(formalized.begin(), formalized.end(), 'h', '\'');
  if (!ParseHDKeypath(formalized, keypath)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "invalid hd keypath");
  }

  CExtKey xkey = bip32rootkey_;
  for (auto&& i : keypath) {
    xkey.Derive(xkey, i);
  }
  return xkey;
}

std::string SoftwareSigner::GetXpubAtPath(const std::string& path) const {
  auto xkey = GetExtKeyAtPath(path);
  return EncodeExtPubKey(xkey.Neuter());
}

std::string SoftwareSigner::GetMasterFingerprint() const {
  CExtKey masterkey{};
  bip32rootkey_.Derive(masterkey, 0);
  return hexStr(masterkey.vchFingerprint, 4);
}

std::string SoftwareSigner::SignTx(const std::string& base64_psbt) const {
  auto psbtx = DecodePsbt(base64_psbt);
  auto master_fingerprint = GetMasterFingerprint();
  FillableSigningProvider provider{};

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
    SignPSBTInput(provider, psbtx, i);
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
  mnemonic_to_seed(mnemonic.c_str(), passphrase.c_str(), seed, nullptr);
  CExtKey bip32rootkey{};
  bip32rootkey.SetSeed(seed, 512 / 8);
  return bip32rootkey;
}

}  // namespace nunchuk
