/*
 * This file is part of the Nunchuk software (https://nunchuk.io/)
 * Copyright (C) 2022, 2023 Nunchuk
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "bip85.h"

#include <iomanip>
#include <iostream>
#include <sstream>

#include <key_io.h>
#include <mutex>
#include <util/bip32.h>
#include <utils/stringutils.hpp>

extern "C" {
#include <bip39.h>
#include <hmac.h>
}

#include <boost/algorithm/hex.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace nunchuk {

Bip85::Bip85(const std::string &mnemonic, const std::string &passphrase)
    : bip32rootkey_(GetBip32RootKey(mnemonic, passphrase)) {}

Bip85::Bip85(const std::string &master_xprv)
    : bip32rootkey_(DecodeExtKey(master_xprv)) {
  if (!bip32rootkey_.key.IsValid()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid master xprv");
  }
}

CExtKey Bip85::GetBip32RootKey(const std::string &mnemonic,
                               const std::string &passphrase) const {
  static std::mutex mu;
  std::scoped_lock<std::mutex> lock(mu);

  uint8_t seed[512 / 8];
  mnemonic_to_seed(mnemonic.c_str(), passphrase.c_str(), seed, nullptr);

  std::vector<std::byte> spanSeed;
  for (size_t i = 0; i < 64; i++) spanSeed.push_back(std::byte{seed[i]});
  CExtKey bip32rootkey;
  bip32rootkey.SetSeed(spanSeed);
  return bip32rootkey;
}

CExtKey Bip85::GetExtKeyAtPath(const std::string &path) const {
  std::vector<uint32_t> keypath;
  std::string formalized = path;
  std::replace(formalized.begin(), formalized.end(), 'h', '\'');
  if (!ParseHDKeypath(formalized, keypath)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid hd keypath");
  }

  CExtKey xkey = bip32rootkey_;
  for (auto &&i : keypath) {
    CExtKey child;
    if (!xkey.Derive(child, i)) {
      throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                             "Invalid path");
    }
    xkey = child;
  }
  return xkey;
}

std::string Bip85::GetMagicWords(int index) const {
  auto mnemonic = split(GetMnemonic(index, index <= 500 ? 3 : 6), ' ');
  int n = index <= 500 ? 3 : 4;
  std::ostringstream magic;
  magic << mnemonic[0];
  for (int i = 1; i < n; i++) {
    magic << '-' << mnemonic[i];
  }
  return magic.str();
}

std::string Bip85::GetMnemonic(int index, int words) const {
  std::stringstream path;
  path << "m/83696968'/39'/0'/" << words << "'/" << index << "'";
  auto xkey = GetExtKeyAtPath(path.str());

  std::vector<uint8_t> key(BIP85_HASH_KEY.begin(), BIP85_HASH_KEY.end());
  std::vector<uint8_t> data((uint8_t *)xkey.key.begin(),
                            (uint8_t *)xkey.key.end());
  uint8_t hmac[512 / 8];
  hmac_sha512(&key[0], key.size(), &data[0], data.size(), hmac);
  return mnemonic_from_data(&hmac[0], words * 4 / 3);
}

static int SHAKE256(uint8_t *out, size_t outlen, const uint8_t *in,
                    size_t inlen) {
  EVP_MD_CTX *hashctx = EVP_MD_CTX_new();

  if (hashctx == NULL) return -1;

  if (!EVP_DigestInit_ex(hashctx, EVP_shake256(), NULL) ||
      !EVP_DigestUpdate(hashctx, in, inlen) ||
      !EVP_DigestFinalXOF(hashctx, out, outlen)) {
    EVP_MD_CTX_free(hashctx);
    return -1;
  }

  EVP_MD_CTX_free(hashctx);
  return 0;
}

std::vector<uint8_t> Bip85::DRNG(const std::string &path, int len) const {
  auto xkey = GetExtKeyAtPath(path);

  std::vector<uint8_t> key(BIP85_HASH_KEY.begin(), BIP85_HASH_KEY.end());
  std::vector<uint8_t> data((uint8_t *)xkey.key.begin(),
                            (uint8_t *)xkey.key.end());
  uint8_t hmac[512 / 8];
  hmac_sha512(&key[0], key.size(), &data[0], data.size(), hmac);

  std::vector<uint8_t> out(len);
  if (SHAKE256(out.data(), len, hmac, 64) < 0) {
    return {};
  }
  return out;
}

std::vector<uint8_t> Bip85::GetHex(int len, int index) const {
  if (len < 16 || len > 64) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, "Invalid len");
  }
  std::stringstream path;
  path << "m/83696968'/128169'/" << len << "'/" << index << "'";
  auto xkey = GetExtKeyAtPath(path.str());

  std::vector<uint8_t> key(BIP85_HASH_KEY.begin(), BIP85_HASH_KEY.end());
  std::vector<uint8_t> data((uint8_t *)xkey.key.begin(),
                            (uint8_t *)xkey.key.end());
  uint8_t hmac[512 / 8];
  hmac_sha512(&key[0], key.size(), &data[0], data.size(), hmac);
  std::vector<uint8_t> rs(hmac, hmac + len);
  return rs;
}

}  // namespace nunchuk
