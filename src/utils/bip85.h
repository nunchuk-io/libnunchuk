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

#ifndef NUNCHUK_BIP85_H
#define NUNCHUK_BIP85_H

#include <nunchuk.h>

#include <key.h>
#include <string>
#include <vector>

namespace nunchuk {

static const std::string BIP85_HASH_KEY = "bip-entropy-from-k";

class Bip85 {
 public:
  Bip85(const std::string &mnemonic, const std::string &passphrase);
  Bip85(const std::string &master_xprv);

  CExtKey GetExtKeyAtPath(const std::string &derivation_path) const;
  std::string GetMagicWords(int index) const;
  std::string GetMnemonic(int index, int words = 24) const;
  std::vector<uint8_t> GetHex(int len, int index) const;
  std::vector<uint8_t> DRNG(const std::string &path, int len) const;

 private:
  CExtKey GetBip32RootKey(const std::string &mnemonic,
                          const std::string &passphrase) const;
  CExtKey bip32rootkey_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_BIP85_H
