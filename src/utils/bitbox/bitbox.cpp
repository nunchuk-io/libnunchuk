/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
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

#include "utils/bitbox/bitbox.hpp"

#include <cstdint>
#include <key_io.h>
#include <stdexcept>
#include <util/bip32.h>

#include "utils/bip32.hpp"
#include "utils/bitbox/bitcoin.hpp"

namespace nunchuk::bitbox {

std::string GetBitBoxSignMessagePath(const SingleSigner& signer) {
  auto keypath = ParseKeypath(signer.get_derivation_path());
  const auto bip32_type = GetBip32Type(WriteHDKeypath(keypath));
  if (bip32_type != "bip49" && bip32_type != "bip84") {
    throw std::invalid_argument(
        "BitBox message signing supports BIP49 and BIP84 paths only");
  }
  if (keypath.size() != 3) {
    throw std::invalid_argument(
        "BitBox message signing requires an account path");
  }

  constexpr uint32_t hardened = uint32_t{1} << 31;
  if (keypath[1] != hardened && keypath[1] != hardened + 1) {
    throw std::invalid_argument(
        "BitBox message signing supports Bitcoin paths only");
  }
  if (keypath[2] < hardened || keypath[2] > hardened + 99) {
    throw std::invalid_argument(
        "BitBox message signing account must be between 0h and 99h");
  }

  keypath.push_back(0);
  keypath.push_back(0);
  return WriteHDKeypath(keypath);
}

std::string GetBitBoxSignMessageAddress(const SingleSigner& signer) {
  const auto keypath = ParseKeypath(GetBitBoxSignMessagePath(signer));

  auto xpub = DecodeExtPubKey(signer.get_xpub());
  if (!xpub.pubkey.IsFullyValid()) {
    throw std::invalid_argument("BitBox signer xpub is invalid");
  }
  if (!xpub.Derive(xpub, keypath[3]) ||
      !xpub.Derive(xpub, keypath[4])) {
    throw std::invalid_argument(
        "Could not derive the BitBox message-signing address");
  }
  return EncodeDestination(PKHash(xpub.pubkey.GetID()));
}

}  // namespace nunchuk::bitbox
