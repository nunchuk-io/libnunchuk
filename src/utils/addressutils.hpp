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

#ifndef NUNCHUK_ADDRESSUTILS_H
#define NUNCHUK_ADDRESSUTILS_H

#include <nunchuk.h>
#include <util/strencodings.h>
#include <crypto/sha256.h>
#include <script/standard.h>
#include <key_io.h>
#include <core_io.h>

#include <string>
#include <vector>

namespace {

inline std::string AddressToScriptPubKey(const std::string& address) {
  using namespace nunchuk;
  CTxDestination dest = DecodeDestination(address);
  if (!IsValidDestination(dest)) {
    throw NunchukException(NunchukException::INVALID_ADDRESS,
                            "invalid address");
  }
  CScript scriptPubKey = GetScriptForDestination(dest);
  return HexStr(scriptPubKey);
}

inline std::string ScriptPubKeyToAddress(const CScript& script) {
  std::vector<std::vector<unsigned char>> solns;
  TxoutType type = Solver(script, solns);
  CTxDestination address;
  if (ExtractDestination(script, address) && type != TxoutType::PUBKEY) {
    return EncodeDestination(address);
  }
  return "";
}

inline std::string ScriptPubKeyToAddress(const std::string& script_pub_key) {
  CScript script;
  auto spk = ParseHex(script_pub_key);
  script.insert(script.end(), spk.begin(), spk.end());
  return ScriptPubKeyToAddress(script);
}

inline std::string AddressToScriptHash(const std::string& address) {
  CSHA256 hasher;
  auto stream = ParseHex(AddressToScriptPubKey(address));
  hasher.Write((unsigned char*)&(*stream.begin()),
               stream.end() - stream.begin());
  uint256 scripthash;
  hasher.Finalize(scripthash.begin());
  return scripthash.GetHex();
}

}  // namespace

#endif  //  NUNCHUK_ADDRESSUTILS_H
