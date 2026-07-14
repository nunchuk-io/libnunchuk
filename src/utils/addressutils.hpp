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
#include <script/solver.h>
#include <key_io.h>
#include <core_io.h>
#include <liquid/wallyutils.hpp>
#include <liquid/wallysigner.hpp>
#include <coreutils.h>
#include <string>
#include <vector>

namespace {

inline CScript AddressToCScriptPubKey(const std::string& address) {
  using namespace nunchuk;
  CTxDestination dest = DecodeDestination(address);
  if (!IsValidDestination(dest)) {
    throw NunchukException(NunchukException::INVALID_ADDRESS,
                           "Invalid address");
  }
  return GetScriptForDestination(dest);
}

inline std::string AddressToScriptPubKey(const std::string& address) {
  return HexStr(AddressToCScriptPubKey(address));
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

inline std::string DeriveAddress(
    const std::string& descriptor,
    const std::shared_ptr<nunchuk::wally::WallySigner>& signer,
    const std::string& path, uint32_t idx, bool internal) {
  using namespace nunchuk;
  if (!descriptor.empty()) {
    return CoreUtils::getInstance().DeriveAddress(descriptor, idx);
  } else if (!signer) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Liquid wallet signer is not available");
  }
  auto details = signer->CacheAddresses(path, idx, idx + 1, internal);
  if (details.empty()) {
    throw NunchukException(NunchukException::INVALID_ADDRESS,
                           "Failed to derive Liquid address");
  }
  return details[0].address;
};

inline std::string AddressToScriptHash(const std::string& address) {
  using namespace nunchuk::wally;
  CSHA256 hasher;
  std::vector<unsigned char> spk;
  if (address.find(std::string(WallyUtils::C().ADDRESS_FAMILY)) == 0) {
    spk = WallyUtils::GetScriptPubkeyFromAddress(address);
  } else if (address.find(std::string(
                 WallyUtils::C().CONFIDENTIAL_ADDRESS_FAMILY)) == 0) {
    spk = WallyUtils::GetScriptPubkeyFromConfidentialAddress(address);
  } else {
    spk = ParseHex(AddressToScriptPubKey(address));
  }
  hasher.Write((unsigned char*)&(*spk.begin()), spk.end() - spk.begin());
  uint256 scripthash;
  hasher.Finalize(scripthash.begin());
  return scripthash.GetHex();
}

}  // namespace

#endif  //  NUNCHUK_ADDRESSUTILS_H
