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

#ifndef NUNCHUK_UNCHAINED_H
#define NUNCHUK_UNCHAINED_H

#include <string>
#include "nunchuk.h"
#include "utils/bip32.hpp"

namespace nunchuk {
bool ParseUnchainedWallet(const std::string& content, std::string& name,
                          AddressType& address_type, WalletType& wallet_type,
                          int& m, int& n, std::vector<SingleSigner>& signers) {
  name.clear();
  address_type = AddressType::LEGACY;
  wallet_type = WalletType::MULTI_SIG;
  m = 0;
  n = 0;
  signers.clear();

  try {
    const json j = json::parse(content);
    name = j["name"];
    address_type = GetAddressTypeFromStr(j["addressType"]);
    n = j["quorum"]["totalSigners"];
    m = j["quorum"]["requiredSigners"];
    for (auto&& signer : j["extendedPublicKeys"]) {
      signers.emplace_back(SingleSigner(
          signer["name"], signer["xpub"], {}, signer["bip32Path"],
          signer["xfp"], std::time(nullptr), {}, false, SignerType::AIRGAP));
    }
    signers = Utils::SanitizeSingleSigners(signers);
    if (n <= 0) n = signers.size();
    if (m <= 0) m = n;
    if (name.empty()) {
      std::stringstream s;
      s << "ImportedWallet-" << m << "of" << n;
      name = s.str();
    }
    if (n <= 0 || m <= 0 || m > n || n != signers.size()) {
      return false;
    }
  } catch (...) {
    return false;
  }
  return true;
}
}  // namespace nunchuk

#endif
