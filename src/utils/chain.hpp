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

#ifndef NUNCHUK_CHAIN_H
#define NUNCHUK_CHAIN_H

#include "base58.h"
#include "nunchuk.h"

namespace nunchuk {
inline std::string ConvertXprvChain(const std::string &xprv, Chain target) {
  static constexpr unsigned char BASE58_MAINNET_PRIV_PREFIX[] = {0x04, 0x88,
                                                                 0xAD, 0xE4};
  static constexpr unsigned char BASE58_TESTNET_PRIV_PREFIX[] = {0x04, 0x35,
                                                                 0x83, 0x94};
  std::vector<unsigned char> data;
  if (!DecodeBase58Check(xprv, data, 78) || data.size() < 4) {
    throw NunchukException(NunchukException::INVALID_FORMAT,
                           "Invalid backup data");
  }
  if (target == Chain::MAIN) {
    std::copy(BASE58_MAINNET_PRIV_PREFIX, BASE58_MAINNET_PRIV_PREFIX + 4,
              data.begin());
  } else {
    std::copy(BASE58_TESTNET_PRIV_PREFIX, BASE58_TESTNET_PRIV_PREFIX + 4,
              data.begin());
  }
  return EncodeBase58Check(data);
}
}  // namespace nunchuk

#endif
