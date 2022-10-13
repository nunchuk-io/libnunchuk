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

#ifndef NUNCHUK_COLDCARD_H
#define NUNCHUK_COLDCARD_H

#include <regex>
#include "nunchuk.h"

namespace nunchuk {

struct BitcoinSignedMessage {
  std::string message;
  std::string address;
  std::string signature;

  BitcoinSignedMessage() = default;
  BitcoinSignedMessage(std::string message, std::string address,
                       std::string signature)
      : message(std::move(message)),
        address(std::move(address)),
        signature(std::move(signature)) {}
};

inline BitcoinSignedMessage ParseBitcoinSignedMessage(const std::string &str) {
  static const std::regex RFC2440_BITCOIN(
      "-----BEGIN BITCOIN SIGNED MESSAGE-----(\\r\\n|\\r|\\n)"
      "(.*)(\\r\\n|\\r|\\n)"
      "-----BEGIN {0,1}(BITCOIN){0,1} SIGNATURE-----(\\r\\n|\\r|\\n)"
      "(.*)(\\r\\n|\\r|\\n| )(.*)(\\r\\n|\\r|\\n)"
      "-----END BITCOIN SIGNED MESSAGE-----");

  std::smatch sm;
  if (!std::regex_search(str, sm, RFC2440_BITCOIN)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid bitcoin signed message");
  }

  if (sm.size() < 9) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid bitcoin signed message");
  }
  return BitcoinSignedMessage{sm[2].str(), sm[6].str(), sm[8].str()};
}

inline std::string GenerateColdCardHealthCheckMessage(
    const std::string &derivation_path,
    const std::string &message = Utils::GenerateHealthCheckMessage(),
    AddressType address_type = AddressType::LEGACY) {
  constexpr auto address_type_to_str = [](AddressType address_type) {
    switch (address_type) {
      case AddressType::LEGACY:
        return std::string("p2pkh");
      case AddressType::NATIVE_SEGWIT:
        return std::string("p2wpkh");
      case AddressType::NESTED_SEGWIT:
        return std::string("p2sh-p2wpkh");
      case AddressType::TAPROOT:
      case AddressType::ANY:
        throw NunchukException(NunchukException::INVALID_ADDRESS_TYPE,
                               "Not supported");
    }
  };

  return message + "\n" + derivation_path + "\n" +
         address_type_to_str(address_type);
}

}  // namespace nunchuk

#endif
