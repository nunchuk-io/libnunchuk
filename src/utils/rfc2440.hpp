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

#ifndef NUNCHUK_RFC2440_H
#define NUNCHUK_RFC2440_H

#include <regex>
#include "nunchuk.h"
#include <tinyformat.h>

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

inline std::string ExportBitcoinSignedMessage(
    const BitcoinSignedMessage &signed_msg) {
  std::stringstream ss;
  ss << "-----BEGIN BITCOIN SIGNED MESSAGE-----\n"
     << signed_msg.message << "\n"
     << "-----BEGIN BITCOIN SIGNATURE-----\n"
     << signed_msg.address << "\n"
     << signed_msg.signature << "\n"
     << "-----END BITCOIN SIGNATURE-----";
  return ss.str();
}

inline BitcoinSignedMessage ParseBitcoinSignedMessage(const std::string &str) {
  static const std::regex RFC2440_BITCOIN(
      "-----BEGIN BITCOIN SIGNED MESSAGE-----(\\r\\n|\\r|\\n)"
      "(.*)(\\r\\n|\\r|\\n)"
      "-----BEGIN {0,1}(BITCOIN){0,1} SIGNATURE-----(\\r\\n|\\r|\\n)"
      "(.*)(\\r\\n|\\r|\\n| )(.*)(\\r\\n|\\r|\\n)"
      "-----END BITCOIN (SIGNED MESSAGE|SIGNATURE)-----");

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
}  // namespace nunchuk
#endif
