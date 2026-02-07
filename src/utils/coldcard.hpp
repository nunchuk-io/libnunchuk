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

#include <utils/json.hpp>
#include "nunchuk.h"
#include "utils/rfc2440.hpp"

using json = nlohmann::json;
namespace nunchuk {

inline std::string GenerateColdCardHealthCheckMessage(
    const std::string& derivation_path,
    const std::string& message = Utils::GenerateHealthCheckMessage(),
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

  json out = {
      {"msg", message},
      {"subpath", derivation_path},
      {"addr_fmt", address_type_to_str(address_type)},
  };
  return out.dump();
}

struct ColdcardBackupData {
  std::string mnemonic;
  std::string xprv;
};

ColdcardBackupData ExtractColdcardBackup(const std::vector<unsigned char>& data,
                                         const std::string& password);

}  // namespace nunchuk

#endif
