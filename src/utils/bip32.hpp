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

#ifndef NUNCHUK_BIP32_H
#define NUNCHUK_BIP32_H

#include <nunchuk.h>

#include <boost/format.hpp>
#include <iomanip>
#include <regex>
#include <string>
#include <vector>

namespace {

static const int SINGLESIG_BIP48_CACHE_NUMBER = 1;
static const int SINGLESIG_BIP49_CACHE_NUMBER = 1;
static const int SINGLESIG_BIP84_CACHE_NUMBER = 3;
static const int MULTISIG_CACHE_NUMBER = 3;
static const int ESCROW_CACHE_NUMBER = 1;
static const int TOTAL_CACHE_NUMBER =
    SINGLESIG_BIP48_CACHE_NUMBER + SINGLESIG_BIP49_CACHE_NUMBER +
    SINGLESIG_BIP84_CACHE_NUMBER + MULTISIG_CACHE_NUMBER + ESCROW_CACHE_NUMBER;

static const std::string TESTNET_HEALTH_CHECK_PATH = "m/45'/1'/0'/1/0";
static const std::string MAINNET_HEALTH_CHECK_PATH = "m/45'/0'/0'/1/0";

inline std::string GetBip32Path(nunchuk::Chain chain,
                         const nunchuk::WalletType& wallet_type,
                         const nunchuk::AddressType& address_type, int index) {
  using namespace nunchuk;

  int coin_type = chain == Chain::TESTNET ? 1 : 0;
  switch (wallet_type) {
    case WalletType::SINGLE_SIG:
      switch (address_type) {
        case AddressType::LEGACY:
          // Single-sig BIP44 Wallets: m/44h/ch/xh, c = coin, x = index
          return boost::str(boost::format{"m/44h/%dh/%dh"} % coin_type % index);
        case AddressType::NESTED_SEGWIT:
          // Single-sig BIP49 Wallets: m/49h/ch/yh, c = coin, y = index
          return boost::str(boost::format{"m/49h/%dh/%dh"} % coin_type % index);
        case AddressType::NATIVE_SEGWIT:
          // Single-sig BIP84 Wallets: m/84h/ch/zh, c = coin, z = index
          return boost::str(boost::format{"m/84h/%dh/%dh"} % coin_type % index);
        default:
          throw NunchukException(NunchukException::INVALID_ADDRESS_TYPE,
                                 "invalid address type");
      }
      break;
    case WalletType::MULTI_SIG:
      if (index == 0)
        throw NunchukException(
            NunchukException::INVALID_PARAMETER,
            "multisig account index 0 is reserved for escrow wallets");
      // Multi-sig BIP48 Wallets: m/48h/ch/ph, c = coin, p = index, p != 0
      return boost::str(boost::format{"m/48h/%dh/%dh"} % coin_type % index);
    case WalletType::ESCROW:
      // Multi-sig Escrow Wallets: m/48h/ch/0h/qh, c = coin, q = index
      return boost::str(boost::format{"m/48h/%dh/0h/%dh"} % coin_type % index);
  }
  throw NunchukException(NunchukException::INVALID_WALLET_TYPE,
                         "invalid wallet type");
}

inline std::string GetBip32Type(const std::string& path) {
  if (path.rfind("m/44h/", 0) == 0) return "bip44";
  if (path.rfind("m/49h/", 0) == 0) return "bip49";
  if (path.rfind("m/84h/", 0) == 0) return "bip84";
  if (path.rfind("m/48h/0h/0h", 0) == 0 || path.rfind("m/48h/1h/0h", 0) == 0) return "escrow";
  if (path.rfind("m/48h/", 0) == 0) return "bip48";
  return "custom";
}

inline std::string GetBip32Type(const nunchuk::WalletType& wallet_type,
                         const nunchuk::AddressType& address_type) {
  using namespace nunchuk;

  switch (wallet_type) {
    case WalletType::SINGLE_SIG:
      switch (address_type) {
        case AddressType::LEGACY:
          return "bip44";
        case AddressType::NESTED_SEGWIT:
          return "bip49";
        case AddressType::NATIVE_SEGWIT:
          return "bip84";
        default:
          throw NunchukException(NunchukException::INVALID_ADDRESS_TYPE,
                                 "invalid address type");
      }
      break;
    case WalletType::MULTI_SIG:
      return "bip48";
    case WalletType::ESCROW:
      return "escrow";
  }
  throw NunchukException(NunchukException::INVALID_WALLET_TYPE,
                         "invalid wallet type");
}

inline int GetIndexFromPath(const std::string& path) {
  std::size_t last = path.find_last_of("/");
  return std::stoi(path.substr(last + 1));
}

}  // namespace

#endif  //  NUNCHUK_BIP32_H
