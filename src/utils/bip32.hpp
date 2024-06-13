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

#include <boost/algorithm/string/predicate.hpp>
#include <boost/format.hpp>
#include <tinyformat.h>
#include <iomanip>
#include <regex>
#include <string>
#include <vector>

namespace {

static const int SINGLESIG_BIP44_CACHE_NUMBER = 1;
static const int SINGLESIG_BIP49_CACHE_NUMBER = 1;
static const int SINGLESIG_BIP84_CACHE_NUMBER = 3;
static const int SINGLESIG_BIP86_CACHE_NUMBER = 3;
static const int MULTISIG_BIP45_CACHE_NUMBER = 1;
static const int MULTISIG_BIP48_1_CACHE_NUMBER = 1;
static const int MULTISIG_BIP48_2_CACHE_NUMBER = 3;
static const int ESCROW_CACHE_NUMBER = 1;
static const int TOTAL_CACHE_NUMBER =
    SINGLESIG_BIP44_CACHE_NUMBER + SINGLESIG_BIP49_CACHE_NUMBER +
    SINGLESIG_BIP84_CACHE_NUMBER + SINGLESIG_BIP86_CACHE_NUMBER +
    MULTISIG_BIP45_CACHE_NUMBER + MULTISIG_BIP48_1_CACHE_NUMBER +
    MULTISIG_BIP48_2_CACHE_NUMBER + ESCROW_CACHE_NUMBER;

static const std::string TESTNET_HEALTH_CHECK_PATH = "m/45'/1'/0'/1/0";
static const std::string MAINNET_HEALTH_CHECK_PATH = "m/45'/0'/0'/1/0";
static const std::string LOGIN_SIGNING_PATH = "m/45'/0'/0'/1/0";

static const int ESCROW_ACCOUNT_INDEX = 9999;

inline std::string GetBip32Path(nunchuk::Chain chain,
                                const nunchuk::WalletType& wallet_type,
                                const nunchuk::AddressType& address_type,
                                int index) {
  using namespace nunchuk;

  int coin_type = chain == Chain::MAIN ? 0 : 1;
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
        case AddressType::TAPROOT:
          // Single-sig BIP86 Wallets: m/86h/ch/zh, c = coin, z = index
          return boost::str(boost::format{"m/86h/%dh/%dh"} % coin_type % index);
        default:
          throw NunchukException(NunchukException::INVALID_ADDRESS_TYPE,
                                 "Invalid address type");
      }
    case WalletType::MULTI_SIG:
      if (index == ESCROW_ACCOUNT_INDEX)
        throw NunchukException(
            NunchukException::INVALID_PARAMETER,
            strprintf(
                "Multisig account index %d is reserved for escrow wallets",
                ESCROW_ACCOUNT_INDEX));
      switch (address_type) {
        case AddressType::LEGACY:
          // Legacy Multi-sig BIP45 Wallets: m/45h
          return "m/45h";
        case AddressType::NESTED_SEGWIT:
          // Nested Segwit Multi-sig BIP48 Wallets: m/48h/ch/yh/1h
          return boost::str(boost::format{"m/48h/%dh/%dh/1h"} % coin_type %
                            index);
        case AddressType::NATIVE_SEGWIT:
          // Native Segwit Multi-sig BIP48 Wallets: m/48h/ch/zh/2h
          return boost::str(boost::format{"m/48h/%dh/%dh/2h"} % coin_type %
                            index);
        case AddressType::TAPROOT:
          // Taproot Multi-sig BIP48 Wallets: m/48h/ch/zh/2h
          return boost::str(boost::format{"m/48h/%dh/%dh/2h"} % coin_type %
                            index);
        default:
          throw NunchukException(NunchukException::INVALID_ADDRESS_TYPE,
                                 "Invalid address type");
      }
    case WalletType::ESCROW:
      // Multi-sig Escrow Wallets: m/48h/ch/9999h/qh, c = coin, q = index
      return boost::str(boost::format{"m/48h/%dh/%dh/%dh"} % coin_type %
                        ESCROW_ACCOUNT_INDEX % index);
  }
  throw NunchukException(NunchukException::INVALID_WALLET_TYPE,
                         "Invalid wallet type");
}

inline std::string GetBip32Type(const std::string& path) {
  if (boost::algorithm::starts_with(path, "m/44h")) return "bip44";
  if (boost::algorithm::starts_with(path, "m/45h")) return "bip45";
  if (boost::algorithm::starts_with(path, "m/49h")) return "bip49";
  if (boost::algorithm::starts_with(path, "m/84h")) return "bip84";
  if (boost::algorithm::starts_with(path, "m/86h")) return "bip86";
  if (boost::algorithm::starts_with(
          path, strprintf("m/48h/0h/%dh", ESCROW_ACCOUNT_INDEX)) ||
      boost::algorithm::starts_with(
          path, strprintf("m/48h/1h/%dh", ESCROW_ACCOUNT_INDEX)))
    return "escrow";
  if (boost::algorithm::starts_with(path, "m/48h")) {
    if (boost::algorithm::ends_with(path, "1h")) return "bip48_1";
    if (boost::algorithm::ends_with(path, "2h")) return "bip48_2";
  }
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
        case AddressType::TAPROOT:
          return "bip86";
        default:
          throw NunchukException(NunchukException::INVALID_ADDRESS_TYPE,
                                 "Invalid address type");
      }
    case WalletType::MULTI_SIG:
      switch (address_type) {
        case AddressType::LEGACY:
          return "bip45";
        case AddressType::NESTED_SEGWIT:
          return "bip48_1";
        case AddressType::NATIVE_SEGWIT:
          return "bip48_2";
        case AddressType::TAPROOT:
          return "bip48_2";
        default:
          throw NunchukException(NunchukException::INVALID_ADDRESS_TYPE,
                                 "Invalid address type");
      }
    case WalletType::ESCROW:
      return "escrow";
  }
  throw NunchukException(NunchukException::INVALID_WALLET_TYPE,
                         "Invalid wallet type");
}

inline int GetIndexFromPath(const nunchuk::WalletType& wallet_type,
                            const nunchuk::AddressType& address_type,
                            const std::string& path) {
  if (wallet_type == nunchuk::WalletType::MULTI_SIG) {
    if (address_type == nunchuk::AddressType::LEGACY) return 0;
    return std::stoi(path.substr(9, path.size() - 3));
  }
  std::size_t last = path.find_last_of("/");
  return std::stoi(path.substr(last + 1));
}

inline int GetIndexFromPath(const std::string& path) {
  auto bip32type = GetBip32Type(path);
  if ("bip45" == bip32type || "custom" == bip32type) return -1;
  if ("bip48_1" == bip32type || "bip48_2" == bip32type) {
    return std::stoi(path.substr(9, path.size() - 3));
  }
  std::size_t last = path.find_last_of("/");
  return std::stoi(path.substr(last + 1));
}

inline nunchuk::AddressType GetAddressTypeFromStr(const std::string& str) {
  if (boost::iequals(str, "p2sh")) {
    return nunchuk::AddressType::LEGACY;
  }
  if (boost::iequals(str, "p2wsh")) {
    return nunchuk::AddressType::NATIVE_SEGWIT;
  }
  if (boost::iequals(str, "p2wsh-p2sh") || boost::iequals(str, "p2sh-p2wsh")) {
    return nunchuk::AddressType::NESTED_SEGWIT;
  }
  if (boost::iequals(str, "p2tr")) {
    return nunchuk::AddressType::TAPROOT;
  }
  throw nunchuk::NunchukException(
      nunchuk::NunchukException::INVALID_ADDRESS_TYPE, "Invalid address type");
}

}  // namespace

#endif  //  NUNCHUK_BIP32_H
