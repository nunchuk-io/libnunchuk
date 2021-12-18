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

#ifndef NUNCHUK_ENUMCONVERTER_H
#define NUNCHUK_ENUMCONVERTER_H

#include <nunchuk.h>

namespace {

inline std::string ChainToStr(nunchuk::Chain value) {
  if (value == nunchuk::Chain::TESTNET) return "TESTNET";
  if (value == nunchuk::Chain::REGTEST) return "REGTEST";
  return "MAIN";
}

inline nunchuk::Chain ChainFromStr(const std::string& value) {
  if (value == "TESTNET") return nunchuk::Chain::TESTNET;
  if (value == "REGTEST") return nunchuk::Chain::REGTEST;
  if (value == "MAIN") return nunchuk::Chain::MAIN;
  throw nunchuk::NunchukException(nunchuk::NunchukException::INVALID_CHAIN,
                                  "invalid chain");
}

inline std::string AddressTypeToStr(nunchuk::AddressType value) {
  if (value == nunchuk::AddressType::LEGACY) return "LEGACY";
  if (value == nunchuk::AddressType::NESTED_SEGWIT) return "NESTED_SEGWIT";
  return "NATIVE_SEGWIT";
}

inline nunchuk::AddressType AddressTypeFromStr(const std::string& value) {
  if (value == "LEGACY") return nunchuk::AddressType::LEGACY;
  if (value == "NESTED_SEGWIT") return nunchuk::AddressType::NESTED_SEGWIT;
  if (value == "NATIVE_SEGWIT") return nunchuk::AddressType::NATIVE_SEGWIT;
  throw nunchuk::NunchukException(
      nunchuk::NunchukException::INVALID_ADDRESS_TYPE, "invalid address type");
}

inline std::string SignerTypeToStr(nunchuk::SignerType value) {
  if (value == nunchuk::SignerType::SOFTWARE) return "SOFTWARE";
  if (value == nunchuk::SignerType::FOREIGN_SOFTWARE) return "FOREIGN_SOFTWARE";
  if (value == nunchuk::SignerType::AIRGAP) return "AIRGAP";
  return "HARDWARE";
}

inline nunchuk::SignerType SignerTypeFromStr(const std::string& value) {
  if (value == "SOFTWARE") return nunchuk::SignerType::SOFTWARE;
  if (value == "FOREIGN_SOFTWARE") return nunchuk::SignerType::FOREIGN_SOFTWARE;
  if (value == "AIRGAP") return nunchuk::SignerType::AIRGAP;
  if (value == "HARDWARE") return nunchuk::SignerType::HARDWARE;
  throw nunchuk::NunchukException(
      nunchuk::NunchukException::INVALID_SIGNER_TYPE, "invalid signer type");
}

}  // namespace

#endif