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
  switch (value) {
    case nunchuk::Chain::MAIN:
      return "MAIN";
    case nunchuk::Chain::SIGNET:
      return "SIGNET";
    case nunchuk::Chain::TESTNET:
      return "TESTNET";
    case nunchuk::Chain::REGTEST:
      return "REGTEST";
  }
}

inline nunchuk::Chain ChainFromStr(const std::string& value) {
  if (value == "MAIN") return nunchuk::Chain::MAIN;
  if (value == "SIGNET") return nunchuk::Chain::SIGNET;
  if (value == "TESTNET") return nunchuk::Chain::TESTNET;
  if (value == "REGTEST") return nunchuk::Chain::REGTEST;
  throw nunchuk::NunchukException(nunchuk::NunchukException::INVALID_CHAIN,
                                  "Invalid chain");
}

inline std::string AddressTypeToStr(nunchuk::AddressType value) {
  if (value == nunchuk::AddressType::LEGACY) return "LEGACY";
  if (value == nunchuk::AddressType::NESTED_SEGWIT) return "NESTED_SEGWIT";
  if (value == nunchuk::AddressType::TAPROOT) return "TAPROOT";
  return "NATIVE_SEGWIT";
}

inline nunchuk::AddressType AddressTypeFromStr(const std::string& value) {
  if (value == "LEGACY") return nunchuk::AddressType::LEGACY;
  if (value == "NESTED_SEGWIT") return nunchuk::AddressType::NESTED_SEGWIT;
  if (value == "NATIVE_SEGWIT") return nunchuk::AddressType::NATIVE_SEGWIT;
  if (value == "TAPROOT") return nunchuk::AddressType::TAPROOT;
  throw nunchuk::NunchukException(
      nunchuk::NunchukException::INVALID_ADDRESS_TYPE, "Invalid address type");
}

inline std::string SignerTypeToStr(nunchuk::SignerType value) {
  switch (value) {
    case nunchuk::SignerType::UNKNOWN:
      return "UNKNOWN";
    case nunchuk::SignerType::SOFTWARE:
      return "SOFTWARE";
    case nunchuk::SignerType::FOREIGN_SOFTWARE:
      return "FOREIGN_SOFTWARE";
    case nunchuk::SignerType::AIRGAP:
      return "AIRGAP";
    case nunchuk::SignerType::HARDWARE:
      return "HARDWARE";
    case nunchuk::SignerType::NFC:
      return "NFC";
    case nunchuk::SignerType::COLDCARD_NFC:
      return "COLDCARD_NFC";
    case nunchuk::SignerType::SERVER:
      return "SERVER";
  }

  throw nunchuk::NunchukException(
      nunchuk::NunchukException::INVALID_SIGNER_TYPE, "Invalid signer type");
}

inline nunchuk::SignerType SignerTypeFromStr(const std::string& value) {
  if (value == "UNKNOWN") return nunchuk::SignerType::UNKNOWN;
  if (value == "SOFTWARE") return nunchuk::SignerType::SOFTWARE;
  if (value == "FOREIGN_SOFTWARE") return nunchuk::SignerType::FOREIGN_SOFTWARE;
  if (value == "AIRGAP") return nunchuk::SignerType::AIRGAP;
  if (value == "HARDWARE") return nunchuk::SignerType::HARDWARE;
  if (value == "NFC") return nunchuk::SignerType::NFC;
  if (value == "COLDCARD_NFC") return nunchuk::SignerType::COLDCARD_NFC;
  if (value == "SERVER") return nunchuk::SignerType::SERVER;

  throw nunchuk::NunchukException(
      nunchuk::NunchukException::INVALID_SIGNER_TYPE, "Invalid signer type");
}

inline std::string SignerTagToStr(nunchuk::SignerTag tag) {
  switch (tag) {
    case nunchuk::SignerTag::INHERITANCE:
      return "INHERITANCE";
    case nunchuk::SignerTag::KEYSTONE:
      return "KEYSTONE";
    case nunchuk::SignerTag::JADE:
      return "JADE";
    case nunchuk::SignerTag::PASSPORT:
      return "PASSPORT";
    case nunchuk::SignerTag::SEEDSIGNER:
      return "SEEDSIGNER";
    case nunchuk::SignerTag::COLDCARD:
      return "COLDCARD";
    case nunchuk::SignerTag::TREZOR:
      return "TREZOR";
    case nunchuk::SignerTag::LEDGER:
      return "LEDGER";
  }
  throw nunchuk::NunchukException(nunchuk::NunchukException::INVALID_PARAMETER,
                                  "Invalid signer tag");
}

inline nunchuk::SignerTag SignerTagFromStr(const std::string& tag) {
  if (tag == "INHERITANCE") return nunchuk::SignerTag::INHERITANCE;
  if (tag == "KEYSTONE") return nunchuk::SignerTag::KEYSTONE;
  if (tag == "JADE") return nunchuk::SignerTag::JADE;
  if (tag == "PASSPORT") return nunchuk::SignerTag::PASSPORT;
  if (tag == "SEEDSIGNER") return nunchuk::SignerTag::SEEDSIGNER;
  if (tag == "COLDCARD") return nunchuk::SignerTag::COLDCARD;
  if (tag == "TREZOR") return nunchuk::SignerTag::TREZOR;
  if (tag == "LEDGER") return nunchuk::SignerTag::LEDGER;
  throw nunchuk::NunchukException(nunchuk::NunchukException::INVALID_PARAMETER,
                                  "Invalid signer tag");
}

inline std::string SlotStatusToStr(nunchuk::SatscardSlot::Status status) {
  switch (status) {
    case nunchuk::SatscardSlot::Status::UNUSED:
      return "UNUSED";
    case nunchuk::SatscardSlot::Status::SEALED:
      return "SEALED";
    case nunchuk::SatscardSlot::Status::UNSEALED:
      return "UNSEALED";
  }
  throw nunchuk::NunchukException(nunchuk::NunchukException::INVALID_PARAMETER,
                                  "Invalid slot status");
}

inline nunchuk::SatscardSlot::Status SlotStatusFromStr(
    const std::string& status) {
  if (status == "UNUSED") {
    return nunchuk::SatscardSlot::Status::UNUSED;
  }
  if (status == "SEALED") {
    return nunchuk::SatscardSlot::Status::SEALED;
  }
  if (status == "UNSEALED") {
    return nunchuk::SatscardSlot::Status::UNSEALED;
  }
  throw nunchuk::NunchukException(nunchuk::NunchukException::INVALID_PARAMETER,
                                  "Invalid slot status");
}

}  // namespace

#endif
