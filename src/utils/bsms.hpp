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

#ifndef NUNCHUK_BSMS_H
#define NUNCHUK_BSMS_H

#include <nunchuk.h>
#include <boost/algorithm/string.hpp>
#include <sstream>
#include <iostream>
#include <regex>

#include <descriptor.h>
#include <coreutils.h>
#include <utils/stringutils.hpp>

namespace {

inline std::string GetDescriptorRecord(const nunchuk::Wallet& wallet) {
  using namespace nunchuk;
  auto retrictpath = true;
  auto sorted = true;
  auto wallet_type =
      wallet.get_n() == 1
          ? WalletType::SINGLE_SIG
          : (wallet.is_escrow() ? WalletType::ESCROW : WalletType::MULTI_SIG);
  std::stringstream descriptor_record;
  descriptor_record << "BSMS 1.0" << std::endl;
  descriptor_record << GetDescriptorForSigners(
                           wallet.get_signers(), wallet.get_m(),
                           retrictpath ? DescriptorPath::TEMPLATE
                                       : DescriptorPath::ANY,
                           wallet.get_address_type(), wallet_type, 0, sorted)
                    << std::endl;
  descriptor_record << (retrictpath ? "/0/*,/1/*" : "No path restrictions")
                    << std::endl;
  bool escrow = wallet_type == WalletType::ESCROW;
  descriptor_record << CoreUtils::getInstance().DeriveAddresses(
      GetDescriptorForSigners(
          wallet.get_signers(), wallet.get_m(), DescriptorPath::EXTERNAL_ALL,
          wallet.get_address_type(), wallet_type, escrow ? -1 : 0, sorted),
      escrow ? -1 : 0);
  return descriptor_record.str();
}

inline bool ParseDescriptorRecord(const std::string bsms,
                                  nunchuk::AddressType& a,
                                  nunchuk::WalletType& w, int& m, int& n,
                                  std::vector<nunchuk::SingleSigner>& signers) {
  using namespace nunchuk;
  a = AddressType::LEGACY;
  w = WalletType::MULTI_SIG;
  m = 0;
  n = 0;
  std::istringstream content_stream(bsms);
  std::string line;
  if (!safeGetline(content_stream, line) || line != "BSMS 1.0") {
    return false; // Invalid BSMS version
  }
  if (!safeGetline(content_stream, line) ||
      !ParseDescriptors(line, a, w, m, n, signers)) {
    return false; // Invalid Descriptor template
  }
  if (!safeGetline(content_stream, line) ||
      (line != "/0/*,/1/*" && line != "No path restrictions")) {
    return false; // Invalid path restrictions
  }
  if (!safeGetline(content_stream, line) ||
      line != CoreUtils::getInstance().DeriveAddresses(
                  GetDescriptorForSigners(
                      signers, m, DescriptorPath::EXTERNAL_ALL, a, w,
                      w == WalletType::ESCROW ? -1 : 0, true),
                  w == WalletType::ESCROW ? -1 : 0)) {
    return false; // Invalid address
  }
  return true;
}

}  // namespace

#endif  // NUNCHUK_BSMS_H