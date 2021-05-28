// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_BSMS_H
#define NUNCHUK_BSMS_H

#include <nunchuk.h>
#include <boost/algorithm/string.hpp>
#include <sstream>
#include <iostream>
#include <regex>

#include <descriptor.h>
#include <coreutils.h>

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
  if (!std::getline(content_stream, line) || line != "BSMS 1.0") {
    return false; // Invalid BSMS version
  }
  if (!std::getline(content_stream, line) ||
      !ParseDescriptors(line, a, w, m, n, signers)) {
    return false; // Invalid Descriptor template
  }
  if (!std::getline(content_stream, line) ||
      (line != "/0/*,/1/*" && line != "No path restrictions")) {
    return false; // Invalid path restrictions
  }
  if (!std::getline(content_stream, line) ||
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