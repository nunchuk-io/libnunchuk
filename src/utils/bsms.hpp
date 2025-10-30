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
  auto path = wallet.get_wallet_type() == WalletType::MINISCRIPT
                  ? DescriptorPath::EXTERNAL_INTERNAL
                  : DescriptorPath::ANY;
  auto sorted = true;
  std::stringstream record;
  record << "BSMS 1.0" << std::endl;
  record << wallet.get_descriptor(path, 0, sorted) << std::endl;
  record << "No path restrictions" << std::endl;
  record << CoreUtils::getInstance().DeriveAddress(
      wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL, 0, sorted),
      wallet.is_escrow() ? -1 : 0);
  return record.str();
}

inline std::optional<nunchuk::Wallet> ParseBSMSRecord(const std::string& bsms,
                                                      std::string& error) {
  using namespace nunchuk;
  std::istringstream content_stream(bsms);
  std::string line;
  if (!safeGetline(content_stream, line) || line != "BSMS 1.0") {
    error = "Invalid BSMS version";
    return std::nullopt;
  }
  if (!safeGetline(content_stream, line)) {
    error = "Invalid Descriptor template";
    return std::nullopt;
  }
  std::optional<Wallet> wallet = ParseDescriptors(line, error);
  if (!wallet) {
    return std::nullopt;
  }
  if (!safeGetline(content_stream, line) ||
      (line != "/0/*,/1/*" && line != "No path restrictions")) {
    error = "Invalid path restrictions";
    return std::nullopt;
  }
  int index = wallet->is_escrow() ? -1 : 0;
  std::string first_address = CoreUtils::getInstance().DeriveAddress(
      wallet->get_descriptor(DescriptorPath::EXTERNAL_ALL, index, true), index);
  if (!safeGetline(content_stream, line) || line != first_address) {
    error = "Invalid address";
    return std::nullopt;
  }
  return wallet;
}

inline nunchuk::BSMSData ParseBSMSData(const std::string& bsms) {
  using namespace nunchuk;
  std::istringstream content_stream(bsms);

  BSMSData result;
  if (!safeGetline(content_stream, result.version) ||
      result.version != "BSMS 1.0") {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid BSMS version");
  }
  result.version = "1.0";

  if (!safeGetline(content_stream, result.descriptor)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid Descriptor template");
  }

  if (!safeGetline(content_stream, result.path_restrictions) ||
      (result.path_restrictions != "/0/*,/1/*" &&
       result.path_restrictions != "No path restrictions")) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid path restrictions");
  }

  std::string error;
  if (!safeGetline(content_stream, result.first_address) ||
      !ParseBSMSRecord(bsms, error)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid address");
  }
  return result;
}

}  // namespace

#endif  // NUNCHUK_BSMS_H
