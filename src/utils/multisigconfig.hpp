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

#ifndef NUNCHUK_MULTISIGCONFIG_H
#define NUNCHUK_MULTISIGCONFIG_H

#include <nunchuk.h>
#include <boost/algorithm/string.hpp>
#include <sstream>
#include <iostream>
#include <regex>
#include <utils/stringutils.hpp>

namespace {

static std::regex NAME_REGEX("Name:(.+)");
static std::regex POLICY_REGEX("Policy: ([0-9]{1,2})(.+?)([0-9]{1,2})");
static std::regex FORMAT_REGEX("Format:(.+)");
static std::regex DERIVATION_REGEX("Derivation:(.+)");
static std::regex XFP_REGEX("([0-9a-fA-F]{8}):(.+)");

inline std::string GetMultisigConfig(const nunchuk::Wallet& wallet) {
  using namespace nunchuk;
  std::stringstream content;
  content << "# Exported from Nunchuk" << std::endl
          << "Name: " << wallet.get_name().substr(0, 20) << std::endl
          << "Policy: " << wallet.get_m() << " of " << wallet.get_n()
          << std::endl
          << "Format: "
          << (wallet.get_address_type() == AddressType::LEGACY
                  ? "P2SH"
                  : wallet.get_address_type() == AddressType::NATIVE_SEGWIT
                        ? "P2WSH"
                        : "P2WSH-P2SH")
          << std::endl;

  content << std::endl;
  for (auto&& signer : wallet.get_signers()) {
    content << "Derivation: " << signer.get_derivation_path() << std::endl;
    content << signer.get_master_fingerprint() << ": " << signer.get_xpub()
            << std::endl
            << std::endl;
  }
  return content.str();
}

inline bool ParseConfig(nunchuk::Chain chain, const std::string content,
                        std::string& name, nunchuk::AddressType& a,
                        nunchuk::WalletType& w, int& m, int& n,
                        std::vector<nunchuk::SingleSigner>& signers) {
  using namespace nunchuk;
  name = "";
  a = AddressType::LEGACY;
  w = WalletType::MULTI_SIG;
  m = 0;
  n = 0;
  try {
    std::istringstream content_stream(content);
    std::string line;
    std::string derivation_path = "";
    while (safeGetline(content_stream, line)) {
      if (boost::starts_with(line, "#")) continue;
      std::smatch sm;
      if (std::regex_match(line, sm, NAME_REGEX)) {
        name = boost::trim_copy(sm[1].str());
      } else if (std::regex_match(line, sm, POLICY_REGEX)) {
        m = std::stoi(sm[1].str());
        n = std::stoi(sm[3].str());
      } else if (std::regex_match(line, sm, FORMAT_REGEX)) {
        std::string format = boost::trim_copy(sm[1].str());
        if (boost::iequals(format, "p2sh")) {
          a = AddressType::LEGACY;
        } else if (boost::iequals(format, "p2wsh")) {
          a = AddressType::NATIVE_SEGWIT;
        } else if (boost::iequals(format, "p2wsh-p2sh") ||
                   boost::iequals(format, "p2sh-p2wsh")) {
          a = AddressType::NESTED_SEGWIT;
        } else {
          throw NunchukException(NunchukException::INVALID_FORMAT,
                                 "Invalid address format");
        }
      } else if (std::regex_match(line, sm, DERIVATION_REGEX)) {
        derivation_path = boost::trim_copy(sm[1].str());
        if (!Utils::IsValidDerivationPath(derivation_path)) {
          throw NunchukException(NunchukException::INVALID_FORMAT,
                                 "Invalid derivation path");
        }
      } else if (std::regex_match(line, sm, XFP_REGEX)) {
        if (derivation_path.empty()) {
          throw NunchukException(NunchukException::INVALID_FORMAT,
                                 "Invalid derivation path");
        }
        std::string xfp = sm[1].str();
        std::string xpub = boost::trim_copy(sm[2].str());
        std::string target_format = chain == Chain::MAIN ? "xpub" : "tpub";
        xpub = Utils::SanitizeBIP32Input(xpub, target_format);
        if (!Utils::IsValidXPub(xpub)) {
          throw NunchukException(NunchukException::INVALID_FORMAT,
                                 "Invalid xpub");
        }
        signers.push_back(SingleSigner{xfp, xpub, {}, derivation_path, xfp, 0});
      }
    }
    if (n <= 0) n = signers.size();
    if (m <= 0) m = n;
    if (name.empty()) {
      std::stringstream s;
      s << "ImportWallet-" << m << "of" << n;
      name = s.str();
    }
  } catch (NunchukException& ne) {
    throw;
  } catch (...) {
    throw NunchukException(NunchukException::INVALID_FORMAT,
                           "Can not parse config");
  }
  return true;
}

}  // namespace

#endif  // NUNCHUK_MULTISIGCONFIG_H
