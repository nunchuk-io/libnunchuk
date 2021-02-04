// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_MULTISIGCONFIG_H
#define NUNCHUK_MULTISIGCONFIG_H

#include <nunchuk.h>
#include <boost/algorithm/string.hpp>
#include <sstream>
#include <iostream>
#include <regex>

namespace {

static std::regex NAME_REGEX("Name:(.+)");
static std::regex POLICY_REGEX("Policy: ([0-9]{1,2})(.+?)([0-9]{1,2})");
static std::regex FORMAT_REGEX("Format:(.+)");
static std::regex DERIVATION_REGEX("Derivation:(.+)");
static std::regex XFP_REGEX("([0-9a-fA-F]{8}):(.+)");

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
    while (std::getline(content_stream, line)) {
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
                                 "invalid xpub");
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