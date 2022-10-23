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

#include "descriptor.h"

#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <regex>
#include <key_io.h>
#include <util/strencodings.h>
#include <utils/json.hpp>
#include <utils/loguru.hpp>
#include <boost/algorithm/string.hpp>
#include <signingprovider.h>
#include <utils/stringutils.hpp>
#include "util/bip32.h"

using json = nlohmann::json;
namespace nunchuk {

std::string AddChecksum(const std::string& str) {
  return str + "#" + GetDescriptorChecksum(str);
}

std::string GetDescriptorsImportString(const std::string& external,
                                       const std::string& internal, int range,
                                       int64_t timestamp) {
  json descs;
  json ts = {"timestamp", "now"};
  if (timestamp != -1) ts = {"timestamp", timestamp};
  descs[0] = {{"desc", external},  {"active", true},   {"range", range}, ts,
              {"internal", false}, {"watchonly", true}};
  if (!internal.empty()) {
    descs[1] = {{"desc", internal}, {"active", true},   {"range", range}, ts,
                {"internal", true}, {"watchonly", true}};
  }
  return descs.dump();
}

std::string GetDescriptorsImportString(const Wallet& wallet) {
  int idx = SigningProviderCache::getInstance().GetMaxIndex(wallet.get_id());
  int range = (idx / 100 + 1) * 100;
  return GetDescriptorsImportString(
      wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL),
      wallet.get_descriptor(DescriptorPath::INTERNAL_ALL), range);
}

std::string GetDerivationPathView(std::string path) {
  std::replace(path.begin(), path.end(), 'h', '\'');
  std::vector<uint32_t> path_int;
  if (!ParseHDKeypath(path, path_int)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid derivation path");
  }
  path = WriteHDKeypath(path_int);
  std::replace(path.begin(), path.end(), '\'', 'h');
  return path;
}

std::string FormalizePath(const std::string& path) {
  std::string rs(path);
  if (rs.rfind("m", 0) == 0) rs.erase(0, 1);  // Remove leading m
  std::replace(rs.begin(), rs.end(), 'h', '\'');
  // Prepend '/'
  if (!rs.empty() && rs[0] != '/') {
    rs = '/' + rs;
  }
  return rs;
}

std::string GetKeyPath(DescriptorPath path, int index) {
  std::stringstream keypath;
  switch (path) {
    case DescriptorPath::ANY:
      keypath << "/*";
      break;
    case DescriptorPath::INTERNAL_ALL:
      keypath << "/1/*";
      break;
    case DescriptorPath::INTERNAL:
      keypath << "/1/" << index;
      break;
    case DescriptorPath::EXTERNAL_ALL:
      keypath << "/0/*";
      break;
    case DescriptorPath::EXTERNAL:
      keypath << "/0/" << index;
      break;
    case DescriptorPath::TEMPLATE:
      keypath << "/**";
      break;
  }
  return keypath.str();
}

std::string GetDescriptorForSigners(const std::vector<SingleSigner>& signers,
                                    int m, DescriptorPath key_path,
                                    AddressType address_type,
                                    WalletType wallet_type, int index,
                                    bool sorted) {
  std::stringstream desc;
  std::string keypath = GetKeyPath(key_path, index);
  if (wallet_type == WalletType::SINGLE_SIG) {
    const SingleSigner& signer = signers[0];
    std::string path = FormalizePath(signer.get_derivation_path());
    desc << (address_type == AddressType::NESTED_SEGWIT ? "sh(" : "");
    desc << (address_type == AddressType::LEGACY    ? "pkh"
             : address_type == AddressType::TAPROOT ? "tr"
                                                    : "wpkh");
    desc << "([" << signer.get_master_fingerprint() << path << "]"
         << signer.get_xpub() << keypath << ")";
    desc << (address_type == AddressType::NESTED_SEGWIT ? ")" : "");
  } else {
    desc << (address_type == AddressType::NESTED_SEGWIT ? "sh(" : "");
    desc << (address_type == AddressType::LEGACY ? "sh" : "wsh");
    desc << (sorted ? "(sortedmulti(" : "(multi(") << m;
    for (auto&& signer : signers) {
      if (wallet_type == WalletType::ESCROW) {
        std::string pubkey = signer.get_public_key();
        if (pubkey.empty()) {
          pubkey = HexStr(DecodeExtPubKey(signer.get_xpub()).pubkey);
        }
        desc << ",[" << signer.get_master_fingerprint()
             << FormalizePath(signer.get_derivation_path()) << "]" << pubkey;
      } else if (key_path == DescriptorPath::EXTERNAL ||
                 key_path == DescriptorPath::INTERNAL) {
        std::stringstream p;
        p << signer.get_derivation_path() << keypath;
        std::string path = FormalizePath(p.str());
        // displayaddress only takes pubkeys as inputs, not xpubs
        auto xpub = DecodeExtPubKey(signer.get_xpub());
        xpub.Derive(xpub, (key_path == DescriptorPath::INTERNAL ? 1 : 0));
        xpub.Derive(xpub, index);
        std::string pubkey = HexStr(xpub.pubkey);
        desc << ",[" << signer.get_master_fingerprint() << path << "]"
             << pubkey;
      } else {
        desc << ",[" << signer.get_master_fingerprint()
             << FormalizePath(signer.get_derivation_path()) << "]"
             << signer.get_xpub() << keypath;
      }
    }
    desc << "))";
    desc << (address_type == AddressType::NESTED_SEGWIT ? ")" : "");
  }

  if (key_path == DescriptorPath::TEMPLATE) {
    return desc.str();
  }

  std::string desc_with_checksum = AddChecksum(desc.str());
  DLOG_F(INFO, "GetDescriptorForSigners(): '%s'", desc_with_checksum.c_str());

  return desc_with_checksum;
}

std::string GetWalletId(const std::vector<SingleSigner>& signers, int m,
                        AddressType address_type, WalletType wallet_type) {
  auto external_desc = GetDescriptorForSigners(
      signers, m, DescriptorPath::EXTERNAL_ALL, address_type, wallet_type);
  return GetDescriptorChecksum(external_desc);
}

std::string GetPkhDescriptor(const std::string& address) {
  std::stringstream desc_without_checksum;
  desc_without_checksum << "pkh(" << address << ")";

  return AddChecksum(desc_without_checksum.str());
}

static std::regex SIGNER_REGEX("\\[([0-9a-fA-F]{8})(.+)\\](.+?)(/.*\\*)?\n?");

static std::map<std::string, std::pair<AddressType, WalletType>>
    PREFIX_MATCHER = {
        {"wsh(sortedmulti(",
         {AddressType::NATIVE_SEGWIT, WalletType::MULTI_SIG}},
        {"sh(wsh(sortedmulti(",
         {AddressType::NESTED_SEGWIT, WalletType::MULTI_SIG}},
        {"sh(sortedmulti(", {AddressType::LEGACY, WalletType::MULTI_SIG}},
        {"wpkh(", {AddressType::NATIVE_SEGWIT, WalletType::SINGLE_SIG}},
        {"sh(wpkh(", {AddressType::NESTED_SEGWIT, WalletType::SINGLE_SIG}},
        {"pkh(", {AddressType::LEGACY, WalletType::SINGLE_SIG}},
        {"tr(", {AddressType::TAPROOT, WalletType::SINGLE_SIG}}};

SingleSigner ParseSignerString(const std::string& signer_str) {
  std::smatch sm;
  if (std::regex_match(signer_str, sm, SIGNER_REGEX)) {
    const std::string xfp = boost::algorithm::to_lower_copy(sm[1].str());
    if (sm[3].str().rfind("tpub", 0) == 0 ||
        sm[3].str().rfind("xpub", 0) == 0) {
      return SingleSigner(sm[1], sm[3], {}, "m" + sm[2].str(), xfp, 0);
    } else {
      return SingleSigner(sm[1], {}, sm[3], "m" + sm[2].str(), xfp, 0);
    }
  }
  throw NunchukException(NunchukException::INVALID_PARAMETER,
                         "Could not parse descriptor. Note that key origin "
                         "is required for XPUB");
}

bool ParseDescriptors(const std::string& descs, AddressType& a, WalletType& w,
                      int& m, int& n, std::vector<SingleSigner>& signers) {
  try {
    auto sep = descs.find('\n', 0);
    bool has_internal = sep != std::string::npos;
    std::string external = has_internal ? descs.substr(0, sep) : descs;
    std::string internal = has_internal ? descs.substr(sep + 1) : "";

    for (auto const& prefix : PREFIX_MATCHER) {
      if (external.rfind(prefix.first, 0) == 0) {
        a = prefix.second.first;
        w = prefix.second.second;
        std::string signer_info = external.substr(
            prefix.first.size(), external.find(")", 0) - prefix.first.size());
        if (w == WalletType::SINGLE_SIG) {
          m = n = 1;
          signers.push_back(ParseSignerString(signer_info));
        } else {
          std::vector<std::string> parts;
          boost::split(parts, signer_info, boost::is_any_of(","),
                       boost::token_compress_off);
          m = std::stoi(parts[0]);
          n = parts.size() - 1;
          for (unsigned i = 1; i <= n; ++i) {
            auto signer = ParseSignerString(parts[i]);
            signers.push_back(signer);
            if (signer.get_xpub().empty()) w = WalletType::ESCROW;
          }
        }

        return true;
      }
    }
  } catch (...) {
  }
  return false;
}

bool ParseJSONDescriptors(const std::string& json_str, std::string& name,
                          AddressType& address_type, WalletType& wallet_type,
                          int& m, int& n, std::vector<SingleSigner>& signers) {
  try {
    const auto json_descs = json::parse(json_str);
    if (auto name_iter = json_descs.find("label");
        name_iter != json_descs.end()) {
      name = *name_iter;
    }
    return ParseDescriptors(json_descs["descriptor"], address_type, wallet_type,
                            m, n, signers);
  } catch (std::exception& e) {
    return false;
  }
}

std::string GetSignerNameFromDerivationPath(const std::string& derivation_path,
                                            const std::string& prefix) {
  if (derivation_path.empty()) {
    return {};
  }
  const auto sp = split(derivation_path, '/');
  if (sp.size() < 2) {
    return {};
  }

  std::string rs = prefix + sp[0] + "/" + sp[1];
  std::replace(rs.begin(), rs.end(), '\'', 'h');
  return rs;
}

}  // namespace nunchuk
