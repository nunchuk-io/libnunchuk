// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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

std::string GetDescriptorForSigners(const std::vector<SingleSigner>& signers,
                                    int m, bool internal,
                                    AddressType address_type,
                                    WalletType wallet_type) {
  std::stringstream desc;
  if (wallet_type == WalletType::SINGLE_SIG) {
    const SingleSigner& signer = signers[0];
    std::string path = signer.get_derivation_path();
    if (path.rfind("m", 0) == 0) path.erase(0, 1);  // Remove leading m
    std::replace(path.begin(), path.end(), 'h', '\'');
    desc << (address_type == AddressType::NESTED_SEGWIT ? "sh(" : "");
    desc << (address_type == AddressType::LEGACY ? "pkh" : "wpkh");
    desc << "([" << signer.get_master_fingerprint() << path << "]"
         << signer.get_xpub() << "/" << (internal ? 1 : 0) << "/*)";
    desc << (address_type == AddressType::NESTED_SEGWIT ? ")" : "");
  } else {
    desc << (address_type == AddressType::NESTED_SEGWIT ? "sh(" : "");
    desc << (address_type == AddressType::LEGACY ? "sh" : "wsh");
    desc << "(sortedmulti(" << m;
    for (auto&& signer : signers) {
      std::string path = signer.get_derivation_path();
      if (path.rfind("m", 0) == 0) path.erase(0, 1);  // Remove leading m
      std::replace(path.begin(), path.end(), 'h', '\'');
      if (wallet_type == WalletType::MULTI_SIG) {
        desc << ",[" << signer.get_master_fingerprint() << path << "]"
             << signer.get_xpub() << "/" << (internal ? 1 : 0) << "/*";
      } else {
        std::string pubkey = signer.get_public_key();
        if (pubkey.empty()) {
          pubkey = HexStr(DecodeExtPubKey(signer.get_xpub()).pubkey);
        }
        desc << ",[" << signer.get_master_fingerprint() << path << "]"
             << pubkey;
      }
    }
    desc << "))";
    desc << (address_type == AddressType::NESTED_SEGWIT ? ")" : "");
  }

  std::string desc_with_checksum = AddChecksum(desc.str());
  DLOG_F(INFO, "GetDescriptorForSigners(): '%s'", desc_with_checksum.c_str());

  return desc_with_checksum;
}

std::string GetDescriptorForSignersAtIndex(
    const std::vector<SingleSigner>& signers, int m, bool internal,
    AddressType address_type, WalletType wallet_type, int index) {
  std::stringstream desc;
  if (wallet_type == WalletType::SINGLE_SIG) {
    const SingleSigner& signer = signers[0];
    std::string path = signer.get_derivation_path();
    if (path.rfind("m", 0) == 0) path.erase(0, 1);  // Remove leading m
    std::replace(path.begin(), path.end(), 'h', '\'');
    desc << (address_type == AddressType::NESTED_SEGWIT ? "sh(" : "");
    desc << (address_type == AddressType::LEGACY ? "pkh" : "wpkh");
    desc << "([" << signer.get_master_fingerprint() << path << "]"
         << signer.get_xpub() << "/" << (internal ? 1 : 0) << "/" << index
         << ")";
    desc << (address_type == AddressType::NESTED_SEGWIT ? ")" : "");
  } else {
    desc << (address_type == AddressType::NESTED_SEGWIT ? "sh(" : "");
    desc << (address_type == AddressType::LEGACY ? "sh" : "wsh");
    desc << "(sortedmulti(" << m;
    for (auto&& signer : signers) {
      std::stringstream p;
      p << signer.get_derivation_path() << "/" << (internal ? 1 : 0) << "/"
        << index;
      std::string path = p.str();
      if (path.rfind("m", 0) == 0) path.erase(0, 1);  // Remove leading m
      std::replace(path.begin(), path.end(), 'h', '\'');
      // displayaddress only takes pubkeys as inputs, not xpubs
      auto xpub = DecodeExtPubKey(signer.get_xpub());
      xpub.Derive(xpub, (internal ? 1 : 0));
      xpub.Derive(xpub, index);
      std::string pubkey = HexStr(xpub.pubkey);
      desc << ",[" << signer.get_master_fingerprint() << path << "]" << pubkey;
    }
    desc << "))";
    desc << (address_type == AddressType::NESTED_SEGWIT ? ")" : "");
  }

  std::string desc_with_checksum = AddChecksum(desc.str());
  DLOG_F(INFO, "GetDescriptorForSignersAtIndex(): '%s'",
         desc_with_checksum.c_str());

  return desc_with_checksum;
}

std::string GetPkhDescriptor(const std::string& address) {
  std::stringstream desc_without_checksum;
  desc_without_checksum << "pkh(" << address << ")";

  return AddChecksum(desc_without_checksum.str());
}

static std::regex SIGNER_REGEX("\\[([0-9a-f]{8})(.+)\\](.+?)(/[01]/\\*)?");

static std::map<std::string, std::pair<AddressType, WalletType>>
    PREFIX_MATCHER = {
        {"wsh(sortedmulti(",
         {AddressType::NATIVE_SEGWIT, WalletType::MULTI_SIG}},
        {"sh(wsh(sortedmulti(",
         {AddressType::NESTED_SEGWIT, WalletType::MULTI_SIG}},
        {"sh(sortedmulti(", {AddressType::LEGACY, WalletType::MULTI_SIG}},
        {"wpkh(", {AddressType::NATIVE_SEGWIT, WalletType::SINGLE_SIG}},
        {"sh(wpkh(", {AddressType::NESTED_SEGWIT, WalletType::SINGLE_SIG}},
        {"pkh(", {AddressType::LEGACY, WalletType::SINGLE_SIG}}};

SingleSigner ParseSignerString(const std::string& signer_str) {
  std::smatch sm;
  if (std::regex_match(signer_str, sm, SIGNER_REGEX)) {
    if (sm[4].str().empty()) {
      return SingleSigner(sm[1], {}, sm[3], "m" + sm[2].str(), sm[1], 0);
    } else {
      return SingleSigner(sm[1], sm[3], {}, "m" + sm[2].str(), sm[1], 0);
    }
  }
  throw NunchukException(
      NunchukException::INVALID_PARAMETER,
      "Could not parse descriptor. Note that key origin is required for XPUB");
}

bool ParseDescriptors(const std::string descs, AddressType& a, WalletType& w,
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

        if (external != GetDescriptorForSigners(signers, m, false, a, w)) {
          return false;
        } else if (w == WalletType::ESCROW) {
          return !has_internal;
        } else {
          return internal == GetDescriptorForSigners(signers, m, true, a, w);
        }
      }
    }
  } catch (...) {
  }
  return false;
}

}  // namespace nunchuk