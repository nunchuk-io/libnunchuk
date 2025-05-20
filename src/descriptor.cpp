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

static const std::string H_POINT =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

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
    case DescriptorPath::INTERNAL_PUBKEY:
    case DescriptorPath::INTERNAL_XPUB:
      keypath << "/1/" << index;
      break;
    case DescriptorPath::EXTERNAL_ALL:
      keypath << "/0/*";
      break;
    case DescriptorPath::EXTERNAL_PUBKEY:
    case DescriptorPath::EXTERNAL_XPUB:
      keypath << "/0/" << index;
      break;
    case DescriptorPath::TEMPLATE:
      keypath << "/**";
      break;
    case DescriptorPath::EXTERNAL_INTERNAL:
      keypath << "/<0;1>/*";
      break;
  }
  return keypath.str();
}

std::string GetScriptpathDescriptor(const std::vector<std::string>& nodes) {
  if (nodes.size() == 1) return nodes[0];
  std::vector<std::string> rs;
  for (size_t i = 0; i < nodes.size(); i = i + 2) {
    if (i == nodes.size() - 1) {
      rs.push_back(nodes[i]);
    } else {
      std::stringstream node;
      node << "{" << nodes[i] << "," << nodes[i + 1] << "}";
      rs.push_back(node.str());
    }
  }
  return GetScriptpathDescriptor(rs);
};

std::string GetMusigDescriptor(const std::vector<std::string>& keys, int m,
                               const std::string& keypath,
                               bool disableValueKeyset) {
  int n = keys.size();

  std::vector<bool> v(n);
  std::fill(v.begin(), v.begin() + m, true);
  auto musig = [&]() {
    std::stringstream rs;
    rs << "musig(";
    bool first = true;
    for (int i = 0; i < n; i++) {
      if (v[i]) {
        if (!first) {
          rs << ",";
        } else {
          first = false;
        }
        rs << keys[i];
      }
    }
    rs << ")";
    return rs.str();
  };

  std::stringstream desc;
  std::vector<std::string> leaves{};
  if (disableValueKeyset) {
    desc << "tr(" << H_POINT;  // keypath
    std::stringstream pkmusig;
    pkmusig << "pk(" << musig() << ")";
    leaves.push_back(pkmusig.str());
  } else {
    desc << "tr(" << musig();  // keypath
    if (n == m) {
      desc << ")";
      return desc.str();
    }
  }
  desc << ",";

  while (std::prev_permutation(v.begin(), v.end())) {
    std::stringstream pkmusig;
    pkmusig << "pk(" << musig() << ")";
    leaves.push_back(pkmusig.str());
  }

  desc << GetScriptpathDescriptor(leaves) << ")";
  return desc.str();
}

std::string GetDescriptorForSigner(const SingleSigner& signer,
                                   DescriptorPath key_path, int index) {
  std::string keypath = GetKeyPath(key_path, index);
  std::stringstream key;
  key << "[" << signer.get_master_fingerprint();
  if (key_path == DescriptorPath::EXTERNAL_PUBKEY ||
      key_path == DescriptorPath::INTERNAL_PUBKEY) {
    std::stringstream p;
    p << signer.get_derivation_path() << keypath;
    std::string path = FormalizePath(p.str());
    auto xpub = DecodeExtPubKey(signer.get_xpub());
    if (!xpub.Derive(xpub,
                     (key_path == DescriptorPath::INTERNAL_PUBKEY ? 1 : 0))) {
      throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                             "Invalid path");
    }
    if (!xpub.Derive(xpub, index)) {
      throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                             "Invalid path");
    }
    std::string pubkey = HexStr(xpub.pubkey);
    key << path << "]" << pubkey;
  } else {
    key << FormalizePath(signer.get_derivation_path()) << "]"
        << signer.get_xpub() << keypath;
  }
  return key.str();
}

std::string GetDescriptorForSigners(const std::vector<SingleSigner>& signers,
                                    int m, DescriptorPath key_path,
                                    AddressType address_type,
                                    WalletType wallet_type,
                                    WalletTemplate wallet_template, int index,
                                    bool sorted) {
  std::string keypath = GetKeyPath(key_path, index);
  std::vector<std::string> keys{};
  for (auto&& signer : signers) {
    std::stringstream key;
    key << "[" << signer.get_master_fingerprint();
    if (wallet_type == WalletType::ESCROW) {
      std::string pubkey = signer.get_public_key();
      if (pubkey.empty()) {
        pubkey = HexStr(DecodeExtPubKey(signer.get_xpub()).pubkey);
      }
      key << FormalizePath(signer.get_derivation_path()) << "]" << pubkey;
    } else if (wallet_type == WalletType::MULTI_SIG &&
               (key_path == DescriptorPath::EXTERNAL_PUBKEY ||
                key_path == DescriptorPath::INTERNAL_PUBKEY)) {
      std::stringstream p;
      p << signer.get_derivation_path() << keypath;
      std::string path = FormalizePath(p.str());
      // displayaddress only takes pubkeys as inputs, not xpubs
      auto xpub = DecodeExtPubKey(signer.get_xpub());
      if (!xpub.Derive(xpub,
                       (key_path == DescriptorPath::INTERNAL_PUBKEY ? 1 : 0))) {
        throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                               "Invalid path");
      }
      if (!xpub.Derive(xpub, index)) {
        throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                               "Invalid path");
      }
      std::string pubkey = HexStr(xpub.pubkey);
      key << path << "]" << pubkey;
    } else {
      key << FormalizePath(signer.get_derivation_path()) << "]"
          << signer.get_xpub() << keypath;
    }
    keys.push_back(key.str());
  }

  std::stringstream desc;
  if (wallet_type == WalletType::SINGLE_SIG) {
    desc << (address_type == AddressType::NESTED_SEGWIT ? "sh(" : "");
    desc << (address_type == AddressType::LEGACY    ? "pkh"
             : address_type == AddressType::TAPROOT ? "tr"
                                                    : "wpkh");
    desc << "(" << keys[0] << ")";
    desc << (address_type == AddressType::NESTED_SEGWIT ? ")" : "");
  } else if (address_type == AddressType::TAPROOT) {
    if (keys.size() <= 5 || keys.size() == m) {
      desc << GetMusigDescriptor(
          keys, m, keypath,
          wallet_template == WalletTemplate::DISABLE_KEY_PATH);
    } else {
      if (wallet_template == WalletTemplate::DISABLE_KEY_PATH) {
        desc << "tr(" << H_POINT << ",";
      } else {
        desc << "tr(musig(";
        for (int i = 0; i < m; i++) {
          if (i > 0) desc << ",";
          desc << keys[i];
        }
        desc << "),";
      }
      desc << (sorted ? "sortedmulti_a(" : "multi_a(") << m;
      for (auto&& key : keys) {
        desc << "," << key;
      }
      desc << "))";
    }
  } else {
    desc << (address_type == AddressType::NESTED_SEGWIT ? "sh(" : "");
    desc << (address_type == AddressType::LEGACY ? "sh" : "wsh");
    desc << (sorted ? "(sortedmulti(" : "(multi(") << m;
    for (auto&& key : keys) {
      desc << "," << key;
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

std::string GetDescriptorForMiniscript(const std::string& miniscript,
                                       AddressType address_type) {
  std::stringstream desc;
  if (address_type == AddressType::NATIVE_SEGWIT) {
    desc << "wsh(" << miniscript << ")";
  } else if (address_type == AddressType::TAPROOT) {
    desc << "tr(" << H_POINT << "," << miniscript << ")";
  } else {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid address type");
  }
  return AddChecksum(desc.str());
}

std::string GetWalletId(const std::vector<SingleSigner>& signers, int m,
                        AddressType a, WalletType w, WalletTemplate t) {
  auto external_desc = GetDescriptorForSigners(
      signers, m, DescriptorPath::EXTERNAL_ALL, a, w, t);
  return GetDescriptorChecksum(external_desc);
}

std::string GetWalletId(const std::string& miniscript,
                        AddressType address_type) {
  std::stringstream desc;
  if (address_type == AddressType::NATIVE_SEGWIT) {
    desc << "wsh(" << miniscript << ")";
  } else if (address_type == AddressType::TAPROOT) {
    desc << "tr(" << H_POINT << "," << miniscript << ")";
  } else {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid address type");
  }
  return GetDescriptorChecksum(desc.str());
}

std::string GetPkhDescriptor(const std::string& address) {
  std::stringstream desc_without_checksum;
  desc_without_checksum << "pkh(" << address << ")";

  return AddChecksum(desc_without_checksum.str());
}

std::string GetDescriptor(const SingleSigner& signer,
                          AddressType address_type) {
  std::stringstream desc;
  std::string path = FormalizePath(signer.get_derivation_path());
  desc << (address_type == AddressType::NESTED_SEGWIT ? "sh(" : "");
  desc << (address_type == AddressType::LEGACY    ? "pkh"
           : address_type == AddressType::TAPROOT ? "tr"
                                                  : "wpkh");
  desc << "([" << signer.get_master_fingerprint() << path << "]"
       << signer.get_xpub() << ")";
  desc << (address_type == AddressType::NESTED_SEGWIT ? ")" : "");

  std::string desc_with_checksum = AddChecksum(desc.str());
  return desc_with_checksum;
}

static std::regex SIGNER_REGEX("\\[([0-9a-fA-F]{8})(.+)\\](.+?)(/.*\\*)?\n?");

static std::map<std::string,
                std::tuple<AddressType, WalletType, WalletTemplate>>
    PREFIX_MATCHER = {
        {"wsh(sortedmulti(",
         {AddressType::NATIVE_SEGWIT, WalletType::MULTI_SIG,
          WalletTemplate::DEFAULT}},
        {"sh(wsh(sortedmulti(",
         {AddressType::NESTED_SEGWIT, WalletType::MULTI_SIG,
          WalletTemplate::DEFAULT}},
        {"sh(sortedmulti(",
         {AddressType::LEGACY, WalletType::MULTI_SIG, WalletTemplate::DEFAULT}},
        {"wpkh(",
         {AddressType::NATIVE_SEGWIT, WalletType::SINGLE_SIG,
          WalletTemplate::DEFAULT}},
        {"sh(wpkh(",
         {AddressType::NESTED_SEGWIT, WalletType::SINGLE_SIG,
          WalletTemplate::DEFAULT}},
        {"pkh(",
         {AddressType::LEGACY, WalletType::SINGLE_SIG,
          WalletTemplate::DEFAULT}},
        {"tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,",
         {AddressType::TAPROOT, WalletType::MULTI_SIG,
          WalletTemplate::DISABLE_KEY_PATH}},
        {"tr(musig(",
         {AddressType::TAPROOT, WalletType::MULTI_SIG,
          WalletTemplate::DEFAULT}},
        {"tr([",
         {AddressType::TAPROOT, WalletType::SINGLE_SIG,
          WalletTemplate::DEFAULT}}};

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

std::string GetDescriptorWithoutChecksum(const std::string& desc) {
  std::string rs = split(desc, '#')[0];
  std::replace(rs.begin(), rs.end(), '\'', 'h');
  std::transform(rs.begin(), rs.end(), rs.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return rs;
}

bool ParseDescriptors(const std::string& descs, AddressType& a, WalletType& w,
                      WalletTemplate& t, int& m, int& n,
                      std::vector<SingleSigner>& signers) {
  try {
    auto sep = descs.find('\n', 0);
    bool has_internal = sep != std::string::npos;
    std::string external = has_internal ? descs.substr(0, sep) : descs;
    std::string internal = has_internal ? descs.substr(sep + 1) : "";

    for (auto&& [prefix, conf] : PREFIX_MATCHER) {
      if (external.rfind(prefix, 0) == 0) {
        a = std::get<0>(conf);
        w = std::get<1>(conf);
        t = std::get<2>(conf);
        if (w == WalletType::SINGLE_SIG) {
          m = n = 1;
          std::string signer_info = external.substr(
              prefix.size(), external.find(")", 0) - prefix.size());
          if (a == AddressType::TAPROOT) signer_info = "[" + signer_info;
          signers.push_back(ParseSignerString(signer_info));
        } else if (a == AddressType::TAPROOT) {
          if (t == WalletTemplate::DISABLE_KEY_PATH) {
            std::vector<std::string> parts;
            std::string scriptpath = external.substr(
                prefix.size(), external.size() - prefix.size() - 1);
            boost::split(parts, scriptpath, boost::is_any_of("{}()"),
                         boost::token_compress_off);
            for (unsigned i = 0; i < parts.size(); ++i) {
              if (parts[i].size() < 20) continue;
              std::vector<std::string> keys;
              boost::split(keys, parts[i], boost::is_any_of(","),
                           boost::token_compress_off);
              m = keys.size();
              break;
            }
          } else {
            std::vector<std::string> parts;
            std::string musig_inner = external.substr(
                prefix.size(), external.find(")", 0) - prefix.size());
            boost::split(parts, musig_inner, boost::is_any_of(","),
                         boost::token_compress_off);
            m = parts.size();
          }
          std::vector<std::string> parts;
          boost::split(parts, external, boost::is_any_of(",{}()"),
                       boost::token_compress_off);
          std::set<std::string> signerStr{};
          for (unsigned i = 0; i < parts.size(); ++i) {
            if (parts[i] == H_POINT) continue;
            if (parts[i].size() < 20) continue;
            if (signerStr.count(parts[i])) continue;
            auto signer = ParseSignerString(parts[i]);
            signers.push_back(signer);
            signerStr.insert(parts[i]);
          }
          n = signers.size();
        } else {
          std::vector<std::string> parts;
          std::string multi_inner = external.substr(
              prefix.size(), external.find(")", 0) - prefix.size());
          boost::split(parts, multi_inner, boost::is_any_of(","),
                       boost::token_compress_off);
          m = std::stoi(parts[0]);
          n = parts.size() - 1;
          for (unsigned i = 1; i <= n; ++i) {
            auto signer = ParseSignerString(parts[i]);
            signers.push_back(signer);
            if (signer.get_xpub().empty()) w = WalletType::ESCROW;
          }
        }

        Wallet wallet{"", "wallet", m, n, signers, a, w, 0};
        wallet.set_wallet_template(t);
        signers = wallet.get_signers();

        std::string in = GetDescriptorWithoutChecksum(external);
        return GetDescriptorWithoutChecksum(
                   wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL)) == in ||
               GetDescriptorWithoutChecksum(wallet.get_descriptor(
                   DescriptorPath::EXTERNAL_INTERNAL)) == in ||
               GetDescriptorWithoutChecksum(
                   wallet.get_descriptor(DescriptorPath::ANY)) == in ||
               GetDescriptorWithoutChecksum(
                   wallet.get_descriptor(DescriptorPath::TEMPLATE)) == in;
      }
    }
  } catch (...) {
  }
  return false;
}

bool ParseJSONDescriptors(const std::string& json_str, std::string& name,
                          AddressType& address_type, WalletType& wallet_type,
                          WalletTemplate& wallet_template, int& m, int& n,
                          std::vector<SingleSigner>& signers) {
  try {
    const auto json_descs = json::parse(json_str);
    if (auto name_iter = json_descs.find("label");
        name_iter != json_descs.end()) {
      name = *name_iter;
    }
    if (auto desc_iter = json_descs.find("descriptor");
        desc_iter != json_descs.end()) {
      return ParseDescriptors(*desc_iter, address_type, wallet_type,
                              wallet_template, m, n, signers);
    }
    return false;
  } catch (...) {
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
