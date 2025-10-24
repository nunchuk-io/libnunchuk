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
#include <miniscript/util.h>
#include "util/bip32.h"
#include <tinyformat.h>

using json = nlohmann::json;
namespace nunchuk {
static const auto BIP341_NUMS_PUBKEY = ParseHex(std::string("02") + H_POINT);

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

DescriptorPath DefaultDescriptorPath(const std::vector<SingleSigner>& signers) {
  for (const auto& signer : signers) {
    if (signer.get_external_internal_index() != std::make_pair(0, 1)) {
      return DescriptorPath::EXTERNAL_INTERNAL;
    }
  }
  return DescriptorPath::ANY;
}

DescriptorPath DefaultDescriptorPath(
    const std::map<std::string, SingleSigner>& signers) {
  for (const auto& signer : signers) {
    if (signer.second.get_external_internal_index() != std::make_pair(0, 1)) {
      return DescriptorPath::EXTERNAL_INTERNAL;
    }
  }
  return DescriptorPath::ANY;
}

std::string GetChildKeyPath(const std::pair<int, int>& eii, DescriptorPath path,
                            int index) {
  std::stringstream keypath;
  switch (path) {
    case DescriptorPath::ANY:
      keypath << "/*";
      break;
    case DescriptorPath::INTERNAL_ALL:
      keypath << "/" << eii.second << "/*";
      break;
    case DescriptorPath::INTERNAL_PUBKEY:
    case DescriptorPath::INTERNAL_XPUB:
      if (index < 0) {
        throw NunchukException(NunchukException::INVALID_PARAMETER,
                               "Invalid index");
      }
      keypath << "/" << eii.second << "/" << index;
      break;
    case DescriptorPath::EXTERNAL_ALL:
      keypath << "/" << eii.first << "/*";
      break;
    case DescriptorPath::EXTERNAL_PUBKEY:
    case DescriptorPath::EXTERNAL_XPUB:
      if (index < 0) {
        throw NunchukException(NunchukException::INVALID_PARAMETER,
                               "Invalid index");
      }
      keypath << "/" << eii.first << "/" << index;
      break;
    case DescriptorPath::TEMPLATE:
      keypath << "/**";
      break;
    case DescriptorPath::EXTERNAL_INTERNAL:
      keypath << "/<" << eii.first << ";" << eii.second << ">/*";
      break;
    case DescriptorPath::NONE:
      keypath << "";
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
                                   DescriptorPath path, int index) {
  auto eii = signer.get_external_internal_index();
  std::string childKeyPath = GetChildKeyPath(eii, path, index);
  std::stringstream key;
  key << "[" << signer.get_master_fingerprint();
  if (path == DescriptorPath::EXTERNAL_PUBKEY ||
      path == DescriptorPath::INTERNAL_PUBKEY) {
    std::string derivationPath = signer.get_derivation_path() + childKeyPath;
    auto xpub = DecodeExtPubKey(signer.get_xpub());
    int changeIndex =
        path == DescriptorPath::INTERNAL_PUBKEY ? eii.second : eii.first;
    if (!xpub.Derive(xpub, changeIndex) || !xpub.Derive(xpub, index)) {
      throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                             "Invalid path");
    }
    std::string pubkey = HexStr(xpub.pubkey);
    key << FormalizePath(derivationPath) << "]" << pubkey;
  } else {
    key << FormalizePath(signer.get_derivation_path()) << "]"
        << signer.get_xpub() << childKeyPath;
  }
  return key.str();
}

std::string GetDescriptorForSigners(const std::vector<SingleSigner>& signers,
                                    int m, DescriptorPath path,
                                    AddressType address_type,
                                    WalletType wallet_type,
                                    WalletTemplate wallet_template, int index,
                                    bool sorted) {
  std::vector<std::string> keys{};
  for (auto&& signer : signers) {
    auto eii = signer.get_external_internal_index();
    std::string childKeyPath = GetChildKeyPath(eii, path, index);
    std::stringstream key;
    key << "[" << signer.get_master_fingerprint();
    if (wallet_type == WalletType::ESCROW) {
      std::string pubkey = signer.get_public_key();
      if (pubkey.empty()) {
        pubkey = HexStr(DecodeExtPubKey(signer.get_xpub()).pubkey);
      }
      key << FormalizePath(signer.get_derivation_path()) << "]" << pubkey;
    } else if (wallet_type == WalletType::MULTI_SIG &&
               (path == DescriptorPath::EXTERNAL_PUBKEY ||
                path == DescriptorPath::INTERNAL_PUBKEY)) {
      auto eii = signer.get_external_internal_index();
      std::string derivationPath = signer.get_derivation_path() + childKeyPath;
      // displayaddress only takes pubkeys as inputs, not xpubs
      auto xpub = DecodeExtPubKey(signer.get_xpub());
      int changeIndex =
          path == DescriptorPath::INTERNAL_PUBKEY ? eii.second : eii.first;
      if (!xpub.Derive(xpub, changeIndex) || !xpub.Derive(xpub, index)) {
        throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                               "Invalid path");
      }
      std::string pubkey = HexStr(xpub.pubkey);
      key << FormalizePath(derivationPath) << "]" << pubkey;
    } else {
      key << FormalizePath(signer.get_derivation_path()) << "]"
          << signer.get_xpub() << childKeyPath;
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
          keys, m, wallet_template == WalletTemplate::DISABLE_KEY_PATH);
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

  if (path == DescriptorPath::TEMPLATE) {
    return desc.str();
  }

  std::string desc_with_checksum = AddChecksum(desc.str());
  DLOG_F(INFO, "GetDescriptorForSigners(): '%s'", desc_with_checksum.c_str());

  return desc_with_checksum;
}

std::string GetDescriptorForMiniscript(const std::string& miniscript,
                                       const std::string& keypath,
                                       AddressType address_type) {
  std::stringstream desc;
  if (address_type == AddressType::NATIVE_SEGWIT) {
    desc << "wsh(" << miniscript << ")";
  } else if (address_type == AddressType::TAPROOT) {
    desc << "tr(" << keypath << "," << miniscript << ")";
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

std::pair<int, int> ParseExternalInternalIndex(const std::string& eii) {
  if (eii.find("/<", 0) == 0 && eii.find(">/*", 0) == eii.size() - 3) {
    std::vector<std::string> parts;
    boost::split(parts, eii.substr(2, eii.size() - 5), boost::is_any_of(";"));
    return {std::stoi(parts[0]), std::stoi(parts[1])};
  }
  return {0, 1};
}

SingleSigner ParseSignerString(const std::string& signer_str) {
  std::smatch sm;
  if (std::regex_match(signer_str, sm, SIGNER_REGEX)) {
    const std::string xfp = boost::algorithm::to_lower_copy(sm[1].str());
    std::pair<int, int> eii = ParseExternalInternalIndex(sm[4].str());
    if (sm[3].str().rfind("tpub", 0) == 0 ||
        sm[3].str().rfind("xpub", 0) == 0) {
      return SingleSigner(sm[1], sm[3], {}, "m" + sm[2].str(), eii, xfp, 0);
    } else {
      return SingleSigner(sm[1], {}, sm[3], "m" + sm[2].str(), eii, xfp, 0);
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

Wallet ParseSortedMultiDescriptor(const std::string& desc, AddressType a) {
  std::string prefix = "sortedmulti(";
  if (a == AddressType::NESTED_SEGWIT) {
    prefix = "sh(wsh(" + prefix;
  } else if (a == AddressType::NATIVE_SEGWIT) {
    prefix = "wsh(" + prefix;
  } else if (a == AddressType::LEGACY) {
    prefix = "sh(" + prefix;
  }
  std::vector<SingleSigner> signers;
  std::vector<std::string> parts;
  auto inner = desc.substr(prefix.size(), desc.find(")", 0) - prefix.size());
  boost::split(parts, inner, boost::is_any_of(","), boost::token_compress_off);

  int m = std::stoi(parts[0]);
  int n = parts.size() - 1;
  WalletType w = WalletType::MULTI_SIG;
  for (unsigned i = 1; i <= n; ++i) {
    auto signer = ParseSignerString(parts[i]);
    signers.push_back(signer);
    if (signer.get_xpub().empty()) w = WalletType::ESCROW;
  }
  return Wallet({}, {}, m, n, signers, a, w, 0);
}

Wallet ParseMusigWallet(const std::string& external, WalletTemplate t) {
  std::vector<SingleSigner> signers;
  int m = 0;
  if (t == WalletTemplate::DISABLE_KEY_PATH) {
    std::string prefix = "tr(" + H_POINT + ",";
    std::vector<std::string> parts;
    std::string scriptpath =
        external.substr(prefix.size(), external.size() - prefix.size() - 1);
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
    std::string prefix = "tr(musig(";
    std::vector<std::string> parts;
    std::string musig_inner =
        external.substr(prefix.size(), external.find(")", 0) - prefix.size());
    boost::split(parts, musig_inner, boost::is_any_of(","),
                 boost::token_compress_off);
    m = parts.size();
  }
  std::vector<std::string> parts;
  boost::split(parts, external, boost::is_any_of(",{}()"),
               boost::token_compress_off);
  std::set<std::string> signerStr{};
  for (unsigned i = 0; i < parts.size(); ++i) {
    if (parts[i] == H_POINT || IsUnspendableXpub(parts[i])) continue;
    if (parts[i].size() < 20) continue;
    if (signerStr.count(parts[i])) continue;
    auto signer = ParseSignerString(parts[i]);
    signers.push_back(signer);
    signerStr.insert(parts[i]);
  }
  int n = signers.size();

  Wallet wallet({}, {}, m, n, signers, AddressType::TAPROOT,
                WalletType::MULTI_SIG, 0);
  wallet.set_wallet_template(t);
  return wallet;
}

std::optional<Wallet> ParseTrDescriptor(const std::string& desc,
                                        std::string& error) {
  std::vector<std::string> keypath;
  std::pair<int, int> eii;
  std::vector<std::string> subscripts;
  std::vector<int> depths;
  if (!ParseTapscriptTemplate(desc, keypath, eii, subscripts, depths, error)) {
    return std::nullopt;
  }
  if (subscripts.empty()) {
    // WalletType::SINGLE_SIG
    if (keypath.size() != 1 || keypath[0] == H_POINT ||
        IsUnspendableXpub(keypath[0])) {
      error = "invalid single-sig descriptor: " + desc;
      return std::nullopt;
    }
    return Wallet({}, {}, 1, 1, {ParseSignerString(keypath[0])},
                  AddressType::TAPROOT, WalletType::SINGLE_SIG, 0);
  }

  int keypath_m = keypath.size();
  std::vector<SingleSigner> signers;
  std::map<std::string, SingleSigner> signers_map;
  for (auto&& key : keypath) {
    if (key == H_POINT || IsUnspendableXpub(key)) {
      keypath_m = 0;
      continue;
    }
    signers.push_back(ParseSignerString(key));
    if (eii != std::make_pair(0,0)) signers.back().set_external_internal_index(eii);
    signers_map[key] = signers.back();
  }

  // WalletType::MINISCRIPT
  bool has_miniscript = false;
  for (auto& subscript : subscripts) {
    if (IsValidMusigTemplate(subscript)) {
      std::string inner = subscript.substr(9, subscript.find(")", 9) - 9);
      std::vector<std::string> keys = split(inner, ',');
      std::string eii_str = subscript.substr(subscript.find(")", 9) + 1);
      eii_str = eii_str.substr(0, eii_str.find(")"));
      eii = ParseExternalInternalIndex(eii_str);
      for (auto& key : keys) {
        signers.push_back(ParseSignerString(key));
        signers.back().set_external_internal_index(eii);
        signers_map[key] = signers.back();
      }
      continue;
    }
    has_miniscript = true;
    if (!Utils::IsValidMiniscriptTemplate(subscript, AddressType::TAPROOT)) {
      error = "invalid miniscript: " + subscript;
      return std::nullopt;
    }
    int tmp;
    auto keys = Utils::ParseSignerNames(subscript, tmp);
    for (auto&& key : keys) {
      signers.push_back(ParseSignerString(key));
      signers_map[key] = signers.back();
    }
  }

  auto script = Utils::TapscriptTemplateToTapscript(desc, signers_map, keypath);
  Wallet wallet(script, signers, AddressType::TAPROOT, keypath_m);
  if (has_miniscript) return wallet;

  // Maybe WalletType::MULTI_SIG
  WalletTemplate t = WalletTemplate::DEFAULT;
  auto miniscript_desc = wallet.get_descriptor(DescriptorPath::NONE);
  if (keypath.size() == 1 && keypath[0] == H_POINT) {
    t = WalletTemplate::DISABLE_KEY_PATH;
    miniscript_desc =
        GetDescriptorForMiniscript(wallet.get_miniscript(DescriptorPath::NONE),
                                   H_POINT, wallet.get_address_type());
  }
  Wallet musig_wallet = ParseMusigWallet(desc, t);
  auto musig_desc = musig_wallet.get_descriptor(DescriptorPath::NONE);
  return (musig_desc == miniscript_desc) ? musig_wallet : wallet;
}

std::optional<Wallet> ParseWshDescriptor(const std::string& desc,
                                         std::string& error) {
  // WalletType::MULTI_SIG
  if (desc.rfind("wsh(sortedmulti(", 0) == 0) {
    return ParseSortedMultiDescriptor(desc, AddressType::NATIVE_SEGWIT);
  }

  // WalletType::MINISCRIPT
  std::string prefix = "wsh(";
  auto script = desc.substr(prefix.size(), desc.size() - prefix.size() - 1);
  if (!Utils::IsValidMiniscriptTemplate(script, AddressType::NATIVE_SEGWIT)) {
    error = "Invalid miniscript: " + script;
    return std::nullopt;
  }
  int keypath_m = 0;
  auto keys = Utils::ParseSignerNames(script, keypath_m);
  std::vector<SingleSigner> signers;
  std::map<std::string, SingleSigner> signers_map;
  for (auto&& key : keys) {
    signers.push_back(ParseSignerString(key));
    signers_map[key] = signers.back();
  }
  script = Utils::MiniscriptTemplateToMiniscript(script, signers_map);
  return Wallet(script, signers, AddressType::NATIVE_SEGWIT, keypath_m);
}

static std::map<std::string, std::pair<AddressType, WalletType>>
    PREFIX_MATCHER = {
        {"sh(wsh(sortedmulti(",
         {AddressType::NESTED_SEGWIT, WalletType::MULTI_SIG}},
        {"sh(sortedmulti(", {AddressType::LEGACY, WalletType::MULTI_SIG}},
        {"sh(wpkh(", {AddressType::NESTED_SEGWIT, WalletType::SINGLE_SIG}},
        {"wpkh(", {AddressType::NATIVE_SEGWIT, WalletType::SINGLE_SIG}},
        {"pkh(", {AddressType::LEGACY, WalletType::SINGLE_SIG}}};

std::optional<Wallet> ParseOutputDescriptors(const std::string& descs,
                                             std::string& error) {
  std::string desc = split(descs, '\n')[0];
  desc = split(desc, '#')[0];

  if (desc.rfind("tr(", 0) == 0) {
    // AddressType::TAPROOT
    return ParseTrDescriptor(desc, error);
  } else if (desc.rfind("wsh(", 0) == 0) {
    // AddressType::NATIVE_SEGWIT
    return ParseWshDescriptor(desc, error);
  }

  for (auto&& [prefix, conf] : PREFIX_MATCHER) {
    if (desc.rfind(prefix, 0) == 0) {
      AddressType a = conf.first;
      WalletType w = conf.second;
      if (w == WalletType::SINGLE_SIG) {
        std::string inner =
            desc.substr(prefix.size(), desc.find(")", 0) - prefix.size());
        auto signer = ParseSignerString(inner);
        return Wallet({}, {}, 1, 1, {signer}, a, w, 0);
      } else {
        return ParseSortedMultiDescriptor(desc, a);
      }
    }
  }
  return std::nullopt;
}

static std::vector<DescriptorPath> DESCRIPTOR_PATHS = {
    DescriptorPath::EXTERNAL_ALL, DescriptorPath::EXTERNAL_INTERNAL,
    DescriptorPath::ANY, DescriptorPath::TEMPLATE};

std::optional<Wallet> ParseDescriptors(const std::string& descs,
                                       std::string& error) {
  using namespace boost::algorithm;
  try {
    auto wallet = ParseOutputDescriptors(descs, error);
    if (!wallet) return std::nullopt;

    // Verify the parsed wallet descriptor matches the input
    std::string in = GetDescriptorWithoutChecksum(split(descs, '\n')[0]);
    for (auto&& path : DESCRIPTOR_PATHS) {
      if (GetDescriptorWithoutChecksum(wallet->get_descriptor(path)) == in) {
        return wallet;
      }
    }
    error = "Failed to verify wallet descriptor";
    return std::nullopt;
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<Wallet> ParseJSONDescriptors(const std::string& json_str,
                                           std::string& error) {
  try {
    const auto json_descs = json::parse(json_str);
    if (auto desc_iter = json_descs.find("descriptor");
        desc_iter != json_descs.end()) {
      auto wallet = ParseDescriptors(*desc_iter, error);
      if (!wallet) return std::nullopt;

      if (auto name_iter = json_descs.find("label");
          name_iter != json_descs.end()) {
        wallet->set_name(*name_iter);
      }
      return wallet;
    }
    return std::nullopt;
  } catch (...) {
    return std::nullopt;
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

std::string GetUnspendableXpub(const std::vector<SingleSigner>& signers) {
  CExtPubKey xpub{};

  std::vector<std::vector<unsigned char>> pubkeys;
  pubkeys.reserve(signers.size());

  for (auto&& signer : signers) {
    auto pubkey = DecodeExtPubKey(signer.get_xpub()).pubkey;
    pubkeys.emplace_back(pubkey.begin(), pubkey.end());
  }

  std::sort(pubkeys.begin(), pubkeys.end());
  pubkeys.erase(std::unique(pubkeys.begin(), pubkeys.end()), pubkeys.end());

  CSHA256 hasher;
  for (auto&& pubkey : pubkeys) {
    hasher.Write(pubkey.data(), pubkey.size());
  }
  hasher.Finalize(xpub.chaincode.data());

  xpub.pubkey.Set(BIP341_NUMS_PUBKEY.begin(), BIP341_NUMS_PUBKEY.end());

  return EncodeExtPubKey(xpub);
}

bool IsUnspendableXpub(const std::string& xpub) {
  if (xpub.empty()) return false;
  auto pubkey = DecodeExtPubKey(split(xpub, '/')[0]).pubkey;
  return std::equal(pubkey.begin(), pubkey.end(), BIP341_NUMS_PUBKEY.begin(),
                    BIP341_NUMS_PUBKEY.end());
}

}  // namespace nunchuk
