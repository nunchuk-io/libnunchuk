/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * libnunchuk is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libnunchuk. If not, see <http://www.gnu.org/licenses/>.
 */

#include "utils/bitbox/bitcoin.hpp"

#include <algorithm>
#include <array>
#include <base58.h>
#include <cctype>
#include <pubkey.h>
#include <stdexcept>
#include <string_view>
#include <util/bip32.h>
#include <util/strencodings.h>

#include <nunchuk.h>

#include "utils/bip32.hpp"
#include "utils/bip388.hpp"

namespace nunchuk::bitbox {
namespace {

std::array<int, 3> ParseVersion(const std::string& value) {
  std::string_view version(value);
  if (!version.empty() && version.front() == 'v') version.remove_prefix(1);
  std::array<int, 3> result{};
  for (size_t index = 0; index < result.size(); ++index) {
    if (version.empty() || !std::isdigit(version.front())) {
      throw std::invalid_argument("BitBox firmware version is invalid");
    }
    int component = 0;
    while (!version.empty() && std::isdigit(version.front())) {
      component = component * 10 + (version.front() - '0');
      if (component > 100000) {
        throw std::invalid_argument("BitBox firmware version is invalid");
      }
      version.remove_prefix(1);
    }
    result[index] = component;
    if (index + 1 != result.size()) {
      if (version.empty() || version.front() != '.') {
        throw std::invalid_argument("BitBox firmware version is invalid");
      }
      version.remove_prefix(1);
    }
  }
  if (!version.empty()) {
    throw std::invalid_argument("BitBox firmware version is invalid");
  }
  return result;
}

proto::XPub ConvertXpub(const std::string& encoded) {
  std::vector<unsigned char> serialized;
  if (!DecodeBase58Check(encoded, serialized,
                         BIP32_EXTKEY_WITH_VERSION_SIZE) ||
      serialized.size() != BIP32_EXTKEY_WITH_VERSION_SIZE) {
    throw std::invalid_argument("BitBox wallet contains an invalid xpub");
  }
  CExtPubKey decoded;
  decoded.DecodeWithVersion(serialized.data());
  if (!decoded.pubkey.IsFullyValid()) {
    throw std::invalid_argument("BitBox wallet contains an invalid xpub");
  }
  proto::XPub result;
  result.depth = decoded.nDepth;
  result.parent_fingerprint.assign(std::begin(decoded.vchFingerprint),
                                   std::end(decoded.vchFingerprint));
  result.child_number = decoded.nChild;
  result.chain_code.assign(decoded.chaincode.begin(), decoded.chaincode.end());
  result.public_key.assign(decoded.pubkey.begin(), decoded.pubkey.end());
  return result;
}

proto::ScriptConfig::SimpleType SimpleType(AddressType address_type) {
  switch (address_type) {
    case AddressType::NESTED_SEGWIT:
      return proto::ScriptConfig::SimpleType::P2WPKH_P2SH;
    case AddressType::NATIVE_SEGWIT:
      return proto::ScriptConfig::SimpleType::P2WPKH;
    case AddressType::TAPROOT:
      return proto::ScriptConfig::SimpleType::P2TR;
    case AddressType::ANY:
    case AddressType::LEGACY:
      throw std::invalid_argument("BitBox does not support this address type");
  }
  throw std::invalid_argument("BitBox address type is invalid");
}

bool EqualFingerprint(const std::string& lhs, const std::string& rhs) {
  if (lhs.size() != rhs.size()) return false;
  return std::equal(lhs.begin(), lhs.end(), rhs.begin(),
                    [](unsigned char a, unsigned char b) {
                      return std::tolower(a) == std::tolower(b);
                    });
}

WalletAccount MakeWalletAccount(const SingleSigner& signer,
                                std::optional<uint32_t> xpub_index) {
  const auto [external_index, internal_index] =
      signer.get_external_internal_index();
  if (external_index < 0 || internal_index < 0) {
    throw std::invalid_argument(
        "BitBox wallet address branches must be unhardened");
  }
  return {ParseKeypath(signer.get_derivation_path()), xpub_index,
          static_cast<uint32_t>(external_index),
          static_cast<uint32_t>(internal_index)};
}

}  // namespace

std::vector<uint32_t> ParseKeypath(const std::string& path) {
  std::string normalized = path;
  std::replace(normalized.begin(), normalized.end(), 'h', '\'');
  std::vector<uint32_t> result;
  if (!ParseHDKeypath(normalized, result)) {
    throw std::invalid_argument("Invalid BitBox derivation path: " + path);
  }
  return result;
}

proto::Coin CoinForChain(Chain chain) {
  switch (chain) {
    case Chain::MAIN:
      return proto::Coin::BTC;
    case Chain::REGTEST:
      return proto::Coin::RBTC;
    case Chain::TESTNET:
    case Chain::SIGNET:
      return proto::Coin::TBTC;
  }
  throw std::invalid_argument("Unsupported BitBox chain");
}

bool FirmwareAtLeast(const std::string& version, int major, int minor,
                     int patch) {
  return ParseVersion(version) >= std::array<int, 3>{major, minor, patch};
}

bool FirmwareBefore(const std::string& version, int major, int minor,
                    int patch) {
  return ParseVersion(version) < std::array<int, 3>{major, minor, patch};
}

WalletConfig BuildWalletConfig(const Wallet& wallet,
                               const std::string& root_fingerprint) {
  if (!IsHex(root_fingerprint) || ParseHex(root_fingerprint).size() != 4) {
    throw std::invalid_argument("BitBox root fingerprint is invalid");
  }
  if (wallet.get_signers().empty()) {
    throw std::invalid_argument("BitBox wallet has no signers");
  }

  WalletConfig result;
  if (wallet.get_wallet_type() == WalletType::SINGLE_SIG) {
    if (wallet.get_signers().size() != 1 ||
        !EqualFingerprint(wallet.get_signers()[0].get_master_fingerprint(),
                          root_fingerprint)) {
      throw std::invalid_argument("BitBox single-sig wallet does not use this device");
    }
    result.script_config.kind = proto::ScriptConfig::Kind::SIMPLE;
    result.script_config.simple_type = SimpleType(wallet.get_address_type());
    result.accounts.push_back(
        MakeWalletAccount(wallet.get_signers()[0], std::nullopt));
    return result;
  }

  if (wallet.get_wallet_type() == WalletType::MULTI_SIG) {
    if (wallet.get_address_type() != AddressType::NESTED_SEGWIT &&
        wallet.get_address_type() != AddressType::NATIVE_SEGWIT) {
      throw std::invalid_argument(
          "BitBox multisig supports native or nested SegWit only");
    }
    result.script_config.kind = proto::ScriptConfig::Kind::MULTISIG;
    result.script_config.threshold = wallet.get_m();
    result.script_config.multisig_type =
        wallet.get_address_type() == AddressType::NATIVE_SEGWIT
            ? proto::ScriptConfig::MultisigType::P2WSH
            : proto::ScriptConfig::MultisigType::P2WSH_P2SH;
    for (size_t index = 0; index < wallet.get_signers().size(); ++index) {
      const auto& signer = wallet.get_signers()[index];
      result.script_config.xpubs.push_back(ConvertXpub(signer.get_xpub()));
    }
    for (size_t index = 0; index < wallet.get_signers().size(); ++index) {
      const auto& signer = wallet.get_signers()[index];
      if (EqualFingerprint(signer.get_master_fingerprint(), root_fingerprint)) {
        result.accounts.push_back(MakeWalletAccount(
            signer, static_cast<uint32_t>(index)));
      }
    }
    if (result.accounts.empty()) {
      throw std::invalid_argument("BitBox multisig wallet does not use this device");
    }
    return result;
  }

  if (wallet.get_wallet_type() == WalletType::MINISCRIPT) {
    const auto policy = GetBip388Policy(wallet);
    if (policy.descriptor_template.find("musig(") != std::string::npos) {
      throw std::invalid_argument("BitBox does not support MuSig wallet policies");
    }
    result.script_config.kind = proto::ScriptConfig::Kind::POLICY;
    result.script_config.policy = policy.descriptor_template;
    for (const auto& key_info : policy.keys_info) {
      proto::KeyOrigin key;
      const auto signer = std::find_if(
          wallet.get_signers().begin(), wallet.get_signers().end(),
          [&](const SingleSigner& candidate) {
            return candidate.get_descriptor() == key_info;
          });
      if (signer != wallet.get_signers().end()) {
        key.root_fingerprint = ParseHex(signer->get_master_fingerprint());
        if (key.root_fingerprint.size() != 4) {
          throw std::invalid_argument(
              "BitBox policy key fingerprint is invalid");
        }
        key.keypath = ParseKeypath(signer->get_derivation_path());
        key.xpub = ConvertXpub(signer->get_xpub());
        if (EqualFingerprint(signer->get_master_fingerprint(),
                             root_fingerprint)) {
          const auto duplicate = std::find_if(
              result.accounts.begin(), result.accounts.end(),
              [&](const WalletAccount& account) {
                return account.keypath == key.keypath;
              });
          if (duplicate == result.accounts.end()) {
            result.accounts.push_back(
                MakeWalletAccount(*signer, std::nullopt));
          }
        }
      } else {
        // BIP388 permits a key without origin information. Nunchuk uses one
        // for the unspendable internal key in Taproot script-only wallets.
        key.xpub = ConvertXpub(key_info);
      }
      result.script_config.keys.push_back(std::move(key));
    }
    if (result.accounts.empty()) {
      throw std::invalid_argument("BitBox policy wallet does not use this device");
    }
    return result;
  }

  throw std::invalid_argument("BitBox does not support this wallet type");
}

proto::ScriptConfig ScriptConfigForAccount(const WalletConfig& wallet,
                                           size_t account_index) {
  if (account_index >= wallet.accounts.size()) {
    throw std::invalid_argument("BitBox wallet account index is invalid");
  }
  auto result = wallet.script_config;
  if (wallet.accounts[account_index].xpub_index.has_value()) {
    result.our_xpub_index = *wallet.accounts[account_index].xpub_index;
  }
  return result;
}

proto::ScriptConfigWithKeypath BuildMessageConfig(
    const std::string& derivation_path) {
  proto::ScriptConfigWithKeypath result;
  result.keypath = ParseKeypath(derivation_path);
  if (result.keypath.empty()) {
    throw std::invalid_argument("BitBox message path is empty");
  }
  result.script_config.kind = proto::ScriptConfig::Kind::SIMPLE;
  const auto bip32_type = GetBip32Type(WriteHDKeypath(result.keypath));
  if (bip32_type == "bip49") {
    result.script_config.simple_type =
        proto::ScriptConfig::SimpleType::P2WPKH_P2SH;
  } else if (bip32_type == "bip84") {
    result.script_config.simple_type = proto::ScriptConfig::SimpleType::P2WPKH;
  } else {
    throw std::invalid_argument(
        "BitBox message signing supports BIP49 and BIP84 paths only");
  }
  return result;
}

std::vector<uint32_t> BuildAddressKeypath(const WalletConfig& wallet,
                                          bool change, uint32_t index) {
  if (wallet.accounts.empty()) {
    throw std::invalid_argument("BitBox wallet has no account keypath");
  }
  const auto& account = wallet.accounts.front();
  auto result = account.keypath;
  result.push_back(change ? account.internal_index : account.external_index);
  result.push_back(index);
  return result;
}

std::string ValidateWalletName(const std::string& name) {
  const auto first = name.find_first_not_of(' ');
  if (first == std::string::npos) {
    throw std::invalid_argument("BitBox wallet name is empty");
  }
  const auto last = name.find_last_not_of(' ');
  const auto result = name.substr(first, last - first + 1);
  if (result.size() > 30 ||
      !std::all_of(result.begin(), result.end(), [](unsigned char value) {
        return value >= 0x20 && value <= 0x7e;
      })) {
    throw std::invalid_argument(
        "BitBox wallet name must be at most 30 printable ASCII characters");
  }
  return result;
}

}  // namespace nunchuk::bitbox
