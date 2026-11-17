/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */
#include "utils/onekey/bitcoin.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <key_io.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include "descriptor.h"
#include "utils/bitbox/bitcoin.hpp"

namespace nunchuk::onekey {
using json = nlohmann::json;

std::vector<uint32_t> ParseKeypath(const std::string& path) {
  std::string normalized = path;
  std::replace(normalized.begin(), normalized.end(), 'h', '\'');
  std::vector<uint32_t> result;
  if (!ParseHDKeypath(normalized, result) || result.empty() ||
      result.size() > 10) {
    throw std::invalid_argument("Invalid OneKey derivation path");
  }
  return result;
}

std::string CoinName(Chain chain) {
  if (chain == Chain::MAIN) return "Bitcoin";
  if (chain == Chain::TESTNET || chain == Chain::SIGNET) return "Testnet";
  if (chain == Chain::REGTEST) return "Regtest";
  throw std::invalid_argument("Unsupported OneKey network");
}

OneKeyDeviceInfo ParseDeviceInfo(const json& features) {
  OneKeyDeviceInfo result;
  if (features.contains("device_type")) {
    switch (features.at("device_type").get<uint32_t>()) {
      case 0:
        result.model = OneKeyModel::CLASSIC;
        break;
      case 1:
        result.model = OneKeyModel::CLASSIC1S;
        break;
      case 5:
        result.model = OneKeyModel::PRO;
        break;
    }
  } else {
    auto serial = features.value("serial", std::string{});
    std::transform(serial.begin(), serial.end(), serial.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (serial.starts_with("bi") || serial.starts_with("cl"))
      result.model = OneKeyModel::CLASSIC;
    if (serial.starts_with("pr")) result.model = OneKeyModel::PRO;
  }
  result.firmware_version = features.value("firmware_version", std::string{});
  if (result.firmware_version.empty())
    result.firmware_version = features.value("onekey_version", std::string{});
  if (result.firmware_version.empty()) {
    result.firmware_version =
        std::to_string(features.at("major").get<uint32_t>()) + "." +
        std::to_string(features.at("minor").get<uint32_t>()) + "." +
        std::to_string(features.at("patch").get<uint32_t>());
  }
  result.device_id = features.at("device_id");
  result.label = features.at("label");
  result.initialized = features.at("initialized");
  result.unlocked = features.at("unlocked");
  result.bootloader = features.at("bootloader");
  result.pin_protection = features.at("pin_protection");
  result.passphrase_protection = features.at("passphrase_protection");
  result.passphrase_on_device = features.at("passphrase_on_device");
  result.supports_raw_psbt =
      (result.model == OneKeyModel::PRO &&
       bitbox::FirmwareAtLeast(result.firmware_version, 4, 9, 3)) ||
      (result.model == OneKeyModel::CLASSIC1S &&
       bitbox::FirmwareAtLeast(result.firmware_version, 3, 10, 1));
  return result;
}

std::string ValidatePublicKey(const json& response,
                              const std::vector<uint32_t>& path) {
  const auto xpub = DecodeExtPubKey(Utils::SanitizeBIP32Input(
      response.at("xpub"), Utils::GetChain() == Chain::MAIN ? "xpub" : "tpub"));
  const auto& node = response.at("node");
  uint32_t parent = 0;
  for (auto byte : xpub.vchFingerprint) parent = (parent << 8) | byte;
  if (!xpub.pubkey.IsFullyValid() || xpub.nDepth != path.size() ||
      xpub.nChild != path.back() || node.at("depth") != xpub.nDepth ||
      node.at("child_num") != xpub.nChild || node.at("fingerprint") != parent ||
      node.at("chain_code") != HexStr(xpub.chaincode) ||
      node.at("public_key") != HexStr(xpub.pubkey)) {
    throw std::runtime_error("OneKey public key does not match its BIP32 node");
  }
  return EncodeExtPubKey(xpub);
}

std::string MasterFingerprint(const json& response) {
  uint32_t fingerprint;
  if (response.contains("root_fingerprint")) {
    fingerprint = response.at("root_fingerprint");
  } else if (response.at("node").at("depth") == 1) {
    fingerprint = response.at("node").at("fingerprint");
  } else {
    throw std::runtime_error("OneKey did not return a master fingerprint");
  }
  std::array<unsigned char, 4> bytes{};
  for (int i = 3; i >= 0; --i) {
    bytes[i] = fingerprint;
    fingerprint >>= 8;
  }
  return HexStr(bytes);
}

void ValidateWallet(const Wallet& wallet) {
  wallet.check_valid();
  const bool single = wallet.get_wallet_type() == WalletType::SINGLE_SIG;
  const bool multi = wallet.get_wallet_type() == WalletType::MULTI_SIG;
  if ((!single && !multi) ||
      wallet.get_wallet_template() != WalletTemplate::DEFAULT ||
      wallet.is_escrow() || wallet.get_n() > 15 ||
      wallet.get_address_type() == AddressType::ANY ||
      (multi && wallet.get_address_type() == AddressType::TAPROOT)) {
    throw std::invalid_argument(
        "OneKey supports standard singlesig and legacy/SegWit multisig "
        "wallets");
  }
  for (const auto& signer : wallet.get_signers()) {
    if (!DecodeExtPubKey(signer.get_xpub()).pubkey.IsFullyValid() ||
        ParseKeypath(signer.get_derivation_path()).size() > 8) {
      throw std::invalid_argument(
          "OneKey wallet requires account extended public keys");
    }
    const auto [external, internal] = signer.get_external_internal_index();
    if (external < 0 || internal < 0 || external == internal) {
      throw std::invalid_argument("Invalid OneKey wallet branches");
    }
  }
}

const SingleSigner& WalletSigner(const Wallet& wallet,
                                 const std::string& fingerprint) {
  const SingleSigner* result = nullptr;
  for (const auto& signer : wallet.get_signers()) {
    if (ParseHex(signer.get_master_fingerprint()) != ParseHex(fingerprint))
      continue;
    if (result)
      throw std::invalid_argument(
          "OneKey requires one account per device in a wallet");
    result = &signer;
  }
  if (!result)
    throw std::invalid_argument("OneKey wallet fingerprint mismatch");
  return *result;
}

std::string WalletAddress(const Wallet& wallet, bool change, uint32_t index) {
  if (index >= 0x80000000)
    throw std::invalid_argument("Invalid OneKey address index");
  FlatSigningProvider provider, derived;
  std::string error;
  auto descriptors =
      Parse(wallet.get_descriptor(change ? DescriptorPath::INTERNAL_ALL
                                         : DescriptorPath::EXTERNAL_ALL),
            provider, error, true);
  std::vector<CScript> scripts;
  CTxDestination destination;
  if (descriptors.size() != 1 ||
      !descriptors[0]->Expand(index, provider, scripts, derived) ||
      scripts.size() != 1 || !ExtractDestination(scripts[0], destination)) {
    throw std::invalid_argument("Could not derive OneKey wallet address");
  }
  return EncodeDestination(destination);
}

json AddressRequest(const Wallet& wallet, const SingleSigner& signer,
                    bool change, uint32_t index) {
  auto path = ParseKeypath(signer.get_derivation_path());
  auto branches = signer.get_external_internal_index();
  path.push_back(change ? branches.second : branches.first);
  path.push_back(index);
  std::string script_type;
  switch (wallet.get_address_type()) {
    case AddressType::LEGACY:
      script_type = wallet.get_n() > 1 ? "SPENDMULTISIG" : "SPENDADDRESS";
      break;
    case AddressType::NESTED_SEGWIT:
      script_type = "SPENDP2SHWITNESS";
      break;
    case AddressType::NATIVE_SEGWIT:
      script_type = "SPENDWITNESS";
      break;
    case AddressType::TAPROOT:
      script_type = "SPENDTAPROOT";
      break;
    default:
      throw std::invalid_argument("Unsupported OneKey address type");
  }
  json result{{"address_n", path}, {"script_type", script_type}};
  if (wallet.get_wallet_type() == WalletType::MULTI_SIG) {
    std::vector<std::pair<CPubKey, json>> keys;
    for (const auto& cosigner : wallet.get_signers()) {
      const auto account = DecodeExtPubKey(cosigner.get_xpub());
      auto child = account;
      branches = cosigner.get_external_internal_index();
      std::vector<uint32_t> suffix{
          static_cast<uint32_t>(change ? branches.second : branches.first),
          index};
      for (uint32_t n : suffix) {
        if (!child.Derive(child, n))
          throw std::invalid_argument("Could not derive OneKey multisig key");
      }
      keys.push_back({child.pubkey,
                      {{"node", cosigner.get_xpub()}, {"address_n", suffix}}});
    }
    std::sort(keys.begin(), keys.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    json pubkeys = json::array();
    for (const auto& [key, node] : keys) pubkeys.push_back(node);
    result["multisig"] = {{"m", wallet.get_m()}, {"pubkeys", pubkeys}};
  }
  return result;
}

}  // namespace nunchuk::onekey
