/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */

#include "utils/jade/bitcoin.hpp"

#include <algorithm>
#include <array>
#include <boost/algorithm/string/predicate.hpp>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <util/bip32.h>
#include <util/strencodings.h>

#include <nunchuk.h>

#include "utils/bip388.hpp"

namespace nunchuk::jade {
namespace {

constexpr size_t MAX_SIGNERS = 15;
constexpr size_t MAX_PATH_ELEMENTS = 16;

std::string ValidateRegistrationName(const std::string& name) {
  if (name.empty() || name.size() > 15) {
    throw std::invalid_argument(
        "Jade wallet registration name must contain 1-15 characters");
  }
  if (!std::all_of(name.begin(), name.end(), [](unsigned char value) {
        return value >= 33 && value <= 126;
      })) {
    throw std::invalid_argument(
        "Jade wallet registration name must contain printable non-space ASCII");
  }
  return name;
}

std::string MultisigVariant(AddressType address_type) {
  switch (address_type) {
    case AddressType::LEGACY:
      return "sh(multi(k))";
    case AddressType::NESTED_SEGWIT:
      return "sh(wsh(multi(k)))";
    case AddressType::NATIVE_SEGWIT:
      return "wsh(multi(k))";
    case AddressType::ANY:
    case AddressType::TAPROOT:
      throw std::invalid_argument(
          "Jade does not support this standard multisig address type");
  }
  throw std::invalid_argument("Invalid Jade multisig address type");
}

std::string SingleSigVariant(AddressType address_type) {
  switch (address_type) {
    case AddressType::LEGACY:
      return "pkh(k)";
    case AddressType::NESTED_SEGWIT:
      return "sh(wpkh(k))";
    case AddressType::NATIVE_SEGWIT:
      return "wpkh(k)";
    case AddressType::TAPROOT:
      return "tr(k)";
    case AddressType::ANY:
      throw std::invalid_argument(
          "Jade single-sig address type is unspecified");
  }
  throw std::invalid_argument("Invalid Jade single-sig address type");
}

void RequireDeviceSigner(const Wallet& wallet,
                         const std::string& root_fingerprint) {
  if (!IsHex(root_fingerprint) || ParseHex(root_fingerprint).size() != 4) {
    throw std::invalid_argument("Jade root fingerprint is invalid");
  }
  if (wallet.get_signers().empty()) {
    throw std::invalid_argument("Jade wallet has no signers");
  }
  if (std::none_of(wallet.get_signers().begin(), wallet.get_signers().end(),
                   [&](const SingleSigner& signer) {
                     return boost::algorithm::iequals(
                         signer.get_master_fingerprint(), root_fingerprint);
                   })) {
    throw std::invalid_argument("Jade wallet does not use this device");
  }
}

std::vector<uint32_t> AddressPath(const SingleSigner& signer, bool change,
                                  uint32_t index) {
  auto path = ParseKeypath(signer.get_derivation_path());
  if (path.size() > MAX_PATH_ELEMENTS - 2) {
    throw std::invalid_argument("Jade address derivation path is too long");
  }
  const auto [external, internal] = signer.get_external_internal_index();
  const int branch = change ? internal : external;
  if (branch < 0 || branch > static_cast<int>(0x7fffffffU)) {
    throw std::invalid_argument("Jade wallet branch must be unhardened");
  }
  path.push_back(static_cast<uint32_t>(branch));
  path.push_back(index);
  return path;
}

}  // namespace

std::string NetworkForChain(Chain chain) {
  switch (chain) {
    case Chain::MAIN:
      return "mainnet";
    case Chain::TESTNET:
    case Chain::SIGNET:
      return "testnet";
    case Chain::REGTEST:
      return "localtest";
  }
  throw std::invalid_argument("Unsupported Jade Bitcoin network");
}

bool FirmwareAtLeast(const std::string& version, int major, int minor,
                     int patch) {
  std::string_view remaining(version);
  if (!remaining.empty() &&
      (remaining.front() == 'v' || remaining.front() == 'V')) {
    remaining.remove_prefix(1);
  }
  std::array<int, 3> parsed{};
  for (size_t component = 0; component < parsed.size(); ++component) {
    if (remaining.empty() ||
        !std::isdigit(static_cast<unsigned char>(remaining.front()))) {
      return false;
    }
    int value = 0;
    while (!remaining.empty() &&
           std::isdigit(static_cast<unsigned char>(remaining.front()))) {
      value = value * 10 + (remaining.front() - '0');
      if (value > 100000) return false;
      remaining.remove_prefix(1);
    }
    parsed[component] = value;
    if (component + 1 != parsed.size()) {
      if (remaining.empty() || remaining.front() != '.') return false;
      remaining.remove_prefix(1);
    }
  }
  const std::array<int, 3> required{major, minor, patch};
  if (parsed != required) return parsed > required;
  if (remaining.empty()) return true;

  // Match the official app's ordering: an alpha/beta/rc label is older than
  // the release with the same numbers, while dirty/commit trailers are
  // development builds of that release.
  if (remaining.front() == '.') return false;
  if (remaining.front() != '-') return false;
  remaining.remove_prefix(1);
  if (remaining == "dirty") return true;
  const auto dash = remaining.find('-');
  return dash != std::string_view::npos && dash != 0 &&
         std::all_of(remaining.begin(), remaining.begin() + dash,
                     [](unsigned char value) { return std::isdigit(value); });
}

std::vector<uint32_t> ParseKeypath(const std::string& path) {
  std::string normalized = path;
  std::replace(normalized.begin(), normalized.end(), 'h', '\'');
  std::replace(normalized.begin(), normalized.end(), 'H', '\'');
  std::vector<uint32_t> result;
  if (!ParseHDKeypath(normalized, result)) {
    throw std::invalid_argument("Invalid Jade derivation path: " + path);
  }
  if (result.size() > MAX_PATH_ELEMENTS) {
    throw std::invalid_argument("Jade derivation path exceeds 16 elements");
  }
  return result;
}

JadeWalletConfig BuildWalletConfig(const Wallet& wallet,
                                   const std::string& root_fingerprint,
                                   Chain chain) {
  RequireDeviceSigner(wallet, root_fingerprint);
  if (wallet.is_escrow() || wallet.get_wallet_type() == WalletType::ESCROW) {
    throw std::invalid_argument("Jade does not support escrow wallets");
  }

  JadeWalletConfig result;
  if (wallet.get_wallet_type() == WalletType::SINGLE_SIG) {
    if (wallet.get_signers().size() != 1) {
      throw std::invalid_argument(
          "Jade single-sig wallet must have one signer");
    }
    SingleSigVariant(wallet.get_address_type());
    result.kind = JadeWalletKind::SINGLE_SIG;
    return result;
  }
  result.name = ValidateRegistrationName(wallet.get_name());

  if (wallet.get_wallet_type() == WalletType::MULTI_SIG) {
    if (wallet.get_signers().size() > MAX_SIGNERS || wallet.get_m() <= 0 ||
        wallet.get_m() > static_cast<int>(wallet.get_signers().size())) {
      throw std::invalid_argument(
          "Jade multisig policy is invalid or too large");
    }
    nlohmann::json descriptor{
        {"variant", MultisigVariant(wallet.get_address_type())},
        {"sorted", true},
        {"threshold", wallet.get_m()},
        {"signers", nlohmann::json::array()}};
    for (const auto& signer : wallet.get_signers()) {
      const auto fingerprint = ParseHex(signer.get_master_fingerprint());
      if (fingerprint.size() != 4) {
        throw std::invalid_argument("Jade wallet fingerprint is invalid");
      }
      descriptor["signers"].push_back(
          {{"fingerprint", nlohmann::json::binary(fingerprint)},
           {"derivation", ParseKeypath(signer.get_derivation_path())},
           {"xpub", signer.get_xpub()},
           {"path", nlohmann::json::array()}});
    }
    result.kind = JadeWalletKind::MULTISIG;
    result.registration_params = {{"network", NetworkForChain(chain)},
                                  {"multisig_name", result.name},
                                  {"descriptor", descriptor}};
    return result;
  }

  if (wallet.get_wallet_type() == WalletType::MINISCRIPT) {
    const auto policy = GetBip388Policy(wallet);
    if (policy.keys_info.empty() || policy.keys_info.size() > MAX_SIGNERS) {
      throw std::invalid_argument("Jade descriptor signer count is invalid");
    }
    if (policy.descriptor_template.find("musig(") != std::string::npos) {
      throw std::invalid_argument(
          "Jade does not support MuSig wallet policies");
    }
    if (policy.descriptor_template.find('*') == std::string::npos) {
      throw std::invalid_argument("Jade descriptor wallet must be ranged");
    }
    nlohmann::json datavalues = nlohmann::json::object();
    for (size_t index = 0; index < policy.keys_info.size(); ++index) {
      datavalues["@" + std::to_string(index)] = policy.keys_info[index];
    }
    result.kind = JadeWalletKind::DESCRIPTOR;
    result.registration_params = {{"network", NetworkForChain(chain)},
                                  {"descriptor_name", result.name},
                                  {"descriptor", policy.descriptor_template},
                                  {"datavalues", std::move(datavalues)}};
    return result;
  }

  throw std::invalid_argument("Jade does not support this wallet type");
}

std::pair<std::string, nlohmann::json> RegistrationRequest(
    const JadeWalletConfig& config) {
  switch (config.kind) {
    case JadeWalletKind::MULTISIG:
      return {"register_multisig", config.registration_params};
    case JadeWalletKind::DESCRIPTOR:
      return {"register_descriptor", config.registration_params};
    case JadeWalletKind::SINGLE_SIG:
      break;
  }
  throw std::invalid_argument("Jade single-sig wallets are not registered");
}

std::pair<std::string, nlohmann::json> RegistrationQuery(
    const JadeWalletConfig& config) {
  switch (config.kind) {
    case JadeWalletKind::MULTISIG:
      return {"get_registered_multisig",
              {{"multisig_name", config.name}, {"as_file", false}}};
    case JadeWalletKind::DESCRIPTOR:
      return {"get_registered_descriptor", {{"descriptor_name", config.name}}};
    case JadeWalletKind::SINGLE_SIG:
      break;
  }
  throw std::invalid_argument("Jade single-sig wallets are not registered");
}

bool RegistrationMatches(const JadeWalletConfig& config,
                         const nlohmann::json& result) {
  if (!result.is_object()) return false;
  if (config.kind == JadeWalletKind::MULTISIG) {
    if (result.value("multisig_name", std::string{}) != config.name ||
        !result.contains("descriptor") ||
        !result.at("descriptor").is_object()) {
      return false;
    }
    const auto& actual = result.at("descriptor");
    const auto& expected = config.registration_params.at("descriptor");
    for (auto it = expected.begin(); it != expected.end(); ++it) {
      if (!actual.contains(it.key()) || actual.at(it.key()) != it.value()) {
        return false;
      }
    }
    return true;
  }
  if (config.kind == JadeWalletKind::DESCRIPTOR) {
    return result.value("descriptor_name", std::string{}) == config.name &&
           result.value("descriptor", std::string{}) ==
               config.registration_params.at("descriptor") &&
           result.contains("datavalues") &&
           result.at("datavalues") ==
               config.registration_params.at("datavalues");
  }
  return true;
}

nlohmann::json AddressRequest(const Wallet& wallet,
                              const JadeWalletConfig& config, Chain chain,
                              uint32_t index, bool change) {
  nlohmann::json params{{"network", NetworkForChain(chain)}};
  switch (config.kind) {
    case JadeWalletKind::SINGLE_SIG:
      params["variant"] = SingleSigVariant(wallet.get_address_type());
      params["path"] = AddressPath(wallet.get_signers().at(0), change, index);
      return params;
    case JadeWalletKind::MULTISIG: {
      nlohmann::json paths = nlohmann::json::array();
      for (const auto& signer : wallet.get_signers()) {
        const auto [external, internal] = signer.get_external_internal_index();
        const int branch = change ? internal : external;
        if (branch < 0 || branch > static_cast<int>(0x7fffffffU)) {
          throw std::invalid_argument("Jade wallet branch must be unhardened");
        }
        paths.push_back({static_cast<uint32_t>(branch), index});
      }
      params["multisig_name"] = config.name;
      params["paths"] = std::move(paths);
      return params;
    }
    case JadeWalletKind::DESCRIPTOR:
      params["descriptor_name"] = config.name;
      params["branch"] = change ? 1 : 0;
      params["pointer"] = index;
      return params;
  }
  throw std::invalid_argument("Invalid Jade wallet kind");
}

}  // namespace nunchuk::jade
