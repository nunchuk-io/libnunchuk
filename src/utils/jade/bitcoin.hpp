/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */

#ifndef NUNCHUK_JADE_BITCOIN_H
#define NUNCHUK_JADE_BITCOIN_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "utils/json.hpp"

namespace nunchuk {
enum class Chain;
class Wallet;
}  // namespace nunchuk

namespace nunchuk::jade {

enum class JadeWalletKind {
  SINGLE_SIG,
  MULTISIG,
  DESCRIPTOR,
};

struct JadeWalletConfig {
  JadeWalletKind kind = JadeWalletKind::SINGLE_SIG;
  std::string name;
  nlohmann::json registration_params;
};

std::string NetworkForChain(Chain chain);
bool FirmwareAtLeast(const std::string& version, int major, int minor,
                     int patch);
std::vector<uint32_t> ParseKeypath(const std::string& path);

JadeWalletConfig BuildWalletConfig(const Wallet& wallet,
                                   const std::string& root_fingerprint,
                                   Chain chain);

std::pair<std::string, nlohmann::json> RegistrationRequest(
    const JadeWalletConfig& config);
std::pair<std::string, nlohmann::json> RegistrationQuery(
    const JadeWalletConfig& config);
bool RegistrationMatches(const JadeWalletConfig& config,
                         const nlohmann::json& result);
nlohmann::json AddressRequest(const Wallet& wallet,
                              const JadeWalletConfig& config, Chain chain,
                              uint32_t index, bool change);

}  // namespace nunchuk::jade

#endif  // NUNCHUK_JADE_BITCOIN_H
