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

#ifndef NUNCHUK_BITBOX_BITCOIN_H
#define NUNCHUK_BITBOX_BITCOIN_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "utils/bitbox/protobuf.hpp"

namespace nunchuk {
enum class Chain;
class Wallet;
}

namespace nunchuk::bitbox {

inline constexpr const char* BLE_SERVICE_UUID =
    "e1511a45-f3db-44c0-82b8-6c880790d1f1";
inline constexpr const char* BLE_WRITE_UUID =
    "799d485c-d354-4ed0-b577-f8ee79ec275a";
inline constexpr const char* BLE_NOTIFY_UUID =
    "419572a5-9f53-4eb1-8db7-61bcab928867";
inline constexpr const char* BLE_PRODUCT_INFO_UUID =
    "9d1c9a77-8b03-4e49-8053-3955cda7da93";

struct WalletAccount {
  std::vector<uint32_t> keypath;
  std::optional<uint32_t> xpub_index;
  uint32_t external_index = 0;
  uint32_t internal_index = 1;
};

struct WalletConfig {
  proto::ScriptConfig script_config;
  std::vector<WalletAccount> accounts;
};

std::vector<uint32_t> ParseKeypath(const std::string& path);
proto::Coin CoinForChain(Chain chain);
bool FirmwareAtLeast(const std::string& version, int major, int minor,
                     int patch);
bool FirmwareBefore(const std::string& version, int major, int minor,
                    int patch);

WalletConfig BuildWalletConfig(const Wallet& wallet,
                               const std::string& root_fingerprint);
proto::ScriptConfig ScriptConfigForAccount(const WalletConfig& wallet,
                                           size_t account_index);
proto::ScriptConfigWithKeypath BuildMessageConfig(
    const std::string& derivation_path);
std::vector<uint32_t> BuildAddressKeypath(const WalletConfig& wallet,
                                          bool change, uint32_t index);
std::string ValidateWalletName(const std::string& name);

}  // namespace nunchuk::bitbox

#endif  // NUNCHUK_BITBOX_BITCOIN_H
