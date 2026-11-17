/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */
#ifndef NUNCHUK_ONEKEY_BITCOIN_HPP
#define NUNCHUK_ONEKEY_BITCOIN_HPP

#include <nunchuk.h>
#include "utils/json.hpp"
#include "utils/onekey/types.hpp"

namespace nunchuk::onekey {

inline constexpr const char* BLE_SERVICE_UUID =
    "00000001-0000-1000-8000-00805f9b34fb";
inline constexpr const char* BLE_WRITE_UUID =
    "00000002-0000-1000-8000-00805f9b34fb";
inline constexpr const char* BLE_NOTIFY_UUID =
    "00000003-0000-1000-8000-00805f9b34fb";

std::vector<uint32_t> ParseKeypath(const std::string& path);
std::string CoinName(Chain chain);
OneKeyDeviceInfo ParseDeviceInfo(const nlohmann::json& features);
std::string ValidatePublicKey(const nlohmann::json& response,
                              const std::vector<uint32_t>& path);
std::string MasterFingerprint(const nlohmann::json& response);
const SingleSigner& WalletSigner(const Wallet& wallet,
                                 const std::string& fingerprint);
std::string WalletAddress(const Wallet& wallet, bool change, uint32_t index);
nlohmann::json AddressRequest(const Wallet& wallet, const SingleSigner& signer,
                              bool change, uint32_t index);
void ValidateWallet(const Wallet& wallet);

}  // namespace nunchuk::onekey
#endif  // NUNCHUK_ONEKEY_BITCOIN_HPP
