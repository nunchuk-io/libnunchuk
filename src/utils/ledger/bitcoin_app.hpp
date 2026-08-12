/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (c) 2020 Enigmo.
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

#ifndef NUNCHUK_LEDGER_BITCOIN_APP_H
#define NUNCHUK_LEDGER_BITCOIN_APP_H

#include <cstddef>
#include <string>
#include <vector>

#include "utils/ledger/apdu_framer.hpp"
#include "utils/ledger/types.hpp"

namespace nunchuk::ledger::bitcoin {

std::vector<unsigned char> BuildGetAppAndVersionApdu();
std::vector<unsigned char> BuildCloseAppApdu();
std::vector<unsigned char> BuildOpenAppApdu(const std::string& app_name);
std::vector<unsigned char> BuildGetExtendedPublicKeyApdu(
    const std::string& derivation_path,
    const GetExtendedPublicKeyOptions& options);
std::vector<unsigned char> BuildGetMasterFingerprintApdu();
std::vector<unsigned char> BuildSignMessageApdu(
    const std::string& derivation_path, size_t message_length,
    const std::vector<unsigned char>& message_merkle_root);
std::vector<unsigned char> BuildRegisterWalletApdu(
    const std::vector<unsigned char>& serialized_wallet_policy);
std::vector<unsigned char> BuildGetWalletAddressApdu(
    bool check_on_device, const std::vector<unsigned char>& wallet_id,
    const std::vector<unsigned char>& wallet_hmac, bool change,
    uint32_t address_index);
std::vector<unsigned char> BuildSignPsbtApdu(
    const std::vector<unsigned char>& global_commitment, size_t inputs_count,
    const std::vector<unsigned char>& inputs_root, size_t outputs_count,
    const std::vector<unsigned char>& outputs_root,
    const std::vector<unsigned char>& wallet_id,
    const std::vector<unsigned char>& wallet_hmac);
std::vector<unsigned char> BuildContinueApdu(
    const std::vector<unsigned char>& payload);

GetExtendedPublicKeyResult ParseGetExtendedPublicKeyResponse(
    const ApduResponse& response);
GetMasterFingerprintResult ParseGetMasterFingerprintResponse(
    const ApduResponse& response);
SignMessageResult ParseMessageSignatureResponse(const ApduResponse& response);
std::string ParseRegisterWalletResponse(const ApduResponse& response);
WalletAddressResult ParseWalletAddressResponse(const ApduResponse& response);
void RequireSuccessResponse(const ApduResponse& response);

std::string StatusWordMessage(uint16_t status_word);

}  // namespace nunchuk::ledger::bitcoin

#endif  // NUNCHUK_LEDGER_BITCOIN_APP_H
