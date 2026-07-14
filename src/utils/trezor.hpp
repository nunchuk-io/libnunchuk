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

#ifndef NUNCHUK_TREZOR_H
#define NUNCHUK_TREZOR_H

#include "nunchuk.h"

namespace nunchuk {
std::string TrezorGetPublicKey(WalletType wallet_type, AddressType address_type,
                               int index);

SingleSigner TrezorParsePublicKeyResponse(const std::string &response);

std::string TrezorSignTransaction(const Wallet &wallet, const std::string &psbt,
                                  const std::string &xfp);

std::string TrezorParseSignTransactionResponse(const Wallet &wallet,
                                               const std::string &psbt,
                                               const std::string &xfp,
                                               const std::string &response);

std::string TrezorSignMessage(const SingleSigner &signer,
                              const std::string &message);

std::string TrezorGetSignMessagePath(const SingleSigner &signer);

std::pair<std::string, std::string> TrezorParseSignMessage(
    const std::string &response);

std::string TrezorGetAddress(const Wallet &wallet, const std::string &address,
                             const std::string &path);

std::string TrezorParseGetAddress(const std::string &response);
}  // namespace nunchuk

#endif
