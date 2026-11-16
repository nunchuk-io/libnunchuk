/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (c) 2026 Nunchuk.
 * Distributed under the GNU General Public License, version 3.
 */

#ifndef NUNCHUK_ONEKEY_QR_HPP
#define NUNCHUK_ONEKEY_QR_HPP

#include <nunchuk.h>
#include <string>
#include <vector>

namespace nunchuk {
namespace onekey {

// Decode single-part or animated crypto-hdkey/crypto-multi-accounts exports.
// Only Bitcoin public keys are returned; an export without any is rejected.
// Device tags are left unset for the caller to assign.
std::vector<SingleSigner> ParseSigners(const std::vector<std::string>& qr_data);

}  // namespace onekey
}  // namespace nunchuk

#endif  // NUNCHUK_ONEKEY_QR_HPP
