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

#ifndef NUNCHUK_BITBOX_H
#define NUNCHUK_BITBOX_H

#include <optional>
#include <string>
#include <string_view>

#include <nunchuk.h>

#include "utils/bitbox/bitbox_manager.hpp"
#include "utils/bitbox/bitbox_session.hpp"
#include "utils/bitbox/bootloader.hpp"
#include "utils/bitbox/types.hpp"
#include "utils/rfc2440.hpp"

namespace nunchuk::bitbox {

// Pass the USB HID product string or the BitBox02 Nova BLE product value:
// - Android USB: pass UsbDevice::getProductName().
// - Android/iOS Bluetooth: read characteristic
//   9d1c9a77-8b03-4e49-8053-3955cda7da93 and pass the JSON `p` value.
// - Other USB hosts: pass the HID device product string.
std::optional<BitBoxEndpoint> IdentifyBitBoxEndpoint(
    std::string_view product_string);
std::string GetBitBoxSignMessagePath(const SingleSigner& signer);
std::string GetBitBoxSignMessageAddress(const SingleSigner& signer);

}  // namespace nunchuk::bitbox

#endif  // NUNCHUK_BITBOX_H
