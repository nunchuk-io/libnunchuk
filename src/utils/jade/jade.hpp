/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */

#ifndef NUNCHUK_JADE_H
#define NUNCHUK_JADE_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "utils/jade/bitcoin.hpp"
#include "utils/jade/http_client.hpp"
#include "utils/jade/jade_manager.hpp"
#include "utils/jade/jade_session.hpp"
#include "utils/jade/types.hpp"

namespace nunchuk::jade {

inline constexpr std::string_view BLE_SERVICE_UUID =
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
inline constexpr std::string_view BLE_WRITE_UUID =
    "6e400002-b5a3-f393-e0a9-e50e24dcca9e";
inline constexpr std::string_view BLE_NOTIFY_UUID =
    "6e400003-b5a3-f393-e0a9-e50e24dcca9e";
inline constexpr uint32_t USB_SERIAL_BAUD_RATE = 115200;

inline constexpr std::array<std::pair<uint16_t, uint16_t>, 6> USB_DEVICE_IDS{{
    {0x10c4, 0xea60},
    {0x1a86, 0x55d4},
    {0x0403, 0x6001},
    {0x1a86, 0x7523},
    {0x303a, 0x4001},
    {0x303a, 0x1001},
}};

constexpr bool IsJadeUsbDevice(uint16_t vendor_id, uint16_t product_id) {
  for (const auto& [vendor, product] : USB_DEVICE_IDS) {
    if (vendor_id == vendor && product_id == product) return true;
  }
  return false;
}

std::string HandlePinQr(const std::vector<std::string>& qr_data,
                        const std::string& certificate_file,
                        bool allow_custom_server = false);

std::vector<std::string> ExportPinQr(const std::string& pin,
                                     int fragment_len = 200);

}  // namespace nunchuk::jade

#endif  // NUNCHUK_JADE_H
