/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */

#ifndef NUNCHUK_ONEKEY_WIRE_FRAMER_HPP
#define NUNCHUK_ONEKEY_WIRE_FRAMER_HPP

#include <optional>
#include <span>
#include "utils/onekey/types.hpp"

namespace nunchuk::onekey {

struct WireMessage {
  uint16_t type;
  std::vector<unsigned char> data;
};

class WireFramer {
 public:
  static constexpr size_t MAX_MESSAGE_SIZE = 4 * 1024 * 1024;
  explicit WireFramer(OneKeyTransport transport);
  static std::vector<std::vector<unsigned char>> encode(
      uint16_t type, std::span<const unsigned char> data);
  // USB accepts arbitrary fragments of 64-byte reports. BLE accepts raw
  // notification bytes: only the first notification has the ?## header.
  std::optional<WireMessage> receive(std::span<const unsigned char> data);
  void reset();

 private:
  void append(std::span<const unsigned char> data);
  OneKeyTransport transport_;
  std::vector<unsigned char> packet_;
  std::vector<unsigned char> message_;
  std::optional<size_t> expected_size_;
};

}  // namespace nunchuk::onekey

#endif  // NUNCHUK_ONEKEY_WIRE_FRAMER_HPP
