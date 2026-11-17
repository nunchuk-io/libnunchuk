/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */

#ifndef NUNCHUK_ONEKEY_WIRE_FRAMER_HPP
#define NUNCHUK_ONEKEY_WIRE_FRAMER_HPP

#include <memory>
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

// Pro 2 uses an independent frame sequence and CRC-protected byte stream.
class V2Framer {
 public:
  static constexpr size_t MAX_FRAME_SIZE = 4200;
  explicit V2Framer(
      OneKeyTransport transport,
      std::shared_ptr<uint8_t> sequence = std::make_shared<uint8_t>(0));
  std::vector<std::vector<unsigned char>> encode(
      uint16_t type, std::span<const unsigned char> data);
  std::optional<WireMessage> receive(std::span<const unsigned char> data);
  void reset();

 private:
  uint8_t router_;
  std::shared_ptr<uint8_t> sequence_;
  uint8_t pending_sequence_ = 0;
  uint8_t last_response_sequence_ = 0;
  std::vector<unsigned char> buffer_;
};

}  // namespace nunchuk::onekey

#endif  // NUNCHUK_ONEKEY_WIRE_FRAMER_HPP
