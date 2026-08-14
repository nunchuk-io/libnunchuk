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

#ifndef NUNCHUK_BITBOX_U2F_FRAMER_H
#define NUNCHUK_BITBOX_U2F_FRAMER_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace nunchuk::bitbox {

struct U2fDecodeResult {
  enum class Type {
    READ_MORE,
    COMPLETE,
    FAILED,
  };

  Type type = Type::READ_MORE;
  std::vector<unsigned char> payload;
  std::string error;
};

class U2fFramer {
 public:
  static constexpr size_t REPORT_SIZE = 64;
  static constexpr unsigned char FIRMWARE_COMMAND = 0xc1;
  static constexpr unsigned char BOOTLOADER_COMMAND = 0xc3;

  explicit U2fFramer(uint32_t cid,
                     unsigned char command = FIRMWARE_COMMAND);

  std::vector<std::vector<unsigned char>> encode(
      std::span<const unsigned char> payload) const;
  U2fDecodeResult decode(std::span<const unsigned char> reports);
  void reset();

 private:
  U2fDecodeResult decodeReport(std::span<const unsigned char> report);
  U2fDecodeResult fail(const std::string& message);

  uint32_t cid_;
  unsigned char command_;
  std::vector<unsigned char> pending_;
  std::optional<size_t> expected_length_;
  uint8_t expected_sequence_ = 0;
};

}  // namespace nunchuk::bitbox

#endif  // NUNCHUK_BITBOX_U2F_FRAMER_H
