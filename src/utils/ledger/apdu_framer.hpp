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

#ifndef NUNCHUK_LEDGER_APDU_FRAMER_H
#define NUNCHUK_LEDGER_APDU_FRAMER_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "utils/ledger/types.hpp"

namespace nunchuk::ledger {

struct ApduResponse {
  std::vector<unsigned char> data;
  uint16_t status_word = SW_NONE;
};

std::vector<unsigned char> SerializeApdu(uint8_t cla, uint8_t ins, uint8_t p1,
                                         uint8_t p2,
                                         std::span<const unsigned char> data);
void AppendLvString(std::vector<unsigned char>& out, std::string_view value,
                    std::string_view field_name);
std::string ReadLvString(const std::vector<unsigned char>& data,
                         size_t& offset, std::string_view context,
                         std::string_view field_name);

struct ApduDecodeResult {
  enum class Type {
    READ_MORE,
    COMPLETE,
    FAILED,
  };

  Type type = Type::READ_MORE;
  ApduResponse response;
  LedgerError error;
};

class ApduFramer {
 public:
  explicit ApduFramer(LedgerTransport transport);

  std::vector<std::vector<unsigned char>> encode(
      const std::vector<unsigned char>& apdu) const;
  ApduDecodeResult decode(const std::vector<unsigned char>& frame);
  void setPacketSize(size_t packet_size);
  void reset();

 private:
  size_t packetSize() const;
  bool hasChannel() const;
  bool hasPadding() const;
  size_t headerSize(size_t frame_index) const;

  LedgerTransport transport_;
  size_t packet_size_ = 0;
  std::vector<unsigned char> pending_;
  std::optional<size_t> expected_length_;
  size_t expected_index_ = 0;
};

}  // namespace nunchuk::ledger

#endif  // NUNCHUK_LEDGER_APDU_FRAMER_H
