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

#ifndef NUNCHUK_BITBOX_BOOTLOADER_H
#define NUNCHUK_BITBOX_BOOTLOADER_H

#include <cstddef>
#include <mutex>
#include <span>
#include <string>
#include <vector>

#include "utils/bitbox/types.hpp"
#include "utils/bitbox/u2f_framer.hpp"

namespace nunchuk::bitbox {

BitBoxFirmwareInfo InspectFirmware(
    std::span<const unsigned char> signed_firmware);

class BitBoxBootloaderSession {
 public:
  explicit BitBoxBootloaderSession(BitBoxProduct product);

  BitBoxStep upgradeFirmware(
      std::span<const unsigned char> signed_firmware);
  BitBoxStep reboot();
  BitBoxStep onData(std::span<const unsigned char> data);

 private:
  enum class Phase {
    IDLE,
    ERASE,
    WRITE_CHUNK,
    SIGNATURES,
  };

  BitBoxStep sendQuery(unsigned char command,
                       std::span<const unsigned char> data, Phase phase,
                       double progress);
  BitBoxStep sendChunk(double progress);
  BitBoxStep sendReboot();
  BitBoxStep fail(BitBoxErrorCode code, const std::string& message,
                  int device_code = 0);
  void reset();

  mutable std::mutex mutex_;
  const BitBoxProduct product_;
  U2fFramer framer_;
  Phase phase_ = Phase::IDLE;
  unsigned char expected_command_ = 0;
  bool awaiting_data_ = false;
  std::vector<unsigned char> firmware_;
  std::vector<unsigned char> signature_data_;
  size_t total_chunks_ = 0;
  size_t next_chunk_ = 0;
  double progress_ = 0;
};

}  // namespace nunchuk::bitbox

#endif  // NUNCHUK_BITBOX_BOOTLOADER_H
