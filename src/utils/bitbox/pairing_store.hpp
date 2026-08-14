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

#ifndef NUNCHUK_BITBOX_PAIRING_STORE_H
#define NUNCHUK_BITBOX_PAIRING_STORE_H

#include <array>
#include <mutex>
#include <span>
#include <vector>

namespace nunchuk {
class Nunchuk;
}

namespace nunchuk::bitbox {

class PairingStore {
 public:
  explicit PairingStore(Nunchuk& nunchuk);
  ~PairingStore();

  std::array<unsigned char, 32> appStaticPrivateKey() const;
  bool containsDevice(std::span<const unsigned char> public_key) const;
  void addDevice(std::span<const unsigned char> public_key);

 private:
  void loadOrCreate();
  void save() const noexcept;

  Nunchuk& nunchuk_;
  mutable std::mutex mutex_;
  std::array<unsigned char, 32> private_key_{};
  std::vector<std::array<unsigned char, 32>> devices_;
};

}  // namespace nunchuk::bitbox

#endif  // NUNCHUK_BITBOX_PAIRING_STORE_H
