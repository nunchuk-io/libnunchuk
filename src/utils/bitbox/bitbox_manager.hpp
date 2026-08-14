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

#ifndef NUNCHUK_BITBOX_MANAGER_H
#define NUNCHUK_BITBOX_MANAGER_H

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace nunchuk {
class Nunchuk;
enum class Chain;
}

namespace nunchuk::bitbox {

class BitBoxBootloaderSession;
class BitBoxSession;
class PairingStore;
enum class BitBoxProduct;
enum class BitBoxTransport;

class BitBoxManager {
 public:
  explicit BitBoxManager(Nunchuk& nunchuk);
  ~BitBoxManager();

  BitBoxSession& forSession(const std::string& session_id,
                            BitBoxTransport transport);
  BitBoxSession& forSession(const std::string& session_id);
  const BitBoxSession& forSession(const std::string& session_id) const;
  BitBoxBootloaderSession& forBootloaderSession(
      const std::string& session_id, BitBoxProduct product);
  BitBoxBootloaderSession& forBootloaderSession(
      const std::string& session_id);

 private:
  mutable std::mutex mutex_;
  std::shared_ptr<PairingStore> pairing_store_;
  Chain chain_;
  std::unordered_map<std::string, std::unique_ptr<BitBoxSession>> sessions_;
  std::unordered_map<std::string, std::unique_ptr<BitBoxBootloaderSession>>
      bootloader_sessions_;
};

}  // namespace nunchuk::bitbox

#endif  // NUNCHUK_BITBOX_MANAGER_H
