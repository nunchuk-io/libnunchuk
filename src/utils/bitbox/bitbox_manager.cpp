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

#include "utils/bitbox/bitbox_manager.hpp"

#include <stdexcept>
#include <tinyformat.h>
#include <utility>

#include <nunchuk.h>

#include "utils/bitbox/bootloader.hpp"
#include "utils/bitbox/bitbox_session.hpp"
#include "utils/bitbox/pairing_store.hpp"

namespace nunchuk::bitbox {

BitBoxManager::BitBoxManager(Nunchuk& nunchuk)
    : pairing_store_(std::make_shared<PairingStore>(nunchuk)),
      chain_(nunchuk.GetAppSettings().get_chain()) {}

BitBoxManager::~BitBoxManager() = default;

BitBoxSession& BitBoxManager::forSession(
    const std::string& session_id, BitBoxTransport transport) {
  std::lock_guard<std::mutex> lock(mutex_);
  bootloader_sessions_.erase(session_id);
  auto session =
      std::make_unique<BitBoxSession>(pairing_store_, chain_, transport);
  auto& result = *session;
  sessions_[session_id] = std::move(session);
  return result;
}

BitBoxSession& BitBoxManager::forSession(const std::string& session_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    throw std::out_of_range(
        strprintf("BitBox session not found: %s", session_id));
  }
  return *it->second;
}

const BitBoxSession& BitBoxManager::forSession(
    const std::string& session_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    throw std::out_of_range(
        strprintf("BitBox session not found: %s", session_id));
  }
  return *it->second;
}

BitBoxBootloaderSession& BitBoxManager::forBootloaderSession(
    const std::string& session_id, BitBoxProduct product) {
  std::lock_guard<std::mutex> lock(mutex_);
  sessions_.erase(session_id);
  auto session = std::make_unique<BitBoxBootloaderSession>(product);
  auto& result = *session;
  bootloader_sessions_[session_id] = std::move(session);
  return result;
}

BitBoxBootloaderSession& BitBoxManager::forBootloaderSession(
    const std::string& session_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = bootloader_sessions_.find(session_id);
  if (it == bootloader_sessions_.end()) {
    throw std::out_of_range(
        strprintf("BitBox bootloader session not found: %s", session_id));
  }
  return *it->second;
}

}  // namespace nunchuk::bitbox
