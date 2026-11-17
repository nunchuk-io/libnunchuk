/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */
#include "utils/onekey/onekey_manager.hpp"
#include <stdexcept>

namespace nunchuk::onekey {
OneKeyManager::OneKeyManager(Nunchuk& nunchuk)
    : chain_(nunchuk.GetAppSettings().get_chain()) {}

OneKeySession& OneKeyManager::forSession(const std::string& id,
                                         OneKeyTransport transport) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto session = std::make_unique<OneKeySession>(chain_, transport);
  auto& result = *session;
  sessions_[id] = std::move(session);
  return result;
}

OneKeySession& OneKeyManager::forSession(const std::string& id) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = sessions_.find(id);
  if (it == sessions_.end())
    throw std::out_of_range("OneKey session not found: " + id);
  return *it->second;
}

const OneKeySession& OneKeyManager::forSession(const std::string& id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = sessions_.find(id);
  if (it == sessions_.end())
    throw std::out_of_range("OneKey session not found: " + id);
  return *it->second;
}
}  // namespace nunchuk::onekey
