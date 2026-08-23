/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */

#include "utils/jade/jade_manager.hpp"

#include <stdexcept>
#include <utility>

#include <nunchuk.h>

namespace nunchuk::jade {

JadeManager::JadeManager(Nunchuk& nunchuk) : nunchuk_(nunchuk) {}

JadeSession& JadeManager::forSession(const std::string& session_id,
                                     size_t max_write_size) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto settings = nunchuk_.GetAppSettings();
  auto session = std::make_unique<JadeSession>(settings.get_chain(),
                                               settings.get_certificate_file(),
                                               max_write_size);
  auto& result = *session;
  sessions_[session_id] = std::move(session);
  return result;
}

JadeSession& JadeManager::forSession(const std::string& session_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    throw std::out_of_range("Jade session not found: " + session_id);
  }
  return *it->second;
}

const JadeSession& JadeManager::forSession(
    const std::string& session_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    throw std::out_of_range("Jade session not found: " + session_id);
  }
  return *it->second;
}

}  // namespace nunchuk::jade
