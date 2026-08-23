/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */

#ifndef NUNCHUK_JADE_MANAGER_H
#define NUNCHUK_JADE_MANAGER_H

#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "utils/jade/jade_session.hpp"

namespace nunchuk {
class Nunchuk;
}

namespace nunchuk::jade {

class JadeManager {
 public:
  explicit JadeManager(Nunchuk& nunchuk);

  // Creates or replaces a session. Pass the effective transport payload limit
  // (BLE MTU - 3); Jade caps it at 512 bytes. Pass 0 to send each RPC in one
  // write, such as over USB serial.
  JadeSession& forSession(const std::string& session_id,
                          size_t max_write_size);
  JadeSession& forSession(const std::string& session_id);
  const JadeSession& forSession(const std::string& session_id) const;

 private:
  mutable std::mutex mutex_;
  Nunchuk& nunchuk_;
  std::unordered_map<std::string, std::unique_ptr<JadeSession>> sessions_;
};

}  // namespace nunchuk::jade

#endif  // NUNCHUK_JADE_MANAGER_H
