/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */
#ifndef NUNCHUK_ONEKEY_MANAGER_HPP
#define NUNCHUK_ONEKEY_MANAGER_HPP

#include <memory>
#include <unordered_map>
#include "utils/onekey/onekey_session.hpp"

namespace nunchuk::onekey {
class OneKeyManager {
 public:
  explicit OneKeyManager(Nunchuk& nunchuk);
  OneKeySession& forSession(const std::string& session_id,
                            OneKeyTransport transport,
                            OneKeyProtocol protocol = OneKeyProtocol::V1);
  OneKeySession& forSession(const std::string& session_id);
  const OneKeySession& forSession(const std::string& session_id) const;

 private:
  mutable std::mutex mutex_;
  Chain chain_;
  std::unordered_map<std::string, std::shared_ptr<uint8_t>> sequences_;
  std::unordered_map<std::string, std::unique_ptr<OneKeySession>> sessions_;
};
}  // namespace nunchuk::onekey
#endif  // NUNCHUK_ONEKEY_MANAGER_HPP
