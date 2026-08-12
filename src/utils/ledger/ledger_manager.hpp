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

#ifndef NUNCHUK_LEDGER_MANAGER_H
#define NUNCHUK_LEDGER_MANAGER_H

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "utils/ledger/ledger_session.hpp"

namespace nunchuk::ledger {

class LedgerManager {
 public:
  LedgerSession& forSession(const std::string& session_id,
                            LedgerTransport transport);
  LedgerSession& forSession(const std::string& session_id);
  const LedgerSession& forSession(const std::string& session_id) const;

 private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::unique_ptr<LedgerSession>> sessions_;
};

}  // namespace nunchuk::ledger

#endif  // NUNCHUK_LEDGER_MANAGER_H
