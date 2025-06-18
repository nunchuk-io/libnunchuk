/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (c) 2020 Enigmo.
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * libnunchuk is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libnunchuk. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NUNCHUK_MINISCRIPT_TIMELINE_H
#define NUNCHUK_MINISCRIPT_TIMELINE_H

#include <nunchuk.h>
#include <miniscript/compiler.h>
#include <vector>
#include <stdexcept>

namespace nunchuk {

class MiniscriptTimeline {
 public:
  explicit MiniscriptTimeline(const std::string& miniscript);
  Timelock::Based get_lock_type() const { return lock_type_; }
  std::vector<int64_t> get_absolute_locks() const { return absolute_locks_; }
  std::vector<int64_t> get_relative_locks() const { return relative_locks_; }
  std::vector<int64_t> get_locks(const UnspentOutput& utxo);

 private:
  void add_node(const ScriptNode& node);
  void detect_timelock_mixing(Timelock::Based new_type);

  ScriptNode node_;
  Timelock::Based lock_type_{Timelock::Based::NONE};
  std::vector<int64_t> absolute_locks_;
  std::vector<int64_t> relative_locks_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_MINISCRIPT_TIMELINE_H