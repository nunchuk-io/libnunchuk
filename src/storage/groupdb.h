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

#ifndef NUNCHUK_STORAGE_GROUPDB_H
#define NUNCHUK_STORAGE_GROUPDB_H

#include "common.h"
#include "db.h"
#include <nunchuk.h>
#include <vector>
#include <string>

namespace nunchuk {

class NunchukGroupDb : public NunchukDb {
 public:
  using NunchukDb::NunchukDb;
  void Init();

  std::pair<std::string, std::string> GetDeviceInfo() const;
  void SetDeviceInfo(const std::string &token, const std::string &uid);

  std::pair<std::string, std::string> GetEphemeralKey() const;
  void SetEphemeralKey(const std::string &pub, const std::string &priv);

  std::vector<std::string> GetSandboxIds() const;
  bool AddSandboxId(const std::string &id);
  bool RemoveSandboxId(const std::string &id);

  std::vector<std::string> GetWalletIds() const;
  bool AddWalletId(const std::string &id);
  bool RemoveWalletId(const std::string &id);

  std::string GetLastEvent(const std::string &group_id) const;
  void SetReadEvent(const std::string &group_id, const std::string &event_id);

 private:
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_GROUPDB_H
