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

#ifndef NUNCHUK_STORAGE_APPDB_H
#define NUNCHUK_STORAGE_APPDB_H

#include "common.h"
#include "db.h"
#include <nunchuk.h>
#include <sqlcipher/sqlite3.h>
#include <string>
#include <vector>

namespace nunchuk {

class NunchukAppStateDb : public NunchukDb {
 public:
  using NunchukDb::NunchukDb;

  void Init();
  int GetChainTip() const;
  bool SetChainTip(int value);
  std::string GetSelectedWallet() const;
  bool SetSelectedWallet(const std::string &value);
  int64_t GetStorageVersion() const;
  bool SetStorageVersion(int64_t value);
  time_t GetLastSyncTs() const;
  bool SetLastSyncTs(time_t value);
  time_t GetLastExportTs() const;
  bool SetLastExportTs(time_t value);
  std::vector<std::string> GetDeletedSigners() const;
  bool AddDeletedSigners(const std::string &id);
  std::vector<std::string> GetDeletedWallets() const;
  bool AddDeletedWallets(const std::string &id);

 private:
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_APPDB_H
