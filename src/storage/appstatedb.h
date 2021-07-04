// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_STORAGE_APPDB_H
#define NUNCHUK_STORAGE_APPDB_H

#include "common.h"
#include "db.h"
#include <nunchuk.h>
#include <sqlcipher/sqlite3.h>
#include <string>

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

 private:
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_APPDB_H
