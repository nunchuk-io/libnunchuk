// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_STORAGE_MATRIXDB_H
#define NUNCHUK_STORAGE_MATRIXDB_H

#include "common.h"
#include "db.h"
#include <nunchukmatrix.h>
#include <sqlcipher/sqlite3.h>
#include <vector>
#include <string>
#include <map>
#include <set>

namespace nunchuk {

class NunchukRoomDb : public NunchukDb {
 public:
  using NunchukDb::NunchukDb;

  void Init();
  bool HasWallet(const std::string& room_id);
  bool SetWallet(const std::string& room_id, const RoomWallet& wallet);
  RoomWallet GetWallet(const std::string& room_id);
  std::vector<RoomWallet> GetWallets();
  bool SetTransaction(const std::string& room_id,
                      const std::string& init_event_id,
                      const RoomTransaction& tx);
  RoomTransaction GetTransaction(const std::string& init_event_id);
  bool SetEvent(const std::string event_id, const NunchukMatrixEvent& event);
  NunchukMatrixEvent GetEvent(const std::string& event_id);
  std::vector<RoomTransaction> GetPendingTransactions(
      const std::string& room_id);

 private:
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_MATRIXDB_H
