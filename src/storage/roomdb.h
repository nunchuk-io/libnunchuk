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
  bool SetSyncRoomId(const std::string& room_id);
  std::string GetSyncRoomId();
  bool HasActiveWallet(const std::string& room_id);
  RoomWallet GetActiveWallet(const std::string& room_id, bool fill_json = true);
  bool SetWallet(const RoomWallet& wallet);
  RoomWallet GetWallet(const std::string& init_event_id, bool fill_json = true);
  std::vector<RoomWallet> GetWallets(bool fill_json = true);
  std::vector<std::string> GetJoinIds(const RoomWallet& wallet);
  bool SetTransaction(const RoomTransaction& tx);
  RoomTransaction GetTransaction(const std::string& init_event_id);
  bool HasEvent(const std::string& event_id);
  bool SetEvent(const NunchukMatrixEvent& event);
  NunchukMatrixEvent GetEvent(const std::string& event_id);
  std::vector<RoomTransaction> GetPendingTransactions(
      const std::string& room_id);

 private:
  bool IsActiveWallet(const RoomWallet& wallet) const;
  std::string GetJsonContent(const RoomWallet& wallet);
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_MATRIXDB_H
