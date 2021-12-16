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
  bool SetTransactionNotify(const std::string& tx_id,
                            const std::string& event_id);
  bool HasTransactionNotify(const std::string& tx_id);

 private:
  bool IsActiveWallet(const RoomWallet& wallet) const;
  void FillWalletData(RoomWallet& wallet);
  Transaction GetTransaction(const RoomTransaction& rtx);
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_MATRIXDB_H
