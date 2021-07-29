// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_STORAGE_MATRIXDB_H
#define NUNCHUK_STORAGE_MATRIXDB_H

#include "common.h"
#include <nunchuk.h>
#include <nunchukmatrix.h>
#include <vector>
#include <string>
#include <map>
#include <set>

namespace nunchuk {

class NunchukMatrixDb {
 public:
  NunchukMatrixDb();
  bool HasWallet(const std::string& room_id);
  bool SetWallet(const std::string& room_id, const RoomWallet& wallet);
  RoomWallet GetWallet(const std::string& room_id);
  bool SetTransaction(const std::string& room_id, const std::string& init_id,
                      const RoomTransaction& tx);
  RoomTransaction GetTransaction(const std::string& init_id);
  bool SetEvent(const std::string event_id, const NunchukMatrixEvent& event);
  NunchukMatrixEvent GetEvent(const std::string& event_id);
  std::set<std::string> GetPendingTransactions(const std::string& room_id);

 private:
  std::map<std::string, RoomWallet> wallets_;
  std::map<std::string, RoomTransaction> txs_;
  std::map<std::string, NunchukMatrixEvent> events_;
  std::map<std::string, std::set<std::string>> pendings_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_MATRIXDB_H
