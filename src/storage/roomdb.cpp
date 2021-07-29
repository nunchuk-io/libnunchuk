// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "roomdb.h"

namespace nunchuk {

NunchukMatrixDb::NunchukMatrixDb() {}

bool NunchukMatrixDb::HasWallet(const std::string& room_id) {
  return wallets_.find(room_id) != wallets_.end();
}

bool NunchukMatrixDb::SetWallet(const std::string& room_id,
                                const RoomWallet& wallet) {
  wallets_[room_id] = wallet;
  return true;
}

RoomWallet NunchukMatrixDb::GetWallet(const std::string& room_id) {
  if (wallets_.find(room_id) == wallets_.end()) {
    throw new NunchukMatrixException(
        NunchukMatrixException::SHARED_WALLET_NOT_FOUND,
        "shared wallet not found");
  }
  return wallets_[room_id];
}

bool NunchukMatrixDb::SetTransaction(const std::string& room_id,
                                     const std::string& init_id,
                                     const RoomTransaction& tx) {
  txs_[init_id] = tx;
  if (tx.get_broadcast_id().empty()) {
    pendings_[room_id].insert(init_id);
  } else {
    pendings_[room_id].erase(init_id);
  }
  return true;
}

RoomTransaction NunchukMatrixDb::GetTransaction(
    const std::string& init_id) {
  if (txs_.find(init_id) == txs_.end()) {
    throw new NunchukMatrixException(
        NunchukMatrixException::TRANSACTION_NOT_FOUND, "transaction not found");
  }
  return txs_[init_id];
}

bool NunchukMatrixDb::SetEvent(const std::string event_id,
                               const NunchukMatrixEvent& event) {
  events_[event_id] = event;
  return true;
}

NunchukMatrixEvent NunchukMatrixDb::GetEvent(const std::string& event_id) {
  if (events_.find(event_id) == events_.end()) {
    throw new NunchukMatrixException(NunchukMatrixException::EVENT_NOT_FOUND,
                                     "event not found");
  }
  return events_[event_id];
}

std::set<std::string> NunchukMatrixDb::GetPendingTransactions(
    const std::string& room_id) {
  return pendings_[room_id];
}

}  // namespace nunchuk
