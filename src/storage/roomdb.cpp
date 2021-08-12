// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "roomdb.h"
#include <utils/json.hpp>

using json = nlohmann::json;

namespace nunchuk {

void NunchukRoomDb::Init() {
  CreateTable();
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS WALLETS("
                        "ID TEXT PRIMARY KEY     NOT NULL,"
                        "VALUE          TEXT    NOT NULL);",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS TXS("
                        "ID TEXT PRIMARY KEY     NOT NULL,"
                        "VALUE          TEXT    NOT NULL);",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS EVENTS("
                        "ID TEXT PRIMARY KEY     NOT NULL,"
                        "VALUE          TEXT    NOT NULL);",
                        NULL, 0, NULL));
}

bool NunchukRoomDb::HasWallet(const std::string& room_id) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM WALLETS WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, room_id.c_str(), room_id.size(), NULL);
  sqlite3_step(stmt);
  std::string value_str;
  if (sqlite3_column_text(stmt, 0)) {
    SQLCHECK(sqlite3_finalize(stmt));
    return true;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    return false;
  }
}

bool NunchukRoomDb::SetWallet(const std::string& room_id,
                              const RoomWallet& wallet) {
  json value{};
  value["wallet_id"] = wallet.get_wallet_id();
  value["init_event_id"] = wallet.get_init_event_id();
  value["join_event_ids"] = wallet.get_join_event_ids();
  value["leave_event_ids"] = wallet.get_leave_event_ids();
  value["finalize_event_id"] = wallet.get_finalize_event_id();
  value["cancel_event_id"] = wallet.get_cancel_event_id();
  std::string value_str = value.dump();

  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO WALLETS(ID, VALUE)"
      "VALUES (?1, ?2)"
      "ON CONFLICT(ID) DO UPDATE SET VALUE=excluded.VALUE;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, room_id.c_str(), room_id.size(), NULL);
  sqlite3_bind_text(stmt, 2, value_str.c_str(), value_str.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

RoomWallet NunchukRoomDb::GetWallet(const std::string& room_id) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM WALLETS WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, room_id.c_str(), room_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    json value = json::parse(std::string((char*)sqlite3_column_text(stmt, 1)));
    RoomWallet rs{};
    rs.set_wallet_id(value["wallet_id"]);
    rs.set_init_event_id(value["init_event_id"]);
    rs.set_join_event_ids(value["join_event_ids"]);
    rs.set_leave_event_ids(value["leave_event_ids"]);
    rs.set_finalize_event_id(value["finalize_event_id"]);
    rs.set_cancel_event_id(value["cancel_event_id"]);
    SQLCHECK(sqlite3_finalize(stmt));
    return rs;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw new NunchukMatrixException(
        NunchukMatrixException::SHARED_WALLET_NOT_FOUND,
        "shared wallet not found");
  }
}

std::vector<RoomWallet> NunchukRoomDb::GetWallets() {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT VALUE FROM WALLETS;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);
  std::vector<RoomWallet> rs;
  while (sqlite3_column_text(stmt, 0)) {
    json value = json::parse(std::string((char*)sqlite3_column_text(stmt, 0)));
    RoomWallet rw{};
    rw.set_wallet_id(value["wallet_id"]);
    rw.set_init_event_id(value["init_event_id"]);
    rw.set_join_event_ids(value["join_event_ids"]);
    rw.set_leave_event_ids(value["leave_event_ids"]);
    rw.set_finalize_event_id(value["finalize_event_id"]);
    rw.set_cancel_event_id(value["cancel_event_id"]);
    rs.push_back(rw);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

bool NunchukRoomDb::SetTransaction(const std::string& room_id,
                                   const std::string& init_event_id,
                                   const RoomTransaction& tx) {
  json value{};
  value["tx_id"] = tx.get_tx_id();
  value["wallet_id"] = tx.get_wallet_id();
  value["init_event_id"] = tx.get_init_event_id();
  value["sign_event_ids"] = tx.get_sign_event_ids();
  value["reject_event_ids"] = tx.get_reject_event_ids();
  value["broadcast_event_id"] = tx.get_broadcast_event_id();
  value["cancel_event_id"] = tx.get_cancel_event_id();
  std::string value_str = value.dump();

  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO TXS(ID, VALUE)"
      "VALUES (?1, ?2)"
      "ON CONFLICT(ID) DO UPDATE SET VALUE=excluded.VALUE;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, init_event_id.c_str(), init_event_id.size(), NULL);
  sqlite3_bind_text(stmt, 2, value_str.c_str(), value_str.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

RoomTransaction NunchukRoomDb::GetTransaction(
    const std::string& init_event_id) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM TXS WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, init_event_id.c_str(), init_event_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    json value = json::parse(std::string((char*)sqlite3_column_text(stmt, 1)));
    RoomTransaction rs{};
    rs.set_tx_id(value["tx_id"]);
    rs.set_wallet_id(value["wallet_id"]);
    rs.set_init_event_id(value["init_event_id"]);
    rs.set_sign_event_ids(value["sign_event_ids"]);
    rs.set_reject_event_ids(value["reject_event_ids"]);
    rs.set_broadcast_event_id(value["broadcast_event_id"]);
    rs.set_cancel_event_id(value["cancel_event_id"]);
    SQLCHECK(sqlite3_finalize(stmt));
    return rs;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw new NunchukMatrixException(
        NunchukMatrixException::TRANSACTION_NOT_FOUND, "transaction not found");
  }
}

bool NunchukRoomDb::SetEvent(const std::string event_id,
                             const NunchukMatrixEvent& event) {
  json value{};
  value["type"] = event.get_type();
  value["content"] = event.get_content();
  value["event_id"] = event.get_event_id();
  value["room_id"] = event.get_room_id();
  value["sender"] = event.get_sender();
  value["ts"] = event.get_ts();
  std::string value_str = value.dump();

  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO EVENTS(ID, VALUE)"
      "VALUES (?1, ?2)"
      "ON CONFLICT(ID) DO UPDATE SET VALUE=excluded.VALUE;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, event_id.c_str(), event_id.size(), NULL);
  sqlite3_bind_text(stmt, 2, value_str.c_str(), value_str.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

NunchukMatrixEvent NunchukRoomDb::GetEvent(const std::string& event_id) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM EVENTS WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, event_id.c_str(), event_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    json value = json::parse(std::string((char*)sqlite3_column_text(stmt, 1)));
    NunchukMatrixEvent rs{};
    rs.set_type(value["type"]);
    rs.set_content(value["content"]);
    rs.set_event_id(value["event_id"]);
    rs.set_room_id(value["room_id"]);
    rs.set_sender(value["sender"]);
    rs.set_ts(value["ts"]);
    SQLCHECK(sqlite3_finalize(stmt));
    return rs;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw new NunchukMatrixException(NunchukMatrixException::EVENT_NOT_FOUND,
                                     "event not found");
  }
}

std::vector<RoomTransaction> NunchukRoomDb::GetPendingTransactions(
    const std::string& room_id) {
  auto wallet_id = GetWallet(room_id).get_wallet_id();
  sqlite3_stmt* stmt;
  std::string sql = "SELECT VALUE FROM TXS;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);
  std::vector<RoomTransaction> rs;
  while (sqlite3_column_text(stmt, 0)) {
    json value = json::parse(std::string((char*)sqlite3_column_text(stmt, 0)));
    if (wallet_id == value["wallet_id"].get<std::string>() &&
        value["broadcast_event_id"].get<std::string>().empty()) {
      RoomTransaction rtx{};
      rtx.set_tx_id(value["tx_id"]);
      rtx.set_wallet_id(value["wallet_id"]);
      rtx.set_init_event_id(value["init_event_id"]);
      rtx.set_sign_event_ids(value["sign_event_ids"]);
      rtx.set_reject_event_ids(value["reject_event_ids"]);
      rtx.set_broadcast_event_id(value["broadcast_event_id"]);
      rtx.set_cancel_event_id(value["cancel_event_id"]);
      rs.push_back(rtx);
    }
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

}  // namespace nunchuk
