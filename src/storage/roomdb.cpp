// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "roomdb.h"
#include <utils/json.hpp>
#include <utils/txutils.hpp>
#include <set>
#include <iostream>
#include <descriptor.h>

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

bool NunchukRoomDb::SetSyncRoomId(const std::string& room_id) {
  return PutString(DbKeys::SYNC_ROOM_ID, room_id);
}

std::string NunchukRoomDb::GetSyncRoomId() {
  return GetString(DbKeys::SYNC_ROOM_ID);
}

bool NunchukRoomDb::HasActiveWallet(const std::string& room_id) {
  auto wallets = GetWallets(false);
  for (auto&& wallet : wallets) {
    if (wallet.get_room_id() == room_id && IsActiveWallet(wallet)) {
      return true;
    }
  }
  return false;
}

RoomWallet NunchukRoomDb::GetActiveWallet(const std::string& room_id,
                                          bool fill_json) {
  auto wallets = GetWallets(fill_json);
  for (auto&& wallet : wallets) {
    if (wallet.get_room_id() == room_id && IsActiveWallet(wallet)) {
      return wallet;
    }
  }
  throw NunchukMatrixException(NunchukMatrixException::SHARED_WALLET_NOT_FOUND,
                               "shared wallet not found");
}

bool NunchukRoomDb::SetWallet(const RoomWallet& wallet) {
  auto init_event_id = wallet.get_init_event_id();
  json value{};
  value["room_id"] = wallet.get_room_id();
  value["wallet_id"] = wallet.get_wallet_id();
  value["init_event_id"] = wallet.get_init_event_id();
  value["join_event_ids"] = wallet.get_join_event_ids();
  value["leave_event_ids"] = wallet.get_leave_event_ids();
  value["finalize_event_id"] = wallet.get_finalize_event_id();
  value["cancel_event_id"] = wallet.get_cancel_event_id();
  value["delete_event_id"] = wallet.get_delete_event_id();
  value["ready_event_id"] = wallet.get_ready_event_id();
  std::string value_str = value.dump();

  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO WALLETS(ID, VALUE)"
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

RoomWallet NunchukRoomDb::GetWallet(const std::string& init_event_id,
                                    bool fill_json) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM WALLETS WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, init_event_id.c_str(), init_event_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    json value = json::parse(std::string((char*)sqlite3_column_text(stmt, 1)));
    RoomWallet rs{};
    rs.set_room_id(value["room_id"]);
    rs.set_wallet_id(value["wallet_id"]);
    rs.set_init_event_id(value["init_event_id"]);
    rs.set_join_event_ids(value["join_event_ids"]);
    rs.set_leave_event_ids(value["leave_event_ids"]);
    rs.set_finalize_event_id(value["finalize_event_id"]);
    rs.set_cancel_event_id(value["cancel_event_id"]);
    rs.set_delete_event_id(value["delete_event_id"]);
    if (value["ready_event_id"] != nullptr) {
      rs.set_ready_event_id(value["ready_event_id"]);
    }
    SQLCHECK(sqlite3_finalize(stmt));
    if (fill_json) {
      rs.set_join_event_ids(GetJoinIds(rs));
      rs.set_leave_event_ids({});
      rs.set_json_content(GetJsonContent(rs));
    }
    return rs;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    RoomWallet rs{};
    rs.set_init_event_id(init_event_id);
    return rs;
  }
}

std::vector<RoomWallet> NunchukRoomDb::GetWallets(bool fill_json) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT VALUE FROM WALLETS;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);
  std::vector<RoomWallet> rs;
  while (sqlite3_column_text(stmt, 0)) {
    json value = json::parse(std::string((char*)sqlite3_column_text(stmt, 0)));
    RoomWallet rw{};
    rw.set_room_id(value["room_id"]);
    rw.set_wallet_id(value["wallet_id"]);
    rw.set_init_event_id(value["init_event_id"]);
    rw.set_join_event_ids(value["join_event_ids"]);
    rw.set_leave_event_ids(value["leave_event_ids"]);
    rw.set_finalize_event_id(value["finalize_event_id"]);
    rw.set_cancel_event_id(value["cancel_event_id"]);
    rw.set_delete_event_id(value["delete_event_id"]);
    if (value["ready_event_id"] != nullptr) {
      rw.set_ready_event_id(value["ready_event_id"]);
    }
    rs.push_back(rw);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  if (fill_json) {
    for (auto&& rw : rs) {
      rw.set_join_event_ids(GetJoinIds(rw));
      rw.set_leave_event_ids({});
      rw.set_json_content(GetJsonContent(rw));
    }
  }
  return rs;
}

bool NunchukRoomDb::SetTransaction(const RoomTransaction& tx) {
  auto init_event_id = tx.get_init_event_id();
  json value{};
  value["room_id"] = tx.get_room_id();
  value["tx_id"] = tx.get_tx_id();
  value["wallet_id"] = tx.get_wallet_id();
  value["init_event_id"] = tx.get_init_event_id();
  value["sign_event_ids"] = tx.get_sign_event_ids();
  value["reject_event_ids"] = tx.get_reject_event_ids();
  value["broadcast_event_id"] = tx.get_broadcast_event_id();
  value["cancel_event_id"] = tx.get_cancel_event_id();
  value["ready_event_id"] = tx.get_ready_event_id();
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
    rs.set_room_id(value["room_id"]);
    rs.set_tx_id(value["tx_id"]);
    rs.set_wallet_id(value["wallet_id"]);
    rs.set_init_event_id(value["init_event_id"]);
    rs.set_sign_event_ids(value["sign_event_ids"]);
    rs.set_reject_event_ids(value["reject_event_ids"]);
    rs.set_broadcast_event_id(value["broadcast_event_id"]);
    rs.set_cancel_event_id(value["cancel_event_id"]);
    if (value["ready_event_id"] != nullptr) {
      rs.set_ready_event_id(value["ready_event_id"]);
    }
    rs.set_tx(GetTransaction(rs));
    SQLCHECK(sqlite3_finalize(stmt));
    return rs;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    RoomTransaction rs{};
    rs.set_init_event_id(init_event_id);
    return rs;
  }
}

bool NunchukRoomDb::HasEvent(const std::string& event_id) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM EVENTS WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, event_id.c_str(), event_id.size(), NULL);
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

bool NunchukRoomDb::SetEvent(const NunchukMatrixEvent& event) {
  json value{};
  auto event_id = event.get_event_id();
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
    throw NunchukMatrixException(NunchukMatrixException::EVENT_NOT_FOUND,
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
      rtx.set_room_id(value["room_id"]);
      rtx.set_tx_id(value["tx_id"]);
      rtx.set_wallet_id(value["wallet_id"]);
      rtx.set_init_event_id(value["init_event_id"]);
      rtx.set_sign_event_ids(value["sign_event_ids"]);
      rtx.set_reject_event_ids(value["reject_event_ids"]);
      rtx.set_broadcast_event_id(value["broadcast_event_id"]);
      rtx.set_cancel_event_id(value["cancel_event_id"]);
      if (value["ready_event_id"] != nullptr) {
        rtx.set_ready_event_id(value["ready_event_id"]);
      }
      rs.push_back(rtx);
    }
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  for (auto&& rt : rs) {
    rt.set_tx(GetTransaction(rt));
  }
  return rs;
}

bool NunchukRoomDb::IsActiveWallet(const RoomWallet& wallet) const {
  return wallet.get_cancel_event_id().empty() &&
         wallet.get_delete_event_id().empty();
}

std::vector<std::string> NunchukRoomDb::GetJoinIds(const RoomWallet& wallet) {
  std::set<std::string> leave_ids;
  for (auto&& leave_event_id : wallet.get_leave_event_ids()) {
    auto leave_event = GetEvent(leave_event_id);
    auto leave_body = json::parse(leave_event.get_content())["body"];
    std::string join_id = leave_body["io.nunchuk.relates_to"]["join_event_id"];
    leave_ids.insert(join_id);
  }
  std::set<std::string> keys;
  std::vector<std::string> join_event_ids;
  for (auto&& join_event_id : wallet.get_join_event_ids()) {
    if (leave_ids.count(join_event_id)) continue;
    auto join_event = GetEvent(join_event_id);
    std::string key = json::parse(join_event.get_content())["body"]["key"];
    if (keys.count(key)) continue;
    keys.insert(key);
    join_event_ids.push_back(join_event_id);
  }
  return join_event_ids;
}

std::string NunchukRoomDb::GetJsonContent(const RoomWallet& wallet) {
  json content;
  auto init_event = GetEvent(wallet.get_init_event_id());
  auto init_body = json::parse(init_event.get_content())["body"];
  content["name"] = init_body["name"];
  content["description"] = init_body["description"];
  content["m"] = init_body["m"];
  content["n"] = init_body["n"];
  content["address_type"] = init_body["address_type"];
  content["is_escrow"] = init_body["is_escrow"];
  content["init_sender"] = init_event.get_sender();
  content["init_ts"] = init_event.get_ts();
  if (!wallet.get_cancel_event_id().empty()) {
    content["canceled"] = true;
    return content.dump();
  }
  if (!wallet.get_finalize_event_id().empty()) {
    content["finalized"] = true;
    content["wallet_id"] = wallet.get_wallet_id();
  }

  auto join_event_ids = GetJoinIds(wallet);
  for (auto&& join_event_id : join_event_ids) {
    auto join_event = GetEvent(join_event_id);
    auto body = json::parse(join_event.get_content())["body"];
    std::string key = body["key"];
    std::string signer_type =
        body["type"] != nullptr ? body["type"].get<std::string>() : "";
    auto parse = ParseSignerString(key);
    json signer = {
        {"master_fingerprint", parse.get_master_fingerprint()},
        {"derivation_path", parse.get_derivation_path()},
        {"signer_type", signer_type},
        {"join_event_id", join_event_id},
        {"join_ts", join_event.get_ts()},
    };
    content["joins"][join_event.get_sender()].push_back(signer);
  }
  return content.dump();
}

Transaction NunchukRoomDb::GetTransaction(const RoomTransaction& rtx) {
  auto init_event = GetEvent(rtx.get_init_event_id());
  auto init_body = json::parse(init_event.get_content())["body"];
  auto psbt = DecodePsbt(init_body["psbt"]);
  auto wallet = GetActiveWallet(rtx.get_room_id());
  auto wallet_init_event = GetEvent(wallet.get_init_event_id());
  int m = json::parse(wallet_init_event.get_content())["body"]["m"];
  std::vector<SingleSigner> signers;
  auto join_event_ids = GetJoinIds(wallet);
  for (auto&& join_event_id : join_event_ids) {
    auto join_event = GetEvent(join_event_id);
    auto body = json::parse(join_event.get_content())["body"];
    std::string key = body["key"];
    signers.push_back(ParseSignerString(key));
  }

  return GetTransactionFromPartiallySignedTransaction(psbt, signers, m);
}

}  // namespace nunchuk
