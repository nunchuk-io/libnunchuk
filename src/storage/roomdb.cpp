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

#include "roomdb.h"
#include <utils/enumconverter.hpp>
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
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS RTXS("
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
                               "Shared wallet not found");
}

bool NunchukRoomDb::SetWallet(const RoomWallet& wallet) {
  auto init_event_id = wallet.get_init_event_id();
  std::string value_str = wallet.to_json();

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
    RoomWallet rs{std::string((char*)sqlite3_column_text(stmt, 1))};
    SQLCHECK(sqlite3_finalize(stmt));
    if (fill_json) FillWalletData(rs);
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
    RoomWallet rw{std::string((char*)sqlite3_column_text(stmt, 0))};
    rs.push_back(rw);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  if (fill_json) {
    for (auto&& rw : rs) FillWalletData(rw);
  }
  return rs;
}

bool NunchukRoomDb::SetTransaction(const RoomTransaction& tx) {
  auto init_event_id = tx.get_init_event_id();
  std::string value_str = tx.to_json();

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
    RoomTransaction rs{std::string((char*)sqlite3_column_text(stmt, 1))};
    // rs.set_tx(GetTransaction(rs));
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
  auto event_id = event.get_event_id();
  std::string value_str = event.to_json();

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
    NunchukMatrixEvent rs{std::string((char*)sqlite3_column_text(stmt, 1))};
    SQLCHECK(sqlite3_finalize(stmt));
    return rs;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw NunchukMatrixException(NunchukMatrixException::EVENT_NOT_FOUND,
                                 "Event not found");
  }
}

std::vector<RoomTransaction> NunchukRoomDb::GetPendingTransactions(
    const std::string& room_id) {
  auto wallet_id = GetActiveWallet(room_id).get_wallet_id();
  sqlite3_stmt* stmt;
  std::string sql = "SELECT VALUE FROM TXS;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);
  std::vector<RoomTransaction> rs;
  while (sqlite3_column_text(stmt, 0)) {
    RoomTransaction rtx{std::string((char*)sqlite3_column_text(stmt, 0))};
    if (wallet_id == rtx.get_wallet_id() &&
        rtx.get_broadcast_event_id().empty()) {
      rs.push_back(rtx);
    }
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  // for (auto&& rt : rs) {
  //   rt.set_tx(GetTransaction(rt));
  // }
  return rs;
}

bool NunchukRoomDb::SetTransactionNotify(const std::string& tx_id,
                                         const std::string& event_id) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO RTXS(ID, VALUE)"
      "VALUES (?1, ?2)"
      "ON CONFLICT(ID) DO UPDATE SET VALUE=excluded.VALUE;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_bind_text(stmt, 2, event_id.c_str(), event_id.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukRoomDb::HasTransactionNotify(const std::string& tx_id) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM RTXS WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
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

void NunchukRoomDb::FillWalletData(RoomWallet& wallet) {
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
  content["members"] = json::array();

  auto members = init_body["members"];
  for (auto&& key : members) {
    auto parse = ParseSignerString(key);
    json signer = {
        {"master_fingerprint", parse.get_master_fingerprint()},
        {"derivation_path", parse.get_derivation_path()},
        {"public_key", parse.get_public_key()},
        {"xpub", parse.get_xpub()},
    };
    content["members"].push_back(signer);
  }

  auto join_event_ids = GetJoinIds(wallet);
  wallet.set_chain(ChainFromStr(init_body["chain"]));
  wallet.set_join_event_ids(join_event_ids);
  wallet.set_leave_event_ids({});

  if (!wallet.get_cancel_event_id().empty()) {
    content["canceled"] = true;
    wallet.set_json_content(content.dump());
    return;
  }
  if (!wallet.get_finalize_event_id().empty()) {
    content["finalized"] = true;
    content["wallet_id"] = wallet.get_wallet_id();
  }

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
  wallet.set_json_content(content.dump());
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
