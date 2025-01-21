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

#include "groupdb.h"

namespace nunchuk {

void NunchukGroupDb::Init() {
  CreateTable();
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS LASTEVENT("
                        "GROUPID TEXT PRIMARY KEY NOT NULL,"
                        "EVENTID TEXT             NOT NULL);",
                        NULL, 0, NULL));
}

void NunchukGroupDb::SetDeviceInfo(const std::string &token,
                                   const std::string &uid) {
  PutString(DbKeys::GROUP_DEVICE_TOKEN, token);
  PutString(DbKeys::GROUP_DEVICE_UID, uid);
}

std::pair<std::string, std::string> NunchukGroupDb::GetDeviceInfo() const {
  return {GetString(DbKeys::GROUP_DEVICE_TOKEN),
          GetString(DbKeys::GROUP_DEVICE_UID)};
}

void NunchukGroupDb::SetEphemeralKey(const std::string &pub,
                                     const std::string &priv) {
  PutString(DbKeys::GROUP_EPHEMERAL_PUB, pub);
  PutString(DbKeys::GROUP_EPHEMERAL_PRIV, priv);
}

std::pair<std::string, std::string> NunchukGroupDb::GetEphemeralKey() const {
  return {GetString(DbKeys::GROUP_EPHEMERAL_PUB),
          GetString(DbKeys::GROUP_EPHEMERAL_PRIV)};
}

std::vector<std::string> NunchukGroupDb::GetSandboxIds() const {
  return GetListStr(DbKeys::GROUP_SANDBOX_LIST);
}

bool NunchukGroupDb::AddSandboxId(const std::string &id) {
  return AddToListStr(DbKeys::GROUP_SANDBOX_LIST, id);
}

bool NunchukGroupDb::RemoveSandboxId(const std::string &id) {
  return RemoveFromListStr(DbKeys::GROUP_SANDBOX_LIST, id);
}

std::vector<std::string> NunchukGroupDb::GetWalletIds() const {
  return GetListStr(DbKeys::GROUP_WALLET_LIST);
}

bool NunchukGroupDb::AddWalletId(const std::string &id) {
  return AddToListStr(DbKeys::GROUP_WALLET_LIST, id);
}

bool NunchukGroupDb::RemoveWalletId(const std::string &id) {
  return RemoveFromListStr(DbKeys::GROUP_WALLET_LIST, id);
}

void NunchukGroupDb::SetReadEvent(const std::string &group_id,
                                  const std::string &event_id) {
  sqlite3_stmt *stmt;
  std::string sql =
      "INSERT INTO LASTEVENT(GROUPID, EVENTID) VALUES (?1, ?2)"
      "ON CONFLICT(GROUPID) DO UPDATE SET EVENTID=excluded.EVENTID;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, group_id.c_str(), group_id.size(), NULL);
  sqlite3_bind_text(stmt, 2, event_id.c_str(), event_id.size(), NULL);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
}

std::string NunchukGroupDb::GetLastEvent(const std::string &group_id) const {
  sqlite3_stmt *stmt;
  std::string sql = "SELECT * FROM LASTEVENT WHERE GROUPID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, group_id.c_str(), group_id.size(), NULL);
  sqlite3_step(stmt);
  std::string rs{};
  if (sqlite3_column_text(stmt, 0)) {
    rs = std::string((char *)sqlite3_column_text(stmt, 1));
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

}  // namespace nunchuk
