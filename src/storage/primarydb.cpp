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

#include "primarydb.h"

namespace nunchuk {

void NunchukPrimaryDb::Init() {
  CreateTable();
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS PKEY("
                        "ACCOUNT TEXT PRIMARY KEY NOT NULL,"
                        "NAME    TEXT             NOT NULL,"
                        "XFP     TEXT             NOT NULL,"
                        "ADDR    TEXT             NOT NULL);",
                        NULL, 0, NULL));
}

bool NunchukPrimaryDb::AddPrimaryKey(const PrimaryKey& key) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO PKEY(ACCOUNT, XFP, ADDR, NAME)"
      "VALUES (?1, ?2, ?3, ?4) "
      "ON CONFLICT(ACCOUNT) DO UPDATE SET "
      "XFP=excluded.XFP, ADDR=excluded.ADDR, NAME=excluded.NAME;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, key.get_account().c_str(),
                    key.get_account().size(), NULL);
  sqlite3_bind_text(stmt, 2, key.get_master_fingerprint().c_str(),
                    key.get_master_fingerprint().size(), NULL);
  sqlite3_bind_text(stmt, 3, key.get_address().c_str(),
                    key.get_address().size(), NULL);
  sqlite3_bind_text(stmt, 4, key.get_name().c_str(), key.get_name().size(),
                    NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

std::vector<PrimaryKey> NunchukPrimaryDb::GetPrimaryKeys() const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT ACCOUNT, XFP, ADDR, NAME FROM PKEY;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);
  std::vector<PrimaryKey> keys;
  while (sqlite3_column_text(stmt, 0)) {
    std::string account = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string xfp = std::string((char*)sqlite3_column_text(stmt, 1));
    std::string address = std::string((char*)sqlite3_column_text(stmt, 2));
    std::string name = std::string((char*)sqlite3_column_text(stmt, 3));
    PrimaryKey key(name, xfp, account, address);
    keys.push_back(key);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return keys;
}

}  // namespace nunchuk
