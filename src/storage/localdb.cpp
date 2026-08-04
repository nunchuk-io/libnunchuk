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

#include "localdb.h"

namespace nunchuk {

void NunchukLocalDb::Init() {
  CreateTable();
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS SECNONCES("
                        "SESSION TEXT PRIMARY KEY NOT NULL,"
                        "NONCE   TEXT             NOT NULL);",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS SIGNPATH("
                        "TXID    TEXT PRIMARY KEY NOT NULL,"
                        "VALUE   INT              NOT NULL);",
                        NULL, 0, NULL));
}

void NunchukLocalDb::SetMuSig2SecNonce(
    const uint256& session_id, const std::string& encrypted_nonce) const {
  std::string key = session_id.GetHex();
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO SECNONCES(SESSION, NONCE) VALUES (?1, ?2)"
      "ON CONFLICT(SESSION) DO UPDATE SET NONCE=excluded.NONCE;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, key.c_str(), key.size(), NULL);
  sqlite3_bind_text(stmt, 2, encrypted_nonce.c_str(), encrypted_nonce.size(),
                    NULL);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
}

std::string NunchukLocalDb::GetMuSig2SecNonce(const uint256& session_id) const {
  std::string key = session_id.GetHex();
  std::string value;
  sqlite3_stmt* stmt = nullptr;

  // Wait briefly under contention instead of failing with SQLITE_BUSY.
  sqlite3_busy_timeout(db_, 5000);

  // IMMEDIATE acquires a reserved lock before SELECT so a second connection
  // cannot also read the same row before the DELETE commits (SIG-003).
  SQLCHECK(sqlite3_exec(db_, "BEGIN IMMEDIATE;", NULL, NULL, NULL));

  auto rollback = [&]() {
    if (stmt) {
      sqlite3_finalize(stmt);
      stmt = nullptr;
    }
    sqlite3_exec(db_, "ROLLBACK;", NULL, NULL, NULL);
  };

  const char* select_sql = "SELECT NONCE FROM SECNONCES WHERE SESSION = ?;";
  if (sqlite3_prepare_v2(db_, select_sql, -1, &stmt, NULL) != SQLITE_OK) {
    rollback();
    throw StorageException(StorageException::SQL_ERROR, sqlite3_errmsg(db_));
  }
  sqlite3_bind_text(stmt, 1, key.c_str(), key.size(), NULL);
  int rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    rollback();
    throw StorageException(StorageException::NONCE_NOT_FOUND,
                           "Nonce not found!");
  }
  value = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
  SQLCHECK(sqlite3_finalize(stmt));
  stmt = nullptr;

  const char* delete_sql = "DELETE FROM SECNONCES WHERE SESSION = ?;";
  if (sqlite3_prepare_v2(db_, delete_sql, -1, &stmt, NULL) != SQLITE_OK) {
    rollback();
    throw StorageException(StorageException::SQL_ERROR, sqlite3_errmsg(db_));
  }
  sqlite3_bind_text(stmt, 1, key.c_str(), key.size(), NULL);
  rc = sqlite3_step(stmt);
  if (rc != SQLITE_DONE) {
    rollback();
    throw StorageException(StorageException::SQL_ERROR, sqlite3_errmsg(db_));
  }
  SQLCHECK(sqlite3_finalize(stmt));
  stmt = nullptr;

  SQLCHECK(sqlite3_exec(db_, "COMMIT;", NULL, NULL, NULL));
  return value;
}

void NunchukLocalDb::SetPreferScriptPath(const std::string& tx_id,
                                         bool value) const {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO SIGNPATH(TXID, VALUE) VALUES (?1, ?2)"
      "ON CONFLICT(TXID) DO UPDATE SET VALUE=excluded.VALUE;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_bind_int(stmt, 2, value ? 1 : 0);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
}

bool NunchukLocalDb::IsPreferScriptPath(const std::string& tx_id) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM SIGNPATH WHERE TXID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  bool value = false;
  if (sqlite3_column_text(stmt, 0)) {
    value = sqlite3_column_int(stmt, 1) == 1;
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return value;
}

}  // namespace nunchuk
