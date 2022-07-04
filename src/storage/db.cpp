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

#include "db.h"
#include <sstream>
#include <utils/loguru.hpp>
#include <utils/stringutils.hpp>
#include <cstring>

namespace nunchuk {

std::map<std::string, std::map<int, std::string>> NunchukDb::vstr_cache_;
std::map<std::string, std::map<int, int64_t>> NunchukDb::vint_cache_;

NunchukDb::NunchukDb(Chain chain, const std::string& id,
                     const std::string& file_name,
                     const std::string& passphrase)
    : id_(id), chain_(chain), db_file_name_(file_name) {
  SQLCHECK(sqlite3_open(db_file_name_.c_str(), &db_));
  if (!passphrase.empty()) {
    const char* key = passphrase.c_str();
    SQLCHECK(sqlite3_key(db_, (const void*)key, std::strlen(key)));
  }
  if (sqlite3_exec(db_, "SELECT count(*) FROM sqlite_master;", NULL, NULL,
                   NULL) != SQLITE_OK) {
    throw NunchukException(NunchukException::INVALID_PASSPHRASE,
                           "Invalid passphrase");
  }
}

void NunchukDb::close() { sqlite3_close(db_); }

void NunchukDb::CreateTable() {
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS VSTR("
                        "ID INT PRIMARY KEY     NOT NULL,"
                        "VALUE          TEXT    NOT NULL);",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS VINT("
                        "ID INT PRIMARY KEY     NOT NULL,"
                        "VALUE          INT     NOT NULL);",
                        NULL, 0, NULL));
  PutString(DbKeys::ID, id_);
  PutInt(DbKeys::VERSION, STORAGE_VER);
}

std::string NunchukDb::GetId() const { return GetString(DbKeys::ID); }

void NunchukDb::DropTable() {
  SQLCHECK(sqlite3_exec(db_, "DROP TABLE IF EXISTS VSTR;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DROP TABLE IF EXISTS VINT;", NULL, 0, NULL));
}

void NunchukDb::ReKey(const std::string& new_passphrase) {
  const char* key = new_passphrase.c_str();
  SQLCHECK(sqlite3_rekey(db_, (const void*)key, std::strlen(key)));
  DLOG_F(INFO, "NunchukDb '%s' ReKey success", db_file_name_.c_str());
}

void NunchukDb::EncryptDb(const std::string& new_file_name,
                          const std::string& new_passphrase) {
  std::stringstream attach_sql;
  attach_sql << "ATTACH DATABASE '" << new_file_name << "' AS encrypted KEY '"
             << new_passphrase << "';";
  const std::string sql = attach_sql.str();
  SQLCHECK(sqlite3_exec(db_, sql.c_str(), NULL, NULL, NULL));
  SQLCHECK(sqlite3_exec(db_, "SELECT sqlcipher_export('encrypted');", NULL,
                        NULL, NULL));
  SQLCHECK(sqlite3_exec(db_, "DETACH DATABASE encrypted;", NULL, NULL, NULL));
}

void NunchukDb::DecryptDb(const std::string& new_file_name) {
  std::stringstream attach_sql;
  attach_sql << "ATTACH DATABASE '" << new_file_name
             << "' AS plaintext KEY '';";
  const std::string sql = attach_sql.str();
  SQLCHECK(sqlite3_exec(db_, sql.c_str(), NULL, NULL, NULL));
  SQLCHECK(sqlite3_exec(db_, "SELECT sqlcipher_export('plaintext');", NULL,
                        NULL, NULL));
  SQLCHECK(sqlite3_exec(db_, "DETACH DATABASE plaintext;", NULL, NULL, NULL));
}

bool NunchukDb::PutString(int key, const std::string& value) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO VSTR(ID, VALUE)"
      "VALUES (?1, ?2)"
      "ON CONFLICT(ID) DO UPDATE SET VALUE=excluded.VALUE;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, key);
  sqlite3_bind_text(stmt, 2, value.c_str(), value.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated) vstr_cache_[db_file_name_][key] = value;
  return updated;
}

bool NunchukDb::PutInt(int key, int64_t value) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO VINT(ID, VALUE)"
      "VALUES (?1, ?2)"
      "ON CONFLICT(ID) DO UPDATE SET VALUE=excluded.VALUE;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, key);
  sqlite3_bind_int64(stmt, 2, value);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated) vint_cache_[db_file_name_][key] = value;
  return updated;
}

std::string NunchukDb::GetString(int key) const {
  if (vstr_cache_[db_file_name_].count(key)) {
    return vstr_cache_[db_file_name_][key];
  }
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM VSTR WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, key);
  sqlite3_step(stmt);
  std::string value;
  if (sqlite3_column_text(stmt, 0)) {
    value = std::string((char*)sqlite3_column_text(stmt, 1));
    vstr_cache_[db_file_name_][key] = value;
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return value;
}

int64_t NunchukDb::GetInt(int key) const {
  if (vint_cache_[db_file_name_].count(key)) {
    return vint_cache_[db_file_name_][key];
  }
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM VINT WHERE ID = ?;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, key);
  sqlite3_step(stmt);
  int64_t value = 0;
  if (sqlite3_column_text(stmt, 0)) {
    value = sqlite3_column_int64(stmt, 1);
    vint_cache_[db_file_name_][key] = value;
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return value;
}

std::vector<std::string> NunchukDb::GetListStr(int key) const {
  return split(GetString(key), ',');
}

bool NunchukDb::AddToListStr(int key, const std::string& id) {
  auto ids = GetListStr(key);
  if (std::find(ids.begin(), ids.end(), id) != ids.end()) return false;
  ids.push_back(id);
  return PutString(key, join(ids, ','));
}

bool NunchukDb::RemoveFromListStr(int key, const std::string& id) {
  auto ids = GetListStr(key);
  auto new_end = std::remove(ids.begin(), ids.end(), id);
  if (new_end == ids.end()) return false;
  ids.resize(new_end - ids.begin());
  return PutString(key, join(ids, ','));
}

bool NunchukDb::TableExists(const std::string& table_name) const {
  sqlite3_stmt* stmt;
  std::string sql =
      "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, table_name.c_str(), table_name.size(), NULL);
  int rc = sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
  return rc == SQLITE_ROW;
}

}  // namespace nunchuk
