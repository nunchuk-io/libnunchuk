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
#include <mutex>
#include <utility>
#include <vector>

namespace nunchuk {

std::map<std::string, std::map<int, std::string>> NunchukDb::vstr_cache_;
std::map<std::string, std::map<int, int64_t>> NunchukDb::vint_cache_;
std::shared_mutex NunchukDb::cache_access_;

namespace {

struct CachedConnection {
  std::shared_ptr<sqlite3> db;
  std::shared_ptr<std::recursive_mutex> mutex;
  std::string passphrase;
};

std::mutex g_conn_mu;
std::map<std::string, CachedConnection> g_conn_cache;

void CloseConnection(sqlite3* db) {
  if (db != nullptr) sqlite3_close_v2(db);
}

bool PathIsUnder(const std::string& file, const std::string& dir) {
  if (file == dir) return true;
  if (dir.empty() || file.size() <= dir.size()) return false;
  if (file.compare(0, dir.size(), dir) != 0) return false;
  const char sep = file[dir.size()];
  return sep == '/' || sep == '\\';
}

}  // namespace

NunchukDb::NunchukDb(Chain chain, const std::string& id,
                     const std::string& file_name,
                     const std::string& passphrase)
    : db_file_name_(file_name),
      db_(nullptr),
      id_(id),
      chain_(chain) {
  {
    std::lock_guard<std::mutex> lock(g_conn_mu);
    auto it = g_conn_cache.find(db_file_name_);
    if (it != g_conn_cache.end() && it->second.passphrase == passphrase &&
        it->second.db) {
      db_holder_ = it->second.db;
      db_mutex_ = it->second.mutex;
      db_ = db_holder_.get();
    }
  }
  if (db_ != nullptr) {
    db_lock_ = std::unique_lock<std::recursive_mutex>(*db_mutex_);
    return;
  }

  int open_rc = sqlite3_open(db_file_name_.c_str(), &db_);
  if (db_ != nullptr) db_holder_.reset(db_, CloseConnection);
  if (open_rc != SQLITE_OK) {
    throw StorageException(StorageException::SQL_ERROR,
                           db_ != nullptr ? sqlite3_errmsg(db_)
                                          : "sqlite3_open failed");
  }
  if (!passphrase.empty()) {
    const char* key = passphrase.c_str();
    SQLCHECK(sqlite3_key(db_, (const void*)key, std::strlen(key)));
  }
  if (sqlite3_exec(db_, "SELECT count(*) FROM sqlite_master;", NULL, NULL,
                   NULL) != SQLITE_OK) {
    db_holder_.reset();
    db_ = nullptr;
    throw NunchukException(NunchukException::INVALID_PASSPHRASE,
                           "Invalid passphrase");
  }

  auto mutex = std::make_shared<std::recursive_mutex>();
  {
    std::lock_guard<std::mutex> lock(g_conn_mu);
    auto it = g_conn_cache.find(db_file_name_);
    if (it != g_conn_cache.end() && it->second.passphrase == passphrase &&
        it->second.db) {
      db_holder_.reset();
      db_holder_ = it->second.db;
      db_mutex_ = it->second.mutex;
      db_ = db_holder_.get();
    } else {
      db_mutex_ = mutex;
      g_conn_cache[db_file_name_] = CachedConnection{db_holder_, db_mutex_,
                                                     passphrase};
    }
  }
  db_lock_ = std::unique_lock<std::recursive_mutex>(*db_mutex_);
}

NunchukDb::NunchukDb(NunchukDb&& other) noexcept
    : db_file_name_(std::move(other.db_file_name_)),
      db_(other.db_),
      id_(std::move(other.id_)),
      chain_(other.chain_),
      db_mutex_(std::move(other.db_mutex_)),
      db_lock_(std::move(other.db_lock_)),
      db_holder_(std::move(other.db_holder_)) {
  other.db_ = nullptr;
}

NunchukDb& NunchukDb::operator=(NunchukDb&& other) noexcept {
  if (this == &other) return *this;
  db_file_name_ = std::move(other.db_file_name_);
  db_ = other.db_;
  other.db_ = nullptr;
  id_ = std::move(other.id_);
  chain_ = other.chain_;
  db_lock_ = std::move(other.db_lock_);
  db_mutex_ = std::move(other.db_mutex_);
  db_holder_ = std::move(other.db_holder_);
  return *this;
}

NunchukDb::~NunchukDb() = default;

void NunchukDb::ClearValueCache(const std::string& file_name) {
  std::unique_lock<std::shared_mutex> lock(cache_access_);
  vstr_cache_.erase(file_name);
  vint_cache_.erase(file_name);
}

void NunchukDb::Evict() {
  {
    std::lock_guard<std::mutex> lock(g_conn_mu);
    auto it = g_conn_cache.find(db_file_name_);
    if (it != g_conn_cache.end() && it->second.db.get() == db_) {
      g_conn_cache.erase(it);
    }
  }
  ClearValueCache(db_file_name_);
}

void NunchukDb::EvictFile(const std::string& file_name) {
  {
    std::lock_guard<std::mutex> lock(g_conn_mu);
    g_conn_cache.erase(file_name);
  }
  ClearValueCache(file_name);
}

void NunchukDb::EvictUnder(const std::string& directory) {
  std::vector<std::string> dropped;
  {
    std::lock_guard<std::mutex> lock(g_conn_mu);
    for (auto it = g_conn_cache.begin(); it != g_conn_cache.end();) {
      if (PathIsUnder(it->first, directory)) {
        dropped.push_back(it->first);
        it = g_conn_cache.erase(it);
      } else {
        ++it;
      }
    }
  }
  for (const auto& file_name : dropped) ClearValueCache(file_name);
}

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

  std::unique_lock<std::shared_mutex> lock(cache_access_);
  vstr_cache_[db_file_name_].clear();
  vint_cache_[db_file_name_].clear();
}

void NunchukDb::ReKey(const std::string& new_passphrase) {
  const char* key = new_passphrase.c_str();
  SQLCHECK(sqlite3_rekey(db_, (const void*)key, std::strlen(key)));
  std::lock_guard<std::mutex> lock(g_conn_mu);
  auto it = g_conn_cache.find(db_file_name_);
  if (it != g_conn_cache.end() && it->second.db.get() == db_) {
    it->second.passphrase = new_passphrase;
  }
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
  std::unique_lock<std::shared_mutex> lock(cache_access_);
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
  std::unique_lock<std::shared_mutex> lock(cache_access_);
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
  std::unique_lock<std::shared_mutex> lock(cache_access_);
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
  std::unique_lock<std::shared_mutex> lock(cache_access_);
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
