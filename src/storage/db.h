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

#ifndef NUNCHUK_STORAGE_DB_H
#define NUNCHUK_STORAGE_DB_H

#include "common.h"
#include <nunchuk.h>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>

namespace nunchuk {

class NunchukStorage;
class NunchukDb {
 public:
  NunchukDb(Chain chain, const std::string &id, const std::string &file_name,
            const std::string &passphrase);
  NunchukDb(const NunchukDb &) = delete;
  NunchukDb &operator=(const NunchukDb &) = delete;
  NunchukDb(NunchukDb &&other) noexcept;
  NunchukDb &operator=(NunchukDb &&other) noexcept;
  ~NunchukDb();
  std::string GetId() const;

 protected:
  void CreateTable();
  void DropTable();
  void ReKey(const std::string &new_passphrase);
  void EncryptDb(const std::string &new_file_name,
                 const std::string &new_passphrase);
  void DecryptDb(const std::string &new_file_name);
  bool PutString(int key, const std::string &value);
  bool PutInt(int key, int64_t value);
  std::string GetString(int key) const;
  int64_t GetInt(int key) const;
  std::vector<std::string> GetListStr(int key) const;
  bool AddToListStr(int key, const std::string &value);
  bool RemoveFromListStr(int key, const std::string &value);
  bool TableExists(const std::string &table_name) const;
  std::string db_file_name_;
  sqlite3 *db_;
  std::string id_;
  Chain chain_;

 private:
  NunchukDb() = delete;
  // db_mutex_ outlives db_lock_. db_holder_ is released first so the
  // connection closes while this object still holds db_lock_.
  std::shared_ptr<std::recursive_mutex> db_mutex_;
  std::unique_lock<std::recursive_mutex> db_lock_;
  std::shared_ptr<sqlite3> db_holder_;

  void Evict();
  static void EvictFile(const std::string &file_name);
  static void EvictUnder(const std::string &directory);
  static void ClearValueCache(const std::string &file_name);

  static std::map<std::string, std::map<int, std::string>> vstr_cache_;
  static std::map<std::string, std::map<int, int64_t>> vint_cache_;
  static std::shared_mutex cache_access_;
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_DB_H
