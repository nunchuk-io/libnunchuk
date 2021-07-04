// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_STORAGE_DB_H
#define NUNCHUK_STORAGE_DB_H

#include "common.h"
#include <nunchuk.h>
#include <string>

namespace nunchuk {

class NunchukStorage;
class NunchukDb {
 public:
  NunchukDb(Chain chain, const std::string &id, const std::string &file_name,
            const std::string &passphrase);
  ~NunchukDb() { close(); }
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
  bool TableExists(const std::string &table_name) const;
  sqlite3 *db_;
  std::string id_;
  Chain chain_;

 private:
  NunchukDb() = delete;
  void close();
  std::string db_file_name_;
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_DB_H
