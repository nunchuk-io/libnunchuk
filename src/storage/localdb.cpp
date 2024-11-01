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
#include <crypto/hex_base.h>
#include <secp256k1_musig.h>

namespace nunchuk {

void NunchukLocalDb::Init() {
  CreateTable();
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS SECNONCES("
                        "SESSION TEXT PRIMARY KEY NOT NULL,"
                        "NONCE   TEXT             NOT NULL);",
                        NULL, 0, NULL));
}

void NunchukLocalDb::SetMuSig2SecNonce(const uint256& session_id, MuSig2SecNonce&& nonce) const {
  std::string key = session_id.GetHex();
  auto data = static_cast<secp256k1_musig_secnonce*>(nonce.Get())->data;
  std::string value = HexStr(std::vector<unsigned char>{data, data + 132});
  nonce.Invalidate();
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO SECNONCES(SESSION, NONCE)"
      "VALUES (?1, ?2)"
      "ON CONFLICT(SESSION) DO UPDATE SET "
      "NONCE=excluded.NONCE;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, key.c_str(), key.size(), NULL);
  sqlite3_bind_text(stmt, 2, value.c_str(), value.size(), NULL);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
}

std::vector<unsigned char> hexStringToByteArray(const std::string& hexString) {
  std::vector<unsigned char> byteArray;
  for (size_t i = 0; i < hexString.length(); i += 2) {
      std::string byteString = hexString.substr(i, 2);
      unsigned char byteValue = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
      byteArray.push_back(byteValue);
  }
  return byteArray;
}

MuSig2SecNonce NunchukLocalDb::GetMuSig2SecNonce(const uint256& session_id) const {
  std::string key = session_id.GetHex();
  std::string value;

  sqlite3_exec(db_, "BEGIN TRANSACTION;", NULL, NULL, NULL);
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM SECNONCES WHERE SESSION = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, key.c_str(), key.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    value = std::string((char*)sqlite3_column_text(stmt, 1));
    SQLCHECK(sqlite3_finalize(stmt));
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw StorageException(StorageException::NONCE_NOT_FOUND,
                           "Nonce not found!");
  }

  sql = "DELETE FROM SECNONCES WHERE SESSION = ?;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, key.c_str(), key.size(), NULL);
  sqlite3_step(stmt);
  sqlite3_exec(db_, "COMMIT;", NULL, NULL, NULL);
  SQLCHECK(sqlite3_finalize(stmt));

  auto rv = hexStringToByteArray(value);
  MuSig2SecNonce nonce{};
  memcpy(static_cast<secp256k1_musig_secnonce*>(nonce.Get())->data, rv.data(), 132);
  return std::move(nonce);
}


std::map<uint256, MuSig2SecNonce> NunchukLocalDb::GetAll() const{
  std::map<uint256, MuSig2SecNonce> rs;

  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM SECNONCES;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);
  while (sqlite3_column_text(stmt, 0)) {
    std::string key = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string value = std::string((char*)sqlite3_column_text(stmt, 1));
    
    auto rv = hexStringToByteArray(value);
    MuSig2SecNonce nonce{};
    memcpy(static_cast<secp256k1_musig_secnonce*>(nonce.Get())->data, rv.data(), 132);
    rs.emplace(*uint256::FromHex(key), std::move(nonce));
    sqlite3_step(stmt);
  } 
  SQLCHECK(sqlite3_finalize(stmt));  
  return rs;
}

void NunchukLocalDb::TestSet(const std::string& session_id, const std::string& nonce){
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO SECNONCES(SESSION, NONCE)"
      "VALUES (?1, ?2);";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, session_id.c_str(), session_id.size(), NULL);
  sqlite3_bind_text(stmt, 2, nonce.c_str(), nonce.size(), NULL);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
}

std::string NunchukLocalDb::TestGet(const std::string& session_id){
  std::string value;
  sqlite3_exec(db_, "BEGIN TRANSACTION;", NULL, NULL, NULL);
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM SECNONCES WHERE SESSION = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, session_id.c_str(), session_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    value = std::string((char*)sqlite3_column_text(stmt, 1));
    SQLCHECK(sqlite3_finalize(stmt));
  }

  sql = "DELETE FROM SECNONCES WHERE SESSION = ?;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, session_id.c_str(), session_id.size(), NULL);
  sqlite3_step(stmt);
  sqlite3_exec(db_, "COMMIT;", NULL, NULL, NULL);
  SQLCHECK(sqlite3_finalize(stmt));
  return value;
}

}  // namespace nunchuk
