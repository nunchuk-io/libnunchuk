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

#include "tapprotocoldb.h"
#include "tinyformat.h"

namespace nunchuk {

void NunchukTapprotocolDb::Init() {
  CreateTable();
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS TAPSIGNER("
                        "CARD_IDENT     TEXT PRIMARY KEY NOT NULL,"
                        "XFP            TEXT             NOT NULL,"
                        "BIRTH_HEIGHT   INT,"
                        "NUM_BACKUPS    INT,"
                        "VERSION        TEXT,"
                        "TESTNET        INT);",
                        NULL, 0, NULL));
}

bool NunchukTapprotocolDb::AddTapsigner(const TapsignerStatus &status) {
  sqlite3_stmt *stmt;
  std::string sql =
      "INSERT INTO TAPSIGNER(CARD_IDENT, XFP, BIRTH_HEIGHT, NUM_BACKUPS, "
      "VERSION, TESTNET) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON "
      "CONFLICT(CARD_IDENT) DO UPDATE SET XFP=excluded.XFP, "
      "BIRTH_HEIGHT=excluded.BIRTH_HEIGHT, NUM_BACKUPS=excluded.NUM_BACKUPS, "
      "VERSION=excluded.VERSION, TESTNET=excluded.TESTNET;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, status.get_card_ident().c_str(),
                    status.get_card_ident().size(), NULL);
  sqlite3_bind_text(stmt, 2, status.get_master_signer_id().c_str(),
                    status.get_master_signer_id().size(), NULL);
  sqlite3_bind_int(stmt, 3, status.get_birth_height());
  sqlite3_bind_int(stmt, 4, status.get_number_of_backup());
  sqlite3_bind_text(stmt, 5, status.get_version().c_str(),
                    status.get_version().size(), NULL);
  sqlite3_bind_int(stmt, 6, status.is_testnet() ? 1 : 0);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

TapsignerStatus NunchukTapprotocolDb::GetTapsignerStatusFromMasterSigner(
    const std::string &master_signer_id) {
  sqlite3_stmt *stmt;
  std::string sql =
      "SELECT CARD_IDENT, XFP, BIRTH_HEIGHT, NUM_BACKUPS, VERSION, TESTNET "
      "FROM TAPSIGNER WHERE XFP = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, master_signer_id.c_str(), master_signer_id.size(),
                    NULL);
  sqlite3_step(stmt);

  TapsignerStatus status;
  if (sqlite3_column_text(stmt, 0)) {
    status.set_card_ident((const char *)sqlite3_column_text(stmt, 0));
    status.set_master_signer_id((const char *)sqlite3_column_text(stmt, 1));
    status.set_birth_height(sqlite3_column_int(stmt, 2));
    status.set_number_of_backup(sqlite3_column_int(stmt, 3));
    status.set_version((const char *)sqlite3_column_text(stmt, 4));
    status.set_testnet(sqlite3_column_int(stmt, 5));
    status.set_current_derivation({});
    sqlite3_step(stmt);
    SQLCHECK(sqlite3_finalize(stmt));
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw StorageException(StorageException::MASTERSIGNER_NOT_FOUND,
                           strprintf("Key doesn't exist! id = '%s'", master_signer_id));
  }
  return status;
}

TapsignerStatus NunchukTapprotocolDb::GetTapsignerStatusFromCardIdent(
    const std::string &card_ident) {
  sqlite3_stmt *stmt;
  std::string sql =
      "SELECT CARD_IDENT, XFP, BIRTH_HEIGHT, NUM_BACKUPS, VERSION, TESTNET "
      "FROM TAPSIGNER WHERE CARD_IDENT = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, card_ident.c_str(), card_ident.size(), NULL);
  sqlite3_step(stmt);

  TapsignerStatus status;
  if (sqlite3_column_text(stmt, 0)) {
    status.set_card_ident((const char *)sqlite3_column_text(stmt, 0));
    status.set_master_signer_id((const char *)sqlite3_column_text(stmt, 1));
    status.set_birth_height(sqlite3_column_int(stmt, 2));
    status.set_number_of_backup(sqlite3_column_int(stmt, 3));
    status.set_version((const char *)sqlite3_column_text(stmt, 4));
    status.set_testnet(sqlite3_column_int(stmt, 5));
    sqlite3_step(stmt);
    SQLCHECK(sqlite3_finalize(stmt));
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw StorageException(StorageException::MASTERSIGNER_NOT_FOUND,
                           "Signer not found!");
  }
  return status;
}

bool NunchukTapprotocolDb::DeleteTapsigner(
    const std::string &master_signer_id) {
  sqlite3_stmt *stmt;
  std::string sql = "DELETE FROM TAPSIGNER WHERE XFP = ?;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, master_signer_id.c_str(), master_signer_id.size(),
                    NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}
}  // namespace nunchuk
