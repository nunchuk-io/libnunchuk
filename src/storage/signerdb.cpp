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

#include "signerdb.h"

#include <descriptor.h>
#include <utils/bip32.hpp>
#include <utils/txutils.hpp>
#include <utils/loguru.hpp>
#include <utils/bsms.hpp>
#include <set>
#include <sstream>

#include <rpc/util.h>
#include <policy/policy.h>

namespace nunchuk {

void NunchukSignerDb::InitSigner(const std::string& name, const Device& device,
                                 const std::string& mnemonic) {
  CreateTable();
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS BIP32("
                        "PATH VARCHAR(20) PRIMARY KEY     NOT NULL,"
                        "XPUB                     TEXT    NOT NULL,"
                        "TYPE                     TEXT    NOT NULL,"
                        "USED                     INT);",
                        NULL, 0, NULL));
  PutString(DbKeys::NAME, name);
  PutString(DbKeys::FINGERPRINT, device.get_master_fingerprint());
  if (!mnemonic.empty()) PutString(DbKeys::MNEMONIC, mnemonic);
  PutString(DbKeys::SIGNER_DEVICE_TYPE, device.get_type());
  PutString(DbKeys::SIGNER_DEVICE_MODEL, device.get_model());
}

void NunchukSignerDb::DeleteSigner() {
  SQLCHECK(sqlite3_exec(db_, "DROP TABLE IF EXISTS REMOTE;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DROP TABLE IF EXISTS BIP32;", NULL, 0, NULL));
  DropTable();
}

bool NunchukSignerDb::AddXPub(const std::string& path, const std::string& xpub,
                              const std::string& type) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO BIP32(PATH, XPUB, TYPE, USED)"
      "VALUES (?1, ?2, ?3, -1)"
      "ON CONFLICT(PATH) DO UPDATE SET XPUB=excluded.XPUB;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, path.c_str(), path.size(), NULL);
  sqlite3_bind_text(stmt, 2, xpub.c_str(), xpub.size(), NULL);
  sqlite3_bind_text(stmt, 3, type.c_str(), type.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukSignerDb::AddXPub(const WalletType& wallet_type,
                              const AddressType& address_type, int index,
                              const std::string& xpub) {
  std::string path = GetBip32Path(chain_, wallet_type, address_type, index);
  std::string type = GetBip32Type(wallet_type, address_type);
  return AddXPub(path, xpub, type);
}

bool NunchukSignerDb::UseIndex(const WalletType& wallet_type,
                               const AddressType& address_type, int index) {
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE BIP32 SET USED = ?1 WHERE PATH = ?2 AND USED = -1;";
  std::string path = GetBip32Path(chain_, wallet_type, address_type, index);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, 1);
  sqlite3_bind_text(stmt, 2, path.c_str(), path.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

std::string NunchukSignerDb::GetXpub(const std::string& path) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT XPUB FROM BIP32 WHERE PATH = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, path.c_str(), path.size(), NULL);
  sqlite3_step(stmt);
  std::string value;
  if (sqlite3_column_text(stmt, 0)) {
    value = std::string((char*)sqlite3_column_text(stmt, 0));
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return value;
}

std::string NunchukSignerDb::GetXpub(const WalletType& wallet_type,
                                     const AddressType& address_type,
                                     int index) {
  std::string path = GetBip32Path(chain_, wallet_type, address_type, index);
  return GetXpub(path);
}

int NunchukSignerDb::GetUnusedIndex(const WalletType& wallet_type,
                                    const AddressType& address_type) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT PATH FROM BIP32 WHERE TYPE = ? AND USED = -1;";
  std::string type = GetBip32Type(wallet_type, address_type);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, type.c_str(), type.size(), NULL);
  sqlite3_step(stmt);
  int value = -1;
  if (sqlite3_column_text(stmt, 0)) {
    value = GetIndexFromPath(std::string((char*)sqlite3_column_text(stmt, 0)));
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return value;
}

int NunchukSignerDb::GetCachedIndex(const WalletType& wallet_type,
                                    const AddressType& address_type) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT PATH FROM BIP32 WHERE TYPE = ?;";
  std::string type = GetBip32Type(wallet_type, address_type);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, type.c_str(), type.size(), NULL);
  sqlite3_step(stmt);
  int value = -1;
  while (sqlite3_column_text(stmt, 0)) {
    int index =
        GetIndexFromPath(std::string((char*)sqlite3_column_text(stmt, 0)));
    if (index > value) value = index;
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return value;
}

bool NunchukSignerDb::SetName(const std::string& value) {
  return PutString(DbKeys::NAME, value);
}

bool NunchukSignerDb::SetLastHealthCheck(time_t value) {
  return PutInt(DbKeys::LAST_HEALTH_CHECK, value);
}

std::string NunchukSignerDb::GetFingerprint() const {
  return GetString(DbKeys::FINGERPRINT);
}

std::string NunchukSignerDb::GetDeviceType() const {
  return GetString(DbKeys::SIGNER_DEVICE_TYPE);
}

std::string NunchukSignerDb::GetDeviceModel() const {
  return GetString(DbKeys::SIGNER_DEVICE_MODEL);
}

std::string NunchukSignerDb::GetName() const { return GetString(DbKeys::NAME); }

time_t NunchukSignerDb::GetLastHealthCheck() const {
  return GetInt(DbKeys::LAST_HEALTH_CHECK);
}

// NunchukSignerDb only creates a BIP32 table if the signer is a master signer.
// When user adds a master signer whose fingerprint matches the master
// fingerprint of an existing remote signer, a BIP32 table will be added to the
// existing signer Db. The single signer will become a master signer.
bool NunchukSignerDb::IsMaster() const { return TableExists("BIP32"); }

SignerType NunchukSignerDb::GetSignerType() const {
  if (!IsMaster()) return SignerType::AIRGAP;
  if (GetDeviceType() == "software") {
    return GetString(DbKeys::MNEMONIC).empty() ? SignerType::FOREIGN_SOFTWARE
                                               : SignerType::SOFTWARE;
  }
  return SignerType::HARDWARE;
}

SoftwareSigner NunchukSignerDb::GetSoftwareSigner(
    const std::string& passphrase) const {
  auto mnemonic = GetString(DbKeys::MNEMONIC);
  if (mnemonic.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Is not software signer");
  }
  auto signer = SoftwareSigner{mnemonic, passphrase};
  if (signer.GetMasterFingerprint() != id_) {
    throw NunchukException(NunchukException::INVALID_SIGNER_PASSPHRASE,
                           "Invalid software signer passphrase");
  }
  return signer;
}

void NunchukSignerDb::InitRemote() {
  CreateTable();
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS REMOTE("
                        "PATH VARCHAR(20) PRIMARY KEY     NOT NULL,"
                        "XPUB                     TEXT,"
                        "PUBKEY                   TEXT,"
                        "NAME                     TEXT    NOT NULL,"
                        "LAST_HEALTHCHECK         INT     NOT NULL,"
                        "USED                     INT);",
                        NULL, 0, NULL));
}

bool NunchukSignerDb::AddRemote(const std::string& name,
                                const std::string& xpub,
                                const std::string& public_key,
                                const std::string& path, bool used) {
  InitRemote();
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO REMOTE(PATH, XPUB, PUBKEY, NAME, LAST_HEALTHCHECK, USED)"
      "VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
      "ON CONFLICT(PATH) DO UPDATE SET XPUB=excluded.XPUB;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, path.c_str(), path.size(), NULL);
  sqlite3_bind_text(stmt, 2, xpub.c_str(), xpub.size(), NULL);
  sqlite3_bind_text(stmt, 3, public_key.c_str(), public_key.size(), NULL);
  sqlite3_bind_text(stmt, 4, name.c_str(), name.size(), NULL);
  sqlite3_bind_int64(stmt, 5, 0);
  sqlite3_bind_int(stmt, 6, used ? 1 : -1);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

SingleSigner NunchukSignerDb::GetRemoteSigner(const std::string& path) const {
  sqlite3_stmt* stmt;
  std::string sql =
      "SELECT XPUB, PUBKEY, NAME, LAST_HEALTHCHECK, USED FROM REMOTE WHERE "
      "PATH = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, path.c_str(), path.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    std::string xpub = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string pubkey = std::string((char*)sqlite3_column_text(stmt, 1));
    std::string name = std::string((char*)sqlite3_column_text(stmt, 2));
    time_t last_health_check = sqlite3_column_int64(stmt, 3);
    bool used = sqlite3_column_int(stmt, 4) == 1;
    SingleSigner signer(name, xpub, pubkey, path, id_, last_health_check, {},
                        used);
    signer.set_type(SignerType::AIRGAP);
    SQLCHECK(sqlite3_finalize(stmt));
    return signer;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw StorageException(StorageException::SIGNER_NOT_FOUND,
                           "Signer not found!");
  }
}

bool NunchukSignerDb::DeleteRemoteSigner(const std::string& path) {
  sqlite3_stmt* stmt;
  std::string sql = "DELETE FROM REMOTE WHERE PATH = ?;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, path.c_str(), path.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukSignerDb::UseRemote(const std::string& path) {
  sqlite3_stmt* stmt;
  std::string sql =
      "UPDATE REMOTE SET USED = ?1 WHERE PATH = ?2 AND USED = -1;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, 1);
  sqlite3_bind_text(stmt, 2, path.c_str(), path.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukSignerDb::SetRemoteName(const std::string& path,
                                    const std::string& value) {
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE REMOTE SET NAME = ?1 WHERE PATH = ?2;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, value.c_str(), value.size(), NULL);
  sqlite3_bind_text(stmt, 2, path.c_str(), path.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukSignerDb::SetRemoteLastHealthCheck(const std::string& path,
                                               time_t value) {
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE REMOTE SET LAST_HEALTHCHECK = ?1 WHERE PATH = ?2;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, value);
  sqlite3_bind_text(stmt, 2, path.c_str(), path.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

std::vector<SingleSigner> NunchukSignerDb::GetRemoteSigners() const {
  if (IsMaster()) return {};
  sqlite3_stmt* stmt;
  std::string sql =
      "SELECT PATH, XPUB, PUBKEY, NAME, LAST_HEALTHCHECK, USED FROM REMOTE;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);
  std::vector<SingleSigner> signers;
  while (sqlite3_column_text(stmt, 0)) {
    std::string path = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string xpub = std::string((char*)sqlite3_column_text(stmt, 1));
    std::string pubkey = std::string((char*)sqlite3_column_text(stmt, 2));
    std::string name = std::string((char*)sqlite3_column_text(stmt, 3));
    time_t last_health_check = sqlite3_column_int64(stmt, 4);
    bool used = sqlite3_column_int(stmt, 5) == 1;
    SingleSigner signer(name, xpub, pubkey, path, id_, last_health_check, {},
                        used);
    signer.set_type(SignerType::AIRGAP);
    if (name != "import") signers.push_back(signer);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return signers;
}

std::vector<SingleSigner> NunchukSignerDb::GetSingleSigners(
    bool usedOnly) const {
  std::string name = GetName();
  std::string master_fingerprint = GetFingerprint();
  time_t last_health_check = GetLastHealthCheck();
  auto signer_type = GetSignerType();

  sqlite3_stmt* stmt;
  std::string sql = usedOnly ? "SELECT PATH, XPUB FROM BIP32 WHERE USED != -1;"
                             : "SELECT PATH, XPUB FROM BIP32;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);
  std::vector<SingleSigner> signers;
  while (sqlite3_column_text(stmt, 0)) {
    std::string path = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string xpub = std::string((char*)sqlite3_column_text(stmt, 1));
    SingleSigner signer(name, xpub, "", path, master_fingerprint,
                        last_health_check, id_, true);
    signer.set_type(signer_type);
    signers.push_back(signer);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return signers;
}

}  // namespace nunchuk
