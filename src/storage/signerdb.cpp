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
#include "storage/common.h"
#include "utils/enumconverter.hpp"

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
  if (device.is_tapsigner()) {
    // Remove master xpriv key if exists
    PutString(DbKeys::MASTER_XPRV, {});
  }
  PutString(DbKeys::SIGNER_DEVICE_TYPE, device.get_type());
  PutString(DbKeys::SIGNER_DEVICE_MODEL, device.get_model());
}

void NunchukSignerDb::InitSignerMasterXprv(const std::string& name,
                                           const Device& device,
                                           const std::string& master_xprv) {
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
  if (!master_xprv.empty()) PutString(DbKeys::MASTER_XPRV, master_xprv);
  PutString(DbKeys::SIGNER_DEVICE_TYPE, device.get_type());
  PutString(DbKeys::SIGNER_DEVICE_MODEL, device.get_model());
}

void NunchukSignerDb::MaybeMigrate() {}

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
      "ON CONFLICT(PATH) DO UPDATE SET TYPE=excluded.TYPE;";
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
bool NunchukSignerDb::SetTags(const std::vector<SignerTag>& value) {
  json json_tags = json::array();
  for (SignerTag tag : value) {
    json_tags.emplace_back(SignerTagToStr(tag));
  }
  return PutString(DbKeys::SIGNER_TAGS, json_tags.dump());
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

std::vector<SignerTag> NunchukSignerDb::GetTags() const {
  std::vector<SignerTag> tags;

  std::string str_tags = GetString(DbKeys::SIGNER_TAGS);
  if (str_tags.empty()) {
    return tags;
  }

  json json_tags = json::parse(str_tags);
  for (std::string tag : json_tags) {
    tags.emplace_back(SignerTagFromStr(tag));
  }
  return tags;
}

time_t NunchukSignerDb::GetLastHealthCheck() const {
  return GetInt(DbKeys::LAST_HEALTH_CHECK);
}

// NunchukSignerDb only creates a BIP32 table if the signer is a master signer.
// When user adds a master signer whose fingerprint matches the master
// fingerprint of an existing remote signer, a BIP32 table will be added to the
// existing signer Db. The single signer will become a master signer.
bool NunchukSignerDb::IsMaster() const { return TableExists("BIP32"); }

SignerType NunchukSignerDb::GetSignerType() const {
  if (!IsMaster()) {
    std::string signer_type_str = GetString(DbKeys::SIGNER_TYPE);
    if (signer_type_str.empty()) {
      return SignerType::AIRGAP;
    } else {
      return SignerTypeFromStr(signer_type_str);
    }
  }
  if (GetDeviceType() == "software") {
    bool has_mnemonic = !GetString(DbKeys::MNEMONIC).empty();
    if (has_mnemonic) {
      return SignerType::SOFTWARE;
    }

    bool has_master_xprv = !GetString(DbKeys::MASTER_XPRV).empty();
    if (has_master_xprv) {
      return SignerType::SOFTWARE;
    }

    return SignerType::FOREIGN_SOFTWARE;
  }

  if (GetDeviceType() == "nfc") {
    return SignerType::NFC;
  }
  return SignerType::HARDWARE;
}

bool NunchukSignerDb::IsSoftware(const std::string& passphrase) const {
  auto mnemonic = GetString(DbKeys::MNEMONIC);
  if (!mnemonic.empty()) {
    auto signer = SoftwareSigner{mnemonic, passphrase};
    return signer.GetMasterFingerprint() == id_;
  }

  auto master_xprv = GetString(DbKeys::MASTER_XPRV);
  if (!master_xprv.empty()) {
    auto signer = SoftwareSigner{master_xprv};
    return signer.GetMasterFingerprint() == id_;
  }
  return false;
}

SoftwareSigner NunchukSignerDb::GetSoftwareSigner(
    const std::string& passphrase) const {
  auto mnemonic = GetString(DbKeys::MNEMONIC);
  if (!mnemonic.empty()) {
    auto signer = SoftwareSigner{mnemonic, passphrase};
    if (signer.GetMasterFingerprint() != id_) {
      throw NunchukException(NunchukException::INVALID_SIGNER_PASSPHRASE,
                             "Invalid passphrase");
    }
    return signer;
  }

  auto master_xprv = GetString(DbKeys::MASTER_XPRV);
  if (!master_xprv.empty()) {
    auto signer = SoftwareSigner{master_xprv};
    if (signer.GetMasterFingerprint() != id_) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid signer");
    }
    return signer;
  }

  throw NunchukException(NunchukException::INVALID_PARAMETER,
                         "Is not software signer");
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
                                const std::string& path, bool used,
                                SignerType signer_type,
                                std::vector<SignerTag> tags) {
  InitRemote();
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO REMOTE(PATH, XPUB, PUBKEY, NAME, LAST_HEALTHCHECK, USED)"
      "VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
      "ON CONFLICT(PATH) DO UPDATE SET XPUB=excluded.XPUB, NAME=excluded.NAME;";
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
  updated |= UpdateSignerType(signer_type);
  updated |= SetTags(tags);
  return updated;
}

SingleSigner NunchukSignerDb::GetRemoteSigner(const std::string& path) const {
  sqlite3_stmt* stmt;
  std::string sql =
      "SELECT XPUB, PUBKEY, NAME, LAST_HEALTHCHECK, USED FROM REMOTE WHERE "
      "PATH = ?1 OR PATH = REPLACE(?1, 'h', '''');";
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
                        used, GetSignerType(), GetTags());
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
  std::string sql =
      "DELETE FROM REMOTE WHERE PATH = ?1 OR PATH = REPLACE(?1, 'h', '''');";
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
      "UPDATE REMOTE SET USED = ?1 "
      "WHERE (PATH = ?2 OR PATH = REPLACE(?2, 'h', '''')) AND USED = -1;";
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
  std::string sql =
      "UPDATE REMOTE SET NAME = ?1 "
      "WHERE PATH = ?2 OR PATH = REPLACE(?2, 'h', '''');";
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
  std::string sql =
      "UPDATE REMOTE SET LAST_HEALTHCHECK = ?1 "
      "WHERE PATH = ?2 OR PATH = REPLACE(?2, 'h', '''');";
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
                        used, GetSignerType());
    signer.set_tags(GetTags());
    if (signer.get_type() != SignerType::UNKNOWN) {
      signers.push_back(signer);
    }

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
                        last_health_check, id_, true, signer_type, GetTags());
    signers.push_back(signer);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return signers;
}

bool NunchukSignerDb::UpdateSignerType(SignerType signer_type) {
  const std::string cur_type_str = GetString(DbKeys::SIGNER_TYPE);
  if (cur_type_str.empty()) {
    PutString(DbKeys::SIGNER_TYPE, SignerTypeToStr(signer_type));
    return true;
  }

  const auto order = [](SignerType signer_type) {
    switch (signer_type) {
      case SignerType::UNKNOWN:
        return 0;
      case SignerType::AIRGAP:
        return 1;
      case SignerType::SERVER:
        return 2;
      case SignerType::FOREIGN_SOFTWARE:
        return 3;
      case SignerType::COLDCARD_NFC:
        return 4;
      case SignerType::NFC:
        return 5;
      case SignerType::HARDWARE:
        return 6;
      case SignerType::SOFTWARE:
        return 7;
    }
    return -1;
  };

  const SignerType cur_type = SignerTypeFromStr(cur_type_str);
  if (order(cur_type) < order(signer_type)) {
    PutString(DbKeys::SIGNER_TYPE, SignerTypeToStr(signer_type));
    return true;
  }
  return false;
}

}  // namespace nunchuk
