// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "storage.h"

#include <descriptor.h>
#include <utils/bip32.hpp>
#include <utils/txutils.hpp>
#include <utils/json.hpp>
#include <utils/loguru.hpp>
#include <boost/filesystem/string_file.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/thread/locks.hpp>
#include <set>
#include <sstream>

#include <univalue.h>
#include <rpc/util.h>
#include <policy/policy.h>

#ifdef _WIN32
#include <shlobj.h>
#endif

#define SQLCHECK(x)                                                         \
  do {                                                                      \
    int rc = (x);                                                           \
    if (rc != SQLITE_OK) {                                                  \
      throw nunchuk::StorageException(nunchuk::StorageException::SQL_ERROR, \
                                      sqlite3_errmsg(db_));                 \
    }                                                                       \
  } while (0)

using json = nlohmann::json;
namespace fs = boost::filesystem;
namespace ba = boost::algorithm;

namespace nunchuk {

NunchukDb::NunchukDb(Chain chain, const std::string& id,
                     const std::string& file_name,
                     const std::string& passphrase)
    : chain_(chain), id_(id), db_file_name_(file_name) {
  SQLCHECK(sqlite3_open(db_file_name_.c_str(), &db_));
  if (!passphrase.empty()) {
    const char* key = passphrase.c_str();
    SQLCHECK(sqlite3_key(db_, (const void*)key, strlen(key)));
  }
  if (sqlite3_exec(db_, "SELECT count(*) FROM sqlite_master;", NULL, NULL,
                   NULL) != SQLITE_OK) {
    throw NunchukException(NunchukException::INVALID_PASSPHRASE,
                           "invalid passphrase");
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
  SQLCHECK(sqlite3_rekey(db_, (const void*)key, strlen(key)));
  DLOG_F(INFO, "NunchukDb '%s' ReKey success", db_file_name_.c_str());
}

void NunchukDb::EncryptDb(const std::string& new_file_name,
                          const std::string& new_passphrase) {
  std::stringstream attach_sql;
  attach_sql << "ATTACH DATABASE '" << new_file_name << "' AS encrypted KEY '"
             << new_passphrase << "';";
  SQLCHECK(sqlite3_exec(db_, attach_sql.str().c_str(), NULL, NULL, NULL));
  SQLCHECK(sqlite3_exec(db_, "SELECT sqlcipher_export('encrypted');", NULL,
                        NULL, NULL));
  SQLCHECK(sqlite3_exec(db_, "DETACH DATABASE encrypted;", NULL, NULL, NULL));
}

void NunchukDb::DecryptDb(const std::string& new_file_name) {
  std::stringstream attach_sql;
  attach_sql << "ATTACH DATABASE '" << new_file_name
             << "' AS plaintext KEY '';";
  SQLCHECK(sqlite3_exec(db_, attach_sql.str().c_str(), NULL, NULL, NULL));
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
  return updated;
}

std::string NunchukDb::GetString(int key) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM VSTR WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, key);
  sqlite3_step(stmt);
  std::string value;
  if (sqlite3_column_text(stmt, 0)) {
    value = std::string((char*)sqlite3_column_text(stmt, 1));
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return value;
}

int64_t NunchukDb::GetInt(int key) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM VINT WHERE ID = ?;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, key);
  sqlite3_step(stmt);
  int64_t value = 0;
  if (sqlite3_column_text(stmt, 0)) {
    value = sqlite3_column_int64(stmt, 1);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return value;
}

void NunchukWalletDb::InitWallet(const std::string& name, int m, int n,
                                 const std::vector<SingleSigner>& signers,
                                 AddressType address_type, bool is_escrow,
                                 time_t create_date,
                                 const std::string& description) {
  CreateTable();
  // Note: when we update VTX table model, all these functions: CreatePsbt,
  // UpdatePsbtTxId, GetTransactions, GetTransaction need to be updated to
  // reflect the new fields.
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS VTX("
                        "ID TEXT PRIMARY KEY     NOT NULL,"
                        "VALUE           TEXT    NOT NULL,"
                        "HEIGHT          INT     NOT NULL,"
                        "FEE             INT     NOT NULL,"
                        "MEMO            TEXT    NOT NULL,"
                        "CHANGEPOS       INT     NOT NULL,"
                        "BLOCKTIME       INT     NOT NULL,"
                        "EXTRA           TEXT    NOT NULL);",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS ADDRESS("
                        "ADDR TEXT PRIMARY KEY     NOT NULL,"
                        "IDX             INT     NOT NULL,"
                        "INTERNAL        INT     NOT NULL,"
                        "USED            INT     NOT NULL,"
                        "UTXO            TEXT);",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS SIGNER("
                        "KEY TEXT PRIMARY KEY     NOT NULL,"
                        "NAME             TEXT    NOT NULL,"
                        "MASTER_ID        TEXT    NOT NULL,"
                        "LAST_HEALTHCHECK INT     NOT NULL);",
                        NULL, 0, NULL));
  PutString(DbKeys::NAME, name);
  PutString(DbKeys::DESCRIPTION, description);

  json immutable_data = {{"m", m},
                         {"n", n},
                         {"address_type", address_type},
                         {"is_escrow", is_escrow},
                         {"create_date", create_date}};
  PutString(DbKeys::IMMUTABLE_DATA, immutable_data.dump());
  for (auto&& signer : signers) {
    AddSigner(signer);
  }
}

void NunchukWalletDb::MaybeMigrate() {
  int64_t current_ver = GetInt(DbKeys::VERSION);
  if (current_ver == STORAGE_VER) return;
  if (current_ver < 1) {
    sqlite3_exec(db_, "ALTER TABLE VTX ADD COLUMN BLOCKTIME INT;", NULL, 0,
                 NULL);
  }
  if (current_ver < 2) {
    sqlite3_exec(db_, "ALTER TABLE VTX ADD COLUMN EXTRA TEXT;", NULL, 0, NULL);
  }
  DLOG_F(INFO, "NunchukWalletDb migrate to version %d", STORAGE_VER);
  PutInt(DbKeys::VERSION, STORAGE_VER);
}

std::string NunchukWalletDb::GetSingleSignerKey(const SingleSigner& signer) {
  json basic_data = {{"xpub", signer.get_xpub()},
                     {"public_key", signer.get_public_key()},
                     {"derivation_path", signer.get_derivation_path()},
                     {"master_fingerprint",
                      ba::to_lower_copy(signer.get_master_fingerprint())}};
  return basic_data.dump();
}

bool NunchukWalletDb::AddSigner(const SingleSigner& signer) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO SIGNER(KEY, NAME, MASTER_ID, LAST_HEALTHCHECK)"
      "VALUES (?1, ?2, ?3, ?4);";
  std::string key = GetSingleSignerKey(signer);
  std::string name = signer.get_name();
  std::string master_id = ba::to_lower_copy(signer.get_master_signer_id());
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, key.c_str(), key.size(), NULL);
  sqlite3_bind_text(stmt, 2, name.c_str(), name.size(), NULL);
  sqlite3_bind_text(stmt, 3, master_id.c_str(), master_id.size(), NULL);
  sqlite3_bind_int64(stmt, 4, signer.get_last_health_check());
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::SetSignerName(const SingleSigner& signer,
                                    const std::string& value) {
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE SIGNER SET NAME = ?1 WHERE KEY = ?2;";
  std::string key = GetSingleSignerKey(signer);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, value.c_str(), value.size(), NULL);
  sqlite3_bind_text(stmt, 2, key.c_str(), key.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::SetSignerMasterId(const SingleSigner& signer,
                                        const std::string& value) {
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE SIGNER SET MASTER_ID = ?1 WHERE KEY = ?2;";
  std::string key = GetSingleSignerKey(signer);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, value.c_str(), value.size(), NULL);
  sqlite3_bind_text(stmt, 2, key.c_str(), key.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::SetSignerLastHealthCheck(const SingleSigner& signer,
                                               time_t value) {
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE SIGNER SET LAST_HEALTHCHECK = ?1 WHERE KEY = ?2;";
  std::string key = GetSingleSignerKey(signer);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 3, value);
  sqlite3_bind_text(stmt, 4, key.c_str(), key.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

void NunchukWalletDb::DeleteWallet() {
  SQLCHECK(sqlite3_exec(db_, "DROP TABLE IF EXISTS SIGNER;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DROP TABLE IF EXISTS ADDRESS;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DROP TABLE IF EXISTS VTX;", NULL, 0, NULL));
  DropTable();
}

bool NunchukWalletDb::SetName(const std::string& value) {
  return PutString(DbKeys::NAME, value);
}

bool NunchukWalletDb::SetDescription(const std::string& value) {
  return PutString(DbKeys::DESCRIPTION, value);
}

Wallet NunchukWalletDb::GetWallet() const {
  json immutable_data = json::parse(GetString(DbKeys::IMMUTABLE_DATA));
  int m = immutable_data["m"];
  int n = immutable_data["n"];
  AddressType address_type = immutable_data["address_type"];
  bool is_escrow = immutable_data["is_escrow"];
  time_t create_date = immutable_data["create_date"];

  auto signers = GetSigners();
  auto balance = GetBalance();
  Wallet wallet(id_, m, n, signers, address_type, is_escrow, create_date);
  wallet.set_name(GetString(DbKeys::NAME));
  wallet.set_balance(balance);
  return wallet;
}

std::vector<SingleSigner> NunchukWalletDb::GetSigners() const {
  sqlite3_stmt* stmt;
  std::string sql =
      "SELECT KEY, NAME, MASTER_ID, LAST_HEALTHCHECK FROM SIGNER;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);
  std::vector<SingleSigner> signers;
  while (sqlite3_column_text(stmt, 0)) {
    std::string key = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string name = std::string((char*)sqlite3_column_text(stmt, 1));
    std::string master_id = std::string((char*)sqlite3_column_text(stmt, 2));

    json basic_info = json::parse(key);
    std::string xpub = basic_info["xpub"];
    std::string public_key = basic_info["public_key"];
    std::string derivation_path = basic_info["derivation_path"];
    std::string master_fingerprint = basic_info["master_fingerprint"];
    ba::to_lower(master_fingerprint);
    time_t last_health_check = sqlite3_column_int64(stmt, 3);
    SingleSigner signer(name, xpub, public_key, derivation_path,
                        master_fingerprint, last_health_check, master_id);
    signers.push_back(signer);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return signers;
}

bool NunchukWalletDb::AddAddress(const std::string& address, int index,
                                 bool internal) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO ADDRESS(ADDR, IDX, INTERNAL, USED)"
      "VALUES (?1, ?2, ?3, 0);";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, address.c_str(), address.size(), NULL);
  sqlite3_bind_int(stmt, 2, index);
  sqlite3_bind_int(stmt, 3, internal ? 1 : 0);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
  return true;
}

bool NunchukWalletDb::UseAddress(const std::string& address) {
  if (address.empty()) return false;
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE ADDRESS SET USED = 1 WHERE ADDR = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, address.c_str(), address.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

std::vector<std::string> NunchukWalletDb::GetAddresses(bool used,
                                                       bool internal) const {
  sqlite3_stmt* stmt;
  std::string sql =
      "SELECT ADDR FROM ADDRESS WHERE USED = ?1 AND INTERNAL = ?2;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, used ? 1 : 0);
  sqlite3_bind_int(stmt, 2, internal ? 1 : 0);
  sqlite3_step(stmt);
  std::vector<std::string> addresses;
  while (sqlite3_column_text(stmt, 0)) {
    addresses.push_back(std::string((char*)sqlite3_column_text(stmt, 0)));
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return addresses;
}

std::vector<std::string> NunchukWalletDb::GetAllAddresses() const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT ADDR FROM ADDRESS;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);
  std::vector<std::string> addresses;
  while (sqlite3_column_text(stmt, 0)) {
    addresses.push_back(std::string((char*)sqlite3_column_text(stmt, 0)));
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return addresses;
}

int NunchukWalletDb::GetCurrentAddressIndex(bool internal) const {
  sqlite3_stmt* stmt;
  std::string sql =
      "SELECT MAX(IDX) FROM ADDRESS WHERE INTERNAL = ? GROUP BY INTERNAL";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, internal ? 1 : 0);
  int current_index = -1;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    current_index = sqlite3_column_int(stmt, 0);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return current_index;
}

Transaction NunchukWalletDb::InsertTransaction(const std::string& raw_tx,
                                               int height, time_t blocktime,
                                               Amount fee,
                                               const std::string& memo,
                                               int change_pos) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO VTX(ID, VALUE, HEIGHT, FEE, MEMO, CHANGEPOS, BLOCKTIME, "
      "EXTRA)"
      "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '');";
  CMutableTransaction mtx = DecodeRawTransaction(raw_tx);
  std::string tx_id = mtx.GetHash().GetHex();
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_bind_text(stmt, 2, raw_tx.c_str(), raw_tx.size(), NULL);
  sqlite3_bind_int64(stmt, 3, height);
  sqlite3_bind_int64(stmt, 4, fee);
  sqlite3_bind_text(stmt, 5, memo.c_str(), memo.size(), NULL);
  sqlite3_bind_int(stmt, 6, change_pos);
  sqlite3_bind_int64(stmt, 7, blocktime);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
  Transaction tx = GetTransaction(tx_id);
  if (height > 0) {
    for (auto&& output : tx.get_outputs()) UseAddress(output.first);
  }
  return tx;
}

void NunchukWalletDb::SetReplacedBy(const std::string& old_txid,
                                    const std::string& new_txid) {
  // Get replaced tx extra
  sqlite3_stmt* select_stmt;
  std::string select_sql = "SELECT EXTRA FROM VTX WHERE ID = ?;";
  sqlite3_prepare_v2(db_, select_sql.c_str(), -1, &select_stmt, NULL);
  sqlite3_bind_text(select_stmt, 1, old_txid.c_str(), old_txid.size(), NULL);
  sqlite3_step(select_stmt);
  if (sqlite3_column_text(select_stmt, 0)) {
    // Update replaced tx extra
    std::string extra = std::string((char*)sqlite3_column_text(select_stmt, 0));
    json extra_json = json::parse(extra);
    extra_json["replaced_by_txid"] = new_txid;
    extra = extra_json.dump();

    sqlite3_stmt* update_stmt;
    std::string update_sql = "UPDATE VTX SET EXTRA = ?1 WHERE ID = ?2;";
    sqlite3_prepare_v2(db_, update_sql.c_str(), -1, &update_stmt, NULL);
    sqlite3_bind_text(update_stmt, 1, extra.c_str(), extra.size(), NULL);
    sqlite3_bind_text(update_stmt, 2, old_txid.c_str(), old_txid.size(), NULL);
    sqlite3_step(update_stmt);
    SQLCHECK(sqlite3_finalize(update_stmt));
  }
  SQLCHECK(sqlite3_finalize(select_stmt));
}

bool NunchukWalletDb::UpdateTransaction(const std::string& raw_tx, int height,
                                        time_t blocktime,
                                        const std::string& reject_msg) {
  if (height == -1) return false;

  CMutableTransaction mtx = DecodeRawTransaction(raw_tx);
  std::string tx_id = mtx.GetHash().GetHex();

  std::string extra = "";
  if (height <= 0) {
    // Persist signers to extra if the psbt existed
    sqlite3_stmt* stmt;
    std::string sql =
        "SELECT VALUE, EXTRA FROM VTX WHERE ID = ? AND HEIGHT = -1;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
    sqlite3_step(stmt);
    if (sqlite3_column_text(stmt, 1)) {
      std::string value = std::string((char*)sqlite3_column_text(stmt, 0));
      extra = std::string((char*)sqlite3_column_text(stmt, 1));
      Transaction tx =
          GetTransactionFromPartiallySignedTransaction(DecodePsbt(value), 0);

      json extra_json = json::parse(extra);
      extra_json["signers"] = tx.get_signers();
      if (!reject_msg.empty()) {
        extra_json["reject_msg"] = reject_msg;
      }
      extra = extra_json.dump();
      if (extra_json["replace_txid"] != nullptr) {
        SetReplacedBy(extra_json["replace_txid"], tx_id);
      }
    }
    SQLCHECK(sqlite3_finalize(stmt));
  }

  sqlite3_stmt* stmt;
  std::string sql =
      extra.empty() ? "UPDATE VTX SET VALUE = ?1, HEIGHT = ?2, BLOCKTIME = ?3 "
                      "WHERE ID = ?4;"
                    : "UPDATE VTX SET VALUE = ?1, HEIGHT = ?2, BLOCKTIME = ?3, "
                      "EXTRA = ?5 WHERE ID = ?4;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, raw_tx.c_str(), raw_tx.size(), NULL);
  sqlite3_bind_int64(stmt, 2, height);
  sqlite3_bind_int64(stmt, 3, blocktime);
  sqlite3_bind_text(stmt, 4, tx_id.c_str(), tx_id.size(), NULL);
  if (!extra.empty()) {
    sqlite3_bind_text(stmt, 5, extra.c_str(), extra.size(), NULL);
  }
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated && height > 0) {
    Transaction tx = GetTransaction(tx_id);
    if (height > 0) {
      for (auto&& output : tx.get_outputs()) UseAddress(output.first);
    }
  }
  return updated;
}

bool NunchukWalletDb::UpdateTransactionMemo(const std::string& tx_id,
                                            const std::string& memo) {
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE VTX SET MEMO = ?1 WHERE ID = ?2;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, memo.c_str(), memo.size(), NULL);
  sqlite3_bind_text(stmt, 2, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

Transaction NunchukWalletDb::CreatePsbt(
    const std::string& psbt, Amount fee, const std::string& memo,
    int change_pos, const std::map<std::string, Amount>& outputs,
    Amount fee_rate, bool subtract_fee_from_amount,
    const std::string& replace_tx) {
  PartiallySignedTransaction psbtx = DecodePsbt(psbt);
  std::string tx_id = psbtx.tx.get().GetHash().GetHex();

  json extra{};
  extra["outputs"] = outputs;
  extra["fee_rate"] = fee_rate;
  extra["subtract"] = subtract_fee_from_amount;
  if (!replace_tx.empty()) {
    extra["replace_txid"] = replace_tx;
  }

  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO "
      "VTX(ID, VALUE, HEIGHT, FEE, MEMO, CHANGEPOS, BLOCKTIME, EXTRA)"
      "VALUES (?1, ?2, -1, ?3, ?4, ?5, ?6, ?7);";
  std::string extra_str = extra.dump();
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_bind_text(stmt, 2, psbt.c_str(), psbt.size(), NULL);
  sqlite3_bind_int64(stmt, 3, fee);
  sqlite3_bind_text(stmt, 4, memo.c_str(), memo.size(), NULL);
  sqlite3_bind_int(stmt, 5, change_pos);
  sqlite3_bind_int64(stmt, 6, 0);
  sqlite3_bind_text(stmt, 7, extra_str.c_str(), extra_str.size(), NULL);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
  return GetTransaction(tx_id);
}

bool NunchukWalletDb::UpdatePsbt(const std::string& psbt) {
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE VTX SET VALUE = ?1 WHERE ID = ?2 AND HEIGHT = -1;";
  PartiallySignedTransaction psbtx = DecodePsbt(psbt);
  std::string tx_id = psbtx.tx.get().GetHash().GetHex();
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, psbt.c_str(), psbt.size(), NULL);
  sqlite3_bind_text(stmt, 2, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

bool NunchukWalletDb::UpdatePsbtTxId(const std::string& old_id,
                                     const std::string& new_id) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM VTX WHERE ID = ? AND HEIGHT = -1;;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, old_id.c_str(), old_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    std::string value = std::string((char*)sqlite3_column_text(stmt, 1));
    int height = sqlite3_column_int(stmt, 2);
    int fee = sqlite3_column_int(stmt, 3);
    std::string memo = std::string((char*)sqlite3_column_text(stmt, 4));
    int change_pos = sqlite3_column_int(stmt, 5);
    time_t blocktime = sqlite3_column_int64(stmt, 6);
    std::string extra;
    if (sqlite3_column_text(stmt, 7)) {
      extra = std::string((char*)sqlite3_column_text(stmt, 7));
    }
    SQLCHECK(sqlite3_finalize(stmt));

    sqlite3_stmt* insert_stmt;
    std::string insert_sql =
        "INSERT INTO "
        "VTX(ID, VALUE, HEIGHT, FEE, MEMO, CHANGEPOS, BLOCKTIME, EXTRA)"
        "VALUES (?1, ?2, -1, ?3, ?4, ?5, ?6, ?7);";
    sqlite3_prepare_v2(db_, insert_sql.c_str(), -1, &insert_stmt, NULL);
    sqlite3_bind_text(insert_stmt, 1, new_id.c_str(), new_id.size(), NULL);
    sqlite3_bind_text(insert_stmt, 2, value.c_str(), value.size(), NULL);
    sqlite3_bind_int64(insert_stmt, 3, fee);
    sqlite3_bind_text(insert_stmt, 4, memo.c_str(), memo.size(), NULL);
    sqlite3_bind_int(insert_stmt, 5, change_pos);
    sqlite3_bind_int64(insert_stmt, 6, 0);
    sqlite3_bind_text(insert_stmt, 7, extra.c_str(), extra.size(), NULL);
    sqlite3_step(insert_stmt);
    SQLCHECK(sqlite3_finalize(insert_stmt));
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw StorageException(StorageException::TX_NOT_FOUND, "old tx not found!");
  }
  return DeleteTransaction(old_id);
}

std::string NunchukWalletDb::GetPsbt(const std::string& tx_id) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT VALUE FROM VTX WHERE ID = ? AND HEIGHT = -1;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    std::string rs = std::string((char*)sqlite3_column_text(stmt, 0));
    SQLCHECK(sqlite3_finalize(stmt));
    return rs;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    return "";
  }
}

Transaction NunchukWalletDb::GetTransaction(const std::string& tx_id) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM VTX WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    std::string value = std::string((char*)sqlite3_column_text(stmt, 1));
    int height = sqlite3_column_int(stmt, 2);
    int fee = sqlite3_column_int(stmt, 3);
    std::string memo = std::string((char*)sqlite3_column_text(stmt, 4));
    int change_pos = sqlite3_column_int(stmt, 5);
    time_t blocktime = sqlite3_column_int64(stmt, 6);

    json immutable_data = json::parse(GetString(DbKeys::IMMUTABLE_DATA));
    int m = immutable_data["m"];

    auto tx = height == -1 ? GetTransactionFromPartiallySignedTransaction(
                                 DecodePsbt(value), m)
                           : GetTransactionFromCMutableTransaction(
                                 DecodeRawTransaction(value), height);
    tx.set_txid(tx_id);
    tx.set_m(m);
    tx.set_fee(Amount(fee));
    tx.set_memo(memo);
    tx.set_change_index(change_pos);
    tx.set_blocktime(blocktime);
    // Default value, will set in FillSendReceiveData
    // TODO: Replace this asap. This code is fragile and potentially dangerous,
    // since it relies on external assumptions (flow of outside code) that might
    // become false
    tx.set_receive(false);
    tx.set_sub_amount(0);

    if (height >= 0) {
      auto singers = GetSigners();
      for (auto&& signer : singers) {
        tx.set_signer(signer.get_master_fingerprint(), false);
      }
    }

    if (sqlite3_column_text(stmt, 7)) {
      std::string extra = std::string((char*)sqlite3_column_text(stmt, 7));
      FillExtra(extra, tx);
    }
    SQLCHECK(sqlite3_finalize(stmt));
    return tx;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw StorageException(StorageException::TX_NOT_FOUND, "tx not found!");
  }
}

bool NunchukWalletDb::DeleteTransaction(const std::string& tx_id) {
  sqlite3_stmt* stmt;
  std::string sql = "DELETE FROM VTX WHERE ID = ?;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

std::string NunchukWalletDb::GetDescriptor(bool internal) const {
  Wallet wallet = GetWallet();
  WalletType wallet_type =
      wallet.get_n() == 1
          ? WalletType::SINGLE_SIG
          : (wallet.is_escrow() ? WalletType::ESCROW : WalletType::MULTI_SIG);
  return GetDescriptorForSigners(wallet.get_signers(), wallet.get_m(), internal,
                                 wallet.get_address_type(), wallet_type);
}

std::string NunchukWalletDb::GetColdcardFile() const {
  Wallet wallet = GetWallet();
  std::stringstream content;
  content << "# Exported from Nunchuk" << std::endl
          << "Name: " << wallet.get_name().substr(0, 20) << std::endl
          << "Policy: " << wallet.get_m() << "/" << wallet.get_n() << std::endl
          << "Format: "
          << (wallet.get_address_type() == AddressType::LEGACY
                  ? "P2SH"
                  : wallet.get_address_type() == AddressType::NATIVE_SEGWIT
                        ? "P2WSH"
                        : "P2WSH-P2SH")
          << std::endl
          << std::endl;
  for (auto&& signer : wallet.get_signers()) {
    content << "# derivation: " << signer.get_derivation_path() << std::endl
            << signer.get_master_fingerprint() << ": " << signer.get_xpub()
            << std::endl
            << std::endl;
  }
  return content.str();
}

bool NunchukWalletDb::SetUtxos(const std::string& address,
                               const std::string& utxo) {
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE ADDRESS SET UTXO = ?1 WHERE ADDR = ?2;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, utxo.c_str(), utxo.size(), NULL);
  sqlite3_bind_text(stmt, 2, address.c_str(), address.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

Amount NunchukWalletDb::GetBalance() const {
  auto utxos = GetUnspentOutputs(true);
  auto change_addresses = GetAddresses(false, true);
  auto is_my_change_address = [change_addresses](std::string address) {
    return (std::find(change_addresses.begin(), change_addresses.end(),
                      address) != change_addresses.end());
  };
  Amount balance = 0;
  for (auto&& utxo : utxos) {
    // Only include confirmed Receive amount and in-mempool Change amount
    // in the wallet balance
    if (utxo.get_height() > 0 || is_my_change_address(utxo.get_address()))
      balance += utxo.get_amount();
  }
  return balance;
}

std::vector<UnspentOutput> NunchukWalletDb::GetUnspentOutputs(
    bool remove_locked) const {
  std::vector<Transaction> transactions;
  if (remove_locked) transactions = GetTransactions();
  auto input_str = [](std::string tx_id, int vout) {
    return boost::str(boost::format{"%s:%d"} % tx_id % vout);
  };
  std::set<std::string> locked_utxos;
  for (auto&& tx : transactions) {
    if (tx.get_height() != 0) continue;
    // remove UTXOs of unconfirmed transactions
    for (auto&& input : tx.get_inputs()) {
      locked_utxos.insert(input_str(input.first, input.second));
    }
  }

  sqlite3_stmt* stmt;
  std::string sql = "SELECT ADDR, UTXO FROM ADDRESS WHERE UTXO IS NOT NULL;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  std::vector<UnspentOutput> rs;
  while (sqlite3_column_text(stmt, 0)) {
    std::string address = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string utxo_str = std::string((char*)sqlite3_column_text(stmt, 1));
    json utxo_json = json::parse(utxo_str);
    for (auto it = utxo_json.begin(); it != utxo_json.end(); ++it) {
      json item = it.value();
      if (locked_utxos.find(input_str(item["tx_hash"], item["tx_pos"])) !=
          locked_utxos.end()) {
        continue;
      }
      UnspentOutput utxo;
      utxo.set_txid(item["tx_hash"]);
      utxo.set_vout(item["tx_pos"]);
      utxo.set_address(address);
      utxo.set_amount(item["value"]);
      utxo.set_height(item["height"]);
      rs.push_back(utxo);
    }
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

std::vector<Transaction> NunchukWalletDb::GetTransactions(int count,
                                                          int skip) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM VTX;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  auto utxos = GetUnspentOutputs(false);
  auto is_valid_input = [utxos](const TxInput& input) {
    for (auto&& utxo : utxos) {
      if (input.first == utxo.get_txid() && input.second == utxo.get_vout())
        return true;
    }
    return false;
  };

  std::vector<Transaction> rs;
  while (sqlite3_column_text(stmt, 0)) {
    std::string tx_id = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string value = std::string((char*)sqlite3_column_text(stmt, 1));
    int height = sqlite3_column_int(stmt, 2);
    int fee = sqlite3_column_int(stmt, 3);
    std::string memo = std::string((char*)sqlite3_column_text(stmt, 4));
    int change_pos = sqlite3_column_int(stmt, 5);
    time_t blocktime = sqlite3_column_int64(stmt, 6);

    json immutable_data = json::parse(GetString(DbKeys::IMMUTABLE_DATA));
    int m = immutable_data["m"];

    auto tx = height == -1 ? GetTransactionFromPartiallySignedTransaction(
                                 DecodePsbt(value), m)
                           : GetTransactionFromCMutableTransaction(
                                 DecodeRawTransaction(value), height);
    if (height == -1) {
      // remove invalid, out-of-date Send transactions
      bool is_valid = true;
      for (auto&& input : tx.get_inputs()) {
        if (!is_valid_input(input)) {
          is_valid = false;
          break;
        }
      }
      if (!is_valid) {
        sqlite3_step(stmt);
        continue;
      }
    }

    tx.set_txid(tx_id);
    tx.set_m(m);
    tx.set_fee(Amount(fee));
    tx.set_memo(memo);
    tx.set_change_index(change_pos);
    tx.set_blocktime(blocktime);

    if (height >= 0) {
      auto singers = GetSigners();
      for (auto& signer : singers) {
        tx.set_signer(signer.get_master_fingerprint(), true);
      }
    }

    if (sqlite3_column_text(stmt, 7)) {
      std::string extra = std::string((char*)sqlite3_column_text(stmt, 7));
      FillExtra(extra, tx);
    }
    rs.push_back(tx);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

std::string NunchukWalletDb::FillPsbt(const std::string& base64_psbt) {
  auto psbt = DecodePsbt(base64_psbt);
  if (!psbt.tx.has_value()) return base64_psbt;

  FlatSigningProvider provider;
  std::string internal_desc = GetDescriptor(true);
  std::string external_desc = GetDescriptor(false);
  UniValue uv;
  uv.read(GetDescriptorsImportString(external_desc, internal_desc));
  auto descs = uv.get_array();
  for (size_t i = 0; i < descs.size(); ++i) {
    EvalDescriptorStringOrObject(descs[i], provider);
  }

  int nin = psbt.tx.get().vin.size();
  for (int i = 0; i < nin; i++) {
    std::string tx_id = psbt.tx.get().vin[i].prevout.hash.GetHex();
    sqlite3_stmt* stmt;
    std::string sql = "SELECT VALUE FROM VTX WHERE ID = ? AND HEIGHT > -1;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
    sqlite3_step(stmt);
    if (sqlite3_column_text(stmt, 0)) {
      std::string raw_tx = std::string((char*)sqlite3_column_text(stmt, 0));
      psbt.inputs[i].non_witness_utxo =
          MakeTransactionRef(DecodeRawTransaction(raw_tx));
      SignPSBTInput(provider, psbt, i, 1);
    }
    SQLCHECK(sqlite3_finalize(stmt));
  }
  // Update script/keypath information using descriptor data.
  for (unsigned int i = 0; i < psbt.tx.get().vout.size(); ++i) {
    UpdatePSBTOutput(provider, psbt, i);
  }
  return EncodePsbt(psbt);
}

void NunchukWalletDb::FillExtra(const std::string& extra,
                                Transaction& tx) const {
  if (!extra.empty()) {
    json extra_json = json::parse(extra);
    if (extra_json["signers"] != nullptr && tx.get_height() >= 0) {
      for (auto&& signer : tx.get_signers()) {
        tx.set_signer(signer.first, extra_json["signers"][signer.first]);
      }
    }
    if (extra_json["outputs"] != nullptr) {
      for (auto&& output : tx.get_outputs()) {
        auto amount = extra_json["outputs"][output.first];
        if (amount != nullptr) {
          tx.add_user_output({output.first, Amount(amount)});
        }
      }
    }
    if (extra_json["fee_rate"] != nullptr) {
      tx.set_fee_rate(extra_json["fee_rate"]);
    }
    if (extra_json["subtract"] != nullptr) {
      tx.set_subtract_fee_from_amount(extra_json["subtract"]);
    }
    if (tx.get_status() == TransactionStatus::PENDING_CONFIRMATION &&
        extra_json["replaced_by_txid"] != nullptr) {
      tx.set_status(TransactionStatus::REPLACED);
      tx.set_replaced_by_txid(extra_json["replaced_by_txid"]);
    }
  }
}

// TODO (bakaoh): consider persisting these data
void NunchukWalletDb::FillSendReceiveData(Transaction& tx) {
  auto addresses = GetAllAddresses();
  auto is_my_address = [addresses](std::string address) {
    return (std::find(addresses.begin(), addresses.end(), address) !=
            addresses.end());
  };
  auto input = tx.get_inputs()[0];
  TxOutput prev_out;
  try {
    prev_out = GetTransaction(input.first).get_outputs()[input.second];
  } catch (StorageException& se) {
    if (se.code() != StorageException::TX_NOT_FOUND) throw;
  }
  auto address = prev_out.first;
  if (is_my_address(address)) {
    Amount send_amount(tx.get_fee());
    for (auto&& output : tx.get_outputs()) {
      if (!is_my_address(output.first)) {
        send_amount += output.second;
      }
    }
    tx.set_receive(false);
    tx.set_sub_amount(send_amount);
  } else {
    Amount receive_amount{0};
    for (auto&& output : tx.get_outputs()) {
      if (is_my_address(output.first)) {
        receive_amount += output.second;
        tx.add_receive_output(output);
      }
    }
    tx.set_receive(true);
    tx.set_sub_amount(receive_amount);
  }
}

void NunchukSignerDb::InitSigner(const std::string& name,
                                 const std::string& fingerprint) {
  CreateTable();
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS BIP32("
                        "PATH VARCHAR(20) PRIMARY KEY     NOT NULL,"
                        "XPUB                     TEXT    NOT NULL,"
                        "TYPE                     TEXT    NOT NULL,"
                        "USED                     INT);",
                        NULL, 0, NULL));
  PutString(DbKeys::NAME, name);
  PutString(DbKeys::FINGERPRINT, fingerprint);
}

void NunchukSignerDb::DeleteSigner() {
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

std::string NunchukSignerDb::GetName() const { return GetString(DbKeys::NAME); }

time_t NunchukSignerDb::GetLastHealthCheck() const {
  return GetInt(DbKeys::LAST_HEALTH_CHECK);
}

void NunchukAppStateDb::Init() { CreateTable(); }

int NunchukAppStateDb::GetChainTip() const { return GetInt(DbKeys::CHAIN_TIP); }

bool NunchukAppStateDb::SetChainTip(int value) {
  return PutInt(DbKeys::CHAIN_TIP, value);
}

std::string NunchukAppStateDb::GetSelectedWallet() const {
  return GetString(DbKeys::SELECTED_WALLET);
}

bool NunchukAppStateDb::SetSelectedWallet(const std::string& value) {
  return PutString(DbKeys::SELECTED_WALLET, value);
}

std::vector<SingleSigner> NunchukSignerDb::GetSingleSigners() const {
  std::string name = GetName();
  std::string master_fingerprint = GetFingerprint();
  time_t last_health_check = GetLastHealthCheck();

  sqlite3_stmt* stmt;
  std::string sql = "SELECT PATH, XPUB FROM BIP32 WHERE USED != -1;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);
  std::vector<SingleSigner> signers;
  while (sqlite3_column_text(stmt, 0)) {
    std::string path = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string xpub = std::string((char*)sqlite3_column_text(stmt, 1));
    SingleSigner signer(name, xpub, "", path, master_fingerprint,
                        last_health_check, id_);
    signers.push_back(signer);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return signers;
}

fs::path NunchukStorage::GetDefaultDataDir() const {
  // Windows: C:\Users\Username\AppData\Roaming\Nunchuk
  // Mac: ~/Library/Application Support/Nunchuk
  // Unix: ~/.nunchuk
#ifdef _WIN32
  // Windows
  WCHAR pszPath[MAX_PATH] = L"";
  if (SHGetSpecialFolderPathW(nullptr, pszPath, CSIDL_APPDATA, true)) {
    return fs::path(pszPath) / "Nunchuk";
  }
  return fs::path("Nunchuk");
#else
  fs::path pathRet;
  char* pszHome = getenv("HOME");
  if (pszHome == nullptr || strlen(pszHome) == 0)
    pathRet = fs::path("/");
  else
    pathRet = fs::path(pszHome);
#ifdef __APPLE__
  // Mac
  return pathRet / "Library/Application Support/Nunchuk";
#else
  // Unix
  return pathRet / ".nunchuk";
#endif
#endif
}

bool NunchukStorage::WriteFile(const std::string& file_path,
                               const std::string& value) {
  fs::save_string_file(fs::system_complete(file_path), value);
  return true;
}

std::string NunchukStorage::LoadFile(const std::string& file_path) {
  std::string value;
  fs::load_string_file(fs::system_complete(file_path), value);
  return value;
}

bool NunchukStorage::ExportWallet(Chain chain, const std::string& wallet_id,
                                  const std::string& file_path,
                                  ExportFormat format) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto wallet_db = GetWalletDb(chain, wallet_id);
  switch (format) {
    case ExportFormat::COLDCARD:
      return WriteFile(file_path, wallet_db.GetColdcardFile());
    case ExportFormat::DESCRIPTOR: {
      std::stringstream descs;
      descs << wallet_db.GetDescriptor(false);
      bool is_escrow = wallet_db.GetWallet().is_escrow();
      if (!is_escrow) {
        descs << "\n" + wallet_db.GetDescriptor(true);
      }
      return WriteFile(file_path, descs.str());
    }
    case ExportFormat::DB:
      if (passphrase_.empty()) {
        fs::copy_file(GetWalletDir(chain, wallet_id), file_path);
      } else {
        wallet_db.DecryptDb(file_path);
      }
      return true;
    default:
      return false;
  }
}

std::string NunchukStorage::ImportWalletDb(Chain chain,
                                           const std::string& file_path) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  auto wallet_db = NunchukWalletDb{chain, "", file_path, ""};
  std::string id = wallet_db.GetId();
  auto wallet_file = GetWalletDir(chain, id);
  if (fs::exists(wallet_file)) {
    throw StorageException(StorageException::WALLET_EXISTED, "wallet existed!");
  }
  wallet_db.EncryptDb(wallet_file.string(), passphrase_);
  return id;
}

NunchukStorage::NunchukStorage(const std::string& datadir,
                               const std::string& passphrase)
    : passphrase_(passphrase) {
  if (!datadir.empty()) {
    datadir_ = fs::system_complete(datadir);
    if (!fs::is_directory(datadir_)) {
      throw StorageException(StorageException::INVALID_DATADIR,
                             "datadir is not directory!");
    }
  } else {
    datadir_ = GetDefaultDataDir();
  }

  if (fs::create_directories(datadir_ / "testnet")) {
    fs::create_directories(datadir_ / "testnet" / "wallets");
    fs::create_directories(datadir_ / "testnet" / "signers");
  }
  if (fs::create_directories(datadir_ / "mainnet")) {
    fs::create_directories(datadir_ / "mainnet" / "wallets");
    fs::create_directories(datadir_ / "mainnet" / "signers");
  }
  fs::create_directories(datadir_ / "tmp");
}

void NunchukStorage::SetPassphrase(Chain chain, const std::string& value) {
  if (value == passphrase_) {
    throw NunchukException(NunchukException::PASSPHRASE_ALREADY_USED,
                           "passphrase used");
  }
  auto wallets = ListWallets(chain);
  auto signers = ListMasterSigners(chain);
  boost::unique_lock<boost::shared_mutex> lock(access_);
  if (passphrase_.empty()) {
    for (auto&& wallet_id : wallets) {
      auto old_file = GetWalletDir(chain, wallet_id);
      auto new_file = datadir_ / "tmp" / wallet_id;
      GetWalletDb(chain, wallet_id).EncryptDb(new_file.string(), value);
      fs::copy_file(new_file, old_file, fs::copy_option::overwrite_if_exists);
      fs::remove(new_file);
    }
    for (auto&& signer_id : signers) {
      auto old_file = GetSignerDir(chain, signer_id);
      auto new_file = datadir_ / "tmp" / signer_id;
      GetSignerDb(chain, signer_id).EncryptDb(new_file.string(), value);
      fs::copy_file(new_file, old_file, fs::copy_option::overwrite_if_exists);
      fs::remove(new_file);
    }
  } else if (value.empty()) {
    for (auto&& wallet_id : wallets) {
      auto old_file = GetWalletDir(chain, wallet_id);
      auto new_file = datadir_ / "tmp" / wallet_id;
      GetWalletDb(chain, wallet_id).DecryptDb(new_file.string());
      fs::copy_file(new_file, old_file, fs::copy_option::overwrite_if_exists);
      fs::remove(new_file);
    }
    for (auto&& signer_id : signers) {
      auto old_file = GetSignerDir(chain, signer_id);
      auto new_file = datadir_ / "tmp" / signer_id;
      GetSignerDb(chain, signer_id).DecryptDb(new_file.string());
      fs::copy_file(new_file, old_file, fs::copy_option::overwrite_if_exists);
      fs::remove(new_file);
    }
  } else {
    for (auto&& wallet_id : wallets) {
      GetWalletDb(chain, wallet_id).ReKey(value);
    }
    for (auto&& signer_id : signers) {
      GetSignerDb(chain, signer_id).ReKey(value);
    }
  }

  passphrase_ = value;
}

std::string NunchukStorage::ChainStr(Chain chain) const {
  if (chain == Chain::TESTNET) {
    return "testnet";
  } else if (chain == Chain::REGTEST) {
    return "regtest";
  }
  return "mainnet";
}

fs::path NunchukStorage::GetWalletDir(Chain chain,
                                      const std::string& id) const {
  return datadir_ / ChainStr(chain) / "wallets" / id;
}

fs::path NunchukStorage::GetSignerDir(Chain chain,
                                      const std::string& id) const {
  return datadir_ / ChainStr(chain) / "signers" / id;
}

fs::path NunchukStorage::GetAppStateDir(Chain chain) const {
  return datadir_ / ChainStr(chain) / "state";
}

NunchukWalletDb NunchukStorage::GetWalletDb(Chain chain,
                                            const std::string& id) {
  fs::path db_file = GetWalletDir(chain, id);
  if (!fs::exists(db_file)) {
    throw StorageException(StorageException::WALLET_NOT_FOUND,
                           "wallet not exists!");
  }
  return NunchukWalletDb{chain, id, db_file.string(), passphrase_};
}

NunchukSignerDb NunchukStorage::GetSignerDb(Chain chain,
                                            const std::string& id) {
  fs::path db_file = GetSignerDir(chain, id);
  if (!fs::exists(db_file)) {
    throw StorageException(StorageException::MASTERSIGNER_NOT_FOUND,
                           "signer not exists!");
  }
  return NunchukSignerDb{chain, id, db_file.string(), passphrase_};
}

NunchukAppStateDb NunchukStorage::GetAppStateDb(Chain chain) {
  fs::path db_file = GetAppStateDir(chain);
  bool is_new = !fs::exists(db_file);
  auto db = NunchukAppStateDb{chain, "", db_file.string(), ""};
  if (is_new) db.Init();
  return db;
}

Wallet NunchukStorage::CreateWallet(Chain chain, const std::string& name, int m,
                                    int n,
                                    const std::vector<SingleSigner>& signers,
                                    AddressType address_type, bool is_escrow,
                                    const std::string& description) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  WalletType wallet_type =
      n == 1 ? WalletType::SINGLE_SIG
             : (is_escrow ? WalletType::ESCROW : WalletType::MULTI_SIG);
  for (auto&& signer : signers) {
    if (signer.has_master_signer()) {
      bool usable =
          GetSignerDb(chain, signer.get_master_signer_id())
              .UseIndex(wallet_type, address_type,
                        GetIndexFromPath(signer.get_derivation_path()));
      if (!usable) {
        throw StorageException(StorageException::SIGNER_USED, "signer used!");
      }
    }
  }
  std::string external_desc =
      GetDescriptorForSigners(signers, m, false, address_type, wallet_type);
  std::string id = GetDescriptorChecksum(external_desc);
  fs::path wallet_file = GetWalletDir(chain, id);
  if (fs::exists(wallet_file)) {
    throw StorageException(StorageException::WALLET_EXISTED, "wallet existed!");
  }
  NunchukWalletDb wallet_db{chain, id, wallet_file.string(), passphrase_};
  time_t create_date = std::time(0);
  wallet_db.InitWallet(name, m, n, signers, address_type, is_escrow,
                       create_date, description);
  Wallet wallet(id, m, n, signers, address_type, is_escrow, create_date);
  wallet.set_name(name);
  wallet.set_description(description);
  wallet.set_balance(0);
  return wallet;
}

std::string NunchukStorage::CreateMasterSigner(Chain chain,
                                               const std::string& name,
                                               const std::string& fingerprint) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  std::string id = fingerprint;
  NunchukSignerDb signer_db{chain, id, GetSignerDir(chain, id).string(),
                            passphrase_};
  signer_db.InitSigner(name, fingerprint);
  return id;
}

SingleSigner NunchukStorage::GetSignerFromMasterSigner(
    Chain chain, const std::string& mastersigner_id,
    const WalletType& wallet_type, const AddressType& address_type, int index) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto signer_db = GetSignerDb(chain, mastersigner_id);
  std::string path = GetBip32Path(chain, wallet_type, address_type, index);
  return SingleSigner(signer_db.GetName(),
                      signer_db.GetXpub(wallet_type, address_type, index), "",
                      path, signer_db.GetFingerprint(),
                      signer_db.GetLastHealthCheck(), mastersigner_id);
}

std::vector<SingleSigner> NunchukStorage::GetSignersFromMasterSigner(
    Chain chain, const std::string& mastersigner_id) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id).GetSingleSigners();
}

bool NunchukStorage::CacheMasterSignerXPub(Chain chain,
                                           const std::string& mastersigner_id,
                                           const std::string& path,
                                           const std::string& xpub) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id).AddXPub(path, xpub, "custom");
}

bool NunchukStorage::CacheMasterSignerXPub(Chain chain,
                                           const std::string& mastersigner_id,
                                           const WalletType& wallet_type,
                                           const AddressType& address_type,
                                           int index, const std::string& xpub) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id)
      .AddXPub(wallet_type, address_type, index, xpub);
}

int NunchukStorage::GetCurrentIndexFromMasterSigner(
    Chain chain, const std::string& mastersigner_id,
    const WalletType& wallet_type, const AddressType& address_type) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id)
      .GetUnusedIndex(wallet_type, address_type);
}

int NunchukStorage::GetCachedIndexFromMasterSigner(
    Chain chain, const std::string& mastersigner_id,
    const WalletType& wallet_type, const AddressType& address_type) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id)
      .GetCachedIndex(wallet_type, address_type);
}

std::string NunchukStorage::GetMasterSignerXPub(
    Chain chain, const std::string& mastersigner_id, const std::string& path) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id).GetXpub(path);
}

std::vector<std::string> NunchukStorage::ListWallets(Chain chain) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  fs::path directory = (datadir_ / ChainStr(chain) / "wallets");
  std::vector<std::string> ids;
  for (auto&& f : fs::directory_iterator(directory)) {
    ids.push_back(f.path().filename().string());
  }
  return ids;
}

std::vector<std::string> NunchukStorage::ListMasterSigners(Chain chain) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  fs::path directory = (datadir_ / ChainStr(chain) / "signers");
  std::vector<std::string> ids;
  for (auto&& f : fs::directory_iterator(directory)) {
    ids.push_back(f.path().filename().string());
  }
  return ids;
}

Wallet NunchukStorage::GetWallet(Chain chain, const std::string& id) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto wallet_db = GetWalletDb(chain, id);
  Wallet wallet = wallet_db.GetWallet();
  std::vector<SingleSigner> signers;

  for (auto&& signer : wallet.get_signers()) {
    single_wallet_[NunchukWalletDb::GetSingleSignerKey(signer)] = id;
    std::string name = signer.get_name();
    std::string master_id = signer.get_master_fingerprint();
    time_t last_health_check = signer.get_last_health_check();
    try {
      auto signer_db = GetSignerDb(chain, master_id);
      name = signer_db.GetName();
      last_health_check = signer_db.GetLastHealthCheck();
    } catch (StorageException& se) {
      if (se.code() == StorageException::MASTERSIGNER_NOT_FOUND) {
        master_id = "";
      } else {
        throw;
      }
    }
    SingleSigner true_signer(name, signer.get_xpub(), signer.get_public_key(),
                             signer.get_derivation_path(),
                             signer.get_master_fingerprint(), last_health_check,
                             master_id);
    signers.push_back(true_signer);
  }
  Wallet true_wallet(id, wallet.get_m(), wallet.get_n(), signers,
                     wallet.get_address_type(), wallet.is_escrow(),
                     wallet.get_create_date());
  true_wallet.set_name(wallet.get_name());
  true_wallet.set_balance(wallet.get_balance());
  return true_wallet;
}

MasterSigner NunchukStorage::GetMasterSigner(Chain chain,
                                             const std::string& id) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto signer_db = GetSignerDb(chain, id);
  MasterSigner signer{id, Device(signer_db.GetFingerprint()),
                      signer_db.GetLastHealthCheck()};
  signer.set_name(signer_db.GetName());
  return signer;
}

bool NunchukStorage::UpdateWallet(Chain chain, Wallet& wallet) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  auto wallet_db = GetWalletDb(chain, wallet.get_id());
  return wallet_db.SetName(wallet.get_name()) &&
         wallet_db.SetDescription(wallet.get_description());
}

bool NunchukStorage::UpdateMasterSigner(Chain chain, MasterSigner& signer) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetSignerDb(chain, signer.get_id()).SetName(signer.get_name());
}

bool NunchukStorage::DeleteWallet(Chain chain, const std::string& id) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  GetWalletDb(chain, id).DeleteWallet();
  return fs::remove(GetWalletDir(chain, id));
}

bool NunchukStorage::DeleteMasterSigner(Chain chain, const std::string& id) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  GetSignerDb(chain, id).DeleteSigner();
  return fs::remove(GetSignerDir(chain, id));
}

bool NunchukStorage::SetHealthCheckSuccess(Chain chain,
                                           const std::string& mastersigner_id) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id).SetLastHealthCheck(std::time(0));
}

bool NunchukStorage::SetHealthCheckSuccess(Chain chain,
                                           const SingleSigner& signer) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  std::string signer_key = NunchukWalletDb::GetSingleSignerKey(signer);
  if (single_wallet_.find(signer_key) == single_wallet_.end()) return false;
  std::string wallet_id = single_wallet_[signer_key];
  return GetWalletDb(chain, wallet_id)
      .SetSignerLastHealthCheck(signer, std::time(0));
}

std::string NunchukStorage::GetDescriptor(Chain chain,
                                          const std::string& wallet_id,
                                          bool internal) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetDescriptor(internal);
}

bool NunchukStorage::AddAddress(Chain chain, const std::string& wallet_id,
                                const std::string& address, int index,
                                bool internal) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).AddAddress(address, index, internal);
}

bool NunchukStorage::UseAddress(Chain chain, const std::string& wallet_id,
                                const std::string& address) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).UseAddress(address);
}

std::vector<std::string> NunchukStorage::GetAddresses(
    Chain chain, const std::string& wallet_id, bool used, bool internal) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetAddresses(used, internal);
}

std::vector<std::string> NunchukStorage::GetAllAddresses(
    Chain chain, const std::string& wallet_id) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetAllAddresses();
}

int NunchukStorage::GetCurrentAddressIndex(Chain chain,
                                           const std::string& wallet_id,
                                           bool internal) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetCurrentAddressIndex(internal);
}

Transaction NunchukStorage::InsertTransaction(
    Chain chain, const std::string& wallet_id, const std::string& raw_tx,
    int height, time_t blocktime, Amount fee, const std::string& memo,
    int change_pos) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id)
      .InsertTransaction(raw_tx, height, blocktime, fee, memo, change_pos);
}

std::vector<Transaction> NunchukStorage::GetTransactions(
    Chain chain, const std::string& wallet_id, int count, int skip) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = GetWalletDb(chain, wallet_id);
  auto vtx = db.GetTransactions(count, skip);
  for (auto&& tx : vtx) {
    db.FillSendReceiveData(tx);
  }
  return vtx;
}

std::vector<UnspentOutput> NunchukStorage::GetUnspentOutputs(
    Chain chain, const std::string& wallet_id, bool remove_locked) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetUnspentOutputs(remove_locked);
}

Transaction NunchukStorage::GetTransaction(Chain chain,
                                           const std::string& wallet_id,
                                           const std::string& tx_id) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = GetWalletDb(chain, wallet_id);
  auto tx = db.GetTransaction(tx_id);
  db.FillSendReceiveData(tx);
  return tx;
}

bool NunchukStorage::UpdateTransaction(Chain chain,
                                       const std::string& wallet_id,
                                       const std::string& raw_tx, int height,
                                       time_t blocktime,
                                       const std::string& reject_msg) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id)
      .UpdateTransaction(raw_tx, height, blocktime, reject_msg);
}

bool NunchukStorage::UpdateTransactionMemo(Chain chain,
                                           const std::string& wallet_id,
                                           const std::string& tx_id,
                                           const std::string& memo) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).UpdateTransactionMemo(tx_id, memo);
}

bool NunchukStorage::DeleteTransaction(Chain chain,
                                       const std::string& wallet_id,
                                       const std::string& tx_id) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).DeleteTransaction(tx_id);
}

Transaction NunchukStorage::CreatePsbt(
    Chain chain, const std::string& wallet_id, const std::string& psbt,
    Amount fee, const std::string& memo, int change_pos,
    const std::map<std::string, Amount>& outputs, Amount fee_rate,
    bool subtract_fee_from_amount, const std::string& replace_tx) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id)
      .CreatePsbt(psbt, fee, memo, change_pos, outputs, fee_rate,
                  subtract_fee_from_amount, replace_tx);
}

bool NunchukStorage::UpdatePsbt(Chain chain, const std::string& wallet_id,
                                const std::string& psbt) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).UpdatePsbt(psbt);
}

bool NunchukStorage::UpdatePsbtTxId(Chain chain, const std::string& wallet_id,
                                    const std::string& old_id,
                                    const std::string& new_id) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).UpdatePsbtTxId(old_id, new_id);
}

std::string NunchukStorage::GetPsbt(Chain chain, const std::string& wallet_id,
                                    const std::string& tx_id) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetPsbt(tx_id);
}

bool NunchukStorage::SetUtxos(Chain chain, const std::string& wallet_id,
                              const std::string& address,
                              const std::string& utxo) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).SetUtxos(address, utxo);
}

Amount NunchukStorage::GetBalance(Chain chain, const std::string& wallet_id) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetBalance();
}
std::string NunchukStorage::FillPsbt(Chain chain, const std::string& wallet_id,
                                     const std::string& psbt) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).FillPsbt(psbt);
}

// non-reentrant function
void NunchukStorage::MaybeMigrate(Chain chain) {
  static std::once_flag flag;
  std::call_once(flag, [&] {
    auto wallets = ListWallets(chain);
    boost::unique_lock<boost::shared_mutex> lock(access_);
    for (auto&& wallet_id : wallets) {
      GetWalletDb(chain, wallet_id).MaybeMigrate();
    }
  });
}

int NunchukStorage::GetChainTip(Chain chain) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  return GetAppStateDb(chain).GetChainTip();
}

bool NunchukStorage::SetChainTip(Chain chain, int value) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetAppStateDb(chain).SetChainTip(value);
}

std::string NunchukStorage::GetSelectedWallet(Chain chain) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  return GetAppStateDb(chain).GetSelectedWallet();
}

bool NunchukStorage::SetSelectedWallet(Chain chain, const std::string& value) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  return GetAppStateDb(chain).SetSelectedWallet(value);
}

}  // namespace nunchuk