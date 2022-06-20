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

#include "walletdb.h"

#include <descriptor.h>
#include <utils/bip32.hpp>
#include <utils/txutils.hpp>
#include <utils/json.hpp>
#include <utils/loguru.hpp>
#include <utils/bsms.hpp>
#include <utils/stringutils.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <sstream>

#include <univalue.h>
#include <rpc/util.h>
#include <policy/policy.h>
#include <signingprovider.h>

using json = nlohmann::json;
namespace ba = boost::algorithm;

namespace nunchuk {

static const int ADDRESS_LOOK_AHEAD = 20;

std::map<std::string, std::map<std::string, AddressData>>
    NunchukWalletDb::addr_cache_;
std::map<std::string, std::vector<SingleSigner>> NunchukWalletDb::signer_cache_;

void NunchukWalletDb::InitWallet(const Wallet& wallet) {
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
  PutString(DbKeys::NAME, wallet.get_name());
  PutString(DbKeys::DESCRIPTION, wallet.get_description());

  json immutable_data = {{"m", wallet.get_m()},
                         {"n", wallet.get_n()},
                         {"address_type", wallet.get_address_type()},
                         {"is_escrow", wallet.is_escrow()},
                         {"create_date", wallet.get_create_date()}};
  PutString(DbKeys::IMMUTABLE_DATA, immutable_data.dump());
  for (auto&& signer : wallet.get_signers()) {
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

Wallet NunchukWalletDb::GetWallet(bool skip_balance, bool skip_provider) const {
  json immutable_data = json::parse(GetString(DbKeys::IMMUTABLE_DATA));
  int m = immutable_data["m"];
  int n = immutable_data["n"];
  AddressType address_type = immutable_data["address_type"];
  bool is_escrow = immutable_data["is_escrow"];
  time_t create_date = immutable_data["create_date"];

  Wallet wallet(id_, m, n, GetSigners(), address_type, is_escrow, create_date);
  wallet.set_name(GetString(DbKeys::NAME));
  if (!skip_balance) wallet.set_balance(GetBalance());
  if (!skip_provider) {
    GetAllAddressData();  // update range to max address index
    auto desc = GetDescriptorsImportString(wallet);
    SigningProviderCache::getInstance().PreCalculate(desc);
  }
  return wallet;
}

std::vector<SingleSigner> NunchukWalletDb::GetSigners() const {
  if (signer_cache_.count(db_file_name_)) {
    return signer_cache_[db_file_name_];
  }
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
  signer_cache_[db_file_name_] = signers;
  return signers;
}

void NunchukWalletDb::SetAddress(const std::string& address, int index,
                                 bool internal, const std::string& utxos) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO ADDRESS(ADDR, IDX, INTERNAL, USED, UTXO)"
      "VALUES (?1, ?2, ?3, ?4, ?5)"
      "ON CONFLICT(ADDR) DO UPDATE SET USED=excluded.USED, UTXO=excluded.UTXO;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, address.c_str(), address.size(), NULL);
  sqlite3_bind_int(stmt, 2, index);
  sqlite3_bind_int(stmt, 3, internal ? 1 : 0);
  sqlite3_bind_int(stmt, 4, utxos.empty() ? 0 : 1);
  sqlite3_bind_text(stmt, 5, utxos.c_str(), utxos.size(), NULL);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
}

bool NunchukWalletDb::AddAddress(const std::string& address, int index,
                                 bool internal) {
  SetAddress(address, index, internal);
  if (!IsMyAddress(address)) {
    addr_cache_[db_file_name_][address] = {address, index, internal, false};
    SigningProviderCache::getInstance().SetMaxIndex(id_, index);
  }
  return true;
}

void NunchukWalletDb::UseAddress(const std::string& address) const {
  if (address.empty()) return;
  if (!addr_cache_.count(db_file_name_)) return;
  if (!addr_cache_[db_file_name_].count(address)) return;
  addr_cache_[db_file_name_][address].used = true;
}

bool NunchukWalletDb::IsMyAddress(const std::string& address) const {
  return GetAllAddressData().count(address);
}

bool NunchukWalletDb::IsMyChange(const std::string& address) const {
  auto all = GetAllAddressData();
  return all.count(address) && all.at(address).internal;
}

std::map<std::string, AddressData> NunchukWalletDb::GetAllAddressData() const {
  if (addr_cache_.count(db_file_name_)) {
    return addr_cache_[db_file_name_];
  }
  std::map<std::string, AddressData> addresses;
  auto wallet = GetWallet(true, true);
  if (wallet.is_escrow()) {
    auto addr = CoreUtils::getInstance().DeriveAddress(
        wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL));
    addresses[addr] = {addr, 0, false, false};
  } else {
    int index = 0;
    auto internal_addr = CoreUtils::getInstance().DeriveAddresses(
        wallet.get_descriptor(DescriptorPath::INTERNAL_ALL), index,
        GetCurrentAddressIndex(true) + ADDRESS_LOOK_AHEAD);
    for (auto&& addr : internal_addr) {
      addresses[addr] = {addr, index++, true, false};
    }
    SigningProviderCache::getInstance().SetMaxIndex(id_, index);
    index = 0;
    auto external_addr = CoreUtils::getInstance().DeriveAddresses(
        wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL), index,
        GetCurrentAddressIndex(false) + ADDRESS_LOOK_AHEAD);
    for (auto&& addr : external_addr) {
      addresses[addr] = {addr, index++, false, false};
    }
    SigningProviderCache::getInstance().SetMaxIndex(id_, index);
  }
  addr_cache_[db_file_name_] = addresses;
  auto txs = GetTransactions();
  for (auto&& tx : txs) {
    for (auto&& output : tx.get_outputs()) UseAddress(output.first);
  }
  return addresses;
}

std::vector<std::string> NunchukWalletDb::GetAddresses(bool used,
                                                       bool internal) const {
  auto all = GetAllAddressData();
  auto cur = GetCurrentAddressIndex(internal);
  std::vector<std::string> rs;
  for (auto&& item : all) {
    auto data = item.second;
    if (data.used == used && data.internal == internal && data.index <= cur)
      rs.push_back(data.address);
  }
  return rs;
}

int NunchukWalletDb::GetAddressIndex(const std::string& address) const {
  auto all = GetAllAddressData();
  if (all.count(address)) return all.at(address).index;
  return -1;
}

Amount NunchukWalletDb::GetAddressBalance(const std::string& address) const {
  auto utxos = GetUtxos(false, true);
  Amount balance = 0;
  for (auto&& utxo : utxos) {
    // Only include confirmed Receive amount
    if (utxo.get_height() > 0 && utxo.get_address() == address)
      balance += utxo.get_amount();
  }
  return balance;
}

std::string NunchukWalletDb::GetAddressStatus(
    const std::string& address) const {
  sqlite3_stmt* stmt;
  std::string sql =
      "SELECT UTXO FROM ADDRESS WHERE ADDR = ? AND UTXO IS NOT NULL;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, address.c_str(), address.size(), NULL);
  std::string status = "";
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    auto utxo = split(std::string((char*)sqlite3_column_text(stmt, 0)), '|');
    if (utxo.size() > 1) status = utxo[1];
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return status;
}

std::vector<std::string> NunchukWalletDb::GetAllAddresses() const {
  auto all = GetAllAddressData();
  std::vector<std::string> rs;
  for (auto&& data : all) {
    rs.push_back(data.second.address);
  }
  return rs;
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
      "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '')"
      "ON CONFLICT(ID) DO UPDATE SET VALUE=excluded.VALUE, "
      "HEIGHT=excluded.HEIGHT;";
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
  return GetTransaction(tx_id);
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
      Transaction tx = GetTransactionFromPartiallySignedTransaction(
          DecodePsbt(value), GetSigners(), 0);

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
  if (updated) GetTransaction(tx_id);
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
  std::string tx_id = psbtx.tx.value().GetHash().GetHex();

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
      "VALUES (?1, ?2, -1, ?3, ?4, ?5, ?6, ?7)"
      "ON CONFLICT(ID) DO UPDATE SET VALUE=excluded.VALUE, "
      "HEIGHT=excluded.HEIGHT;";
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
  std::string tx_id = psbtx.tx.value().GetHash().GetHex();
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, psbt.c_str(), psbt.size(), NULL);
  sqlite3_bind_text(stmt, 2, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated) GetTransaction(tx_id);
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
    int fee = sqlite3_column_int(stmt, 3);
    std::string memo = std::string((char*)sqlite3_column_text(stmt, 4));
    int change_pos = sqlite3_column_int(stmt, 5);
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
    throw StorageException(StorageException::TX_NOT_FOUND, "Old tx not found!");
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

    auto signers = GetSigners();
    auto tx = height == -1 ? GetTransactionFromPartiallySignedTransaction(
                                 DecodePsbt(value), signers, m)
                           : GetTransactionFromCMutableTransaction(
                                 DecodeRawTransaction(value), signers, height);
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
    if (height == -1) {
      tx.set_psbt(value);
    } else {
      tx.set_raw(value);
    }

    if (sqlite3_column_text(stmt, 7)) {
      std::string extra = std::string((char*)sqlite3_column_text(stmt, 7));
      FillExtra(extra, tx);
    }
    SQLCHECK(sqlite3_finalize(stmt));
    for (auto&& output : tx.get_outputs()) UseAddress(output.first);
    return tx;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
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

bool NunchukWalletDb::SetUtxos(const std::string& address,
                               const std::string& utxo) {
  auto all = GetAllAddressData();
  if (!all.count(address)) return false;
  SetAddress(address, all[address].index, all[address].internal, utxo);
  return true;
}

Amount NunchukWalletDb::GetBalance() const {
  auto utxos = GetUtxos(false, true);
  Amount balance = 0;
  for (auto&& utxo : utxos) {
    // Only include confirmed Receive amount and in-mempool Change amount
    // in the wallet balance
    if (utxo.get_height() > 0 || IsMyChange(utxo.get_address()))
      balance += utxo.get_amount();
  }
  return balance;
}

std::vector<UnspentOutput> NunchukWalletDb::GetUtxos(
    bool include_locked, bool include_mempool) const {
  std::vector<Transaction> transactions = GetTransactions();
  auto input_str = [](std::string tx_id, int vout) {
    return boost::str(boost::format{"%s:%d"} % tx_id % vout);
  };
  std::set<std::string> locked_utxos;
  std::map<std::string, std::string> memo_map;
  std::map<std::string, int> height_map;

  std::vector<UnspentOutput> rs;
  for (auto&& tx : transactions) {
    memo_map[tx.get_txid()] = tx.get_memo();
    height_map[tx.get_txid()] = tx.get_height();
    if (tx.get_height() != 0) continue;

    if (include_mempool) {
      // CoreRPC uses polling requests to get new UTXO so it has some delay to
      // update the balance. To fix #19 bug, we have to add change UTXO manually
      int nout = tx.get_outputs().size();
      for (int vout = 0; vout < nout; vout++) {
        auto output = tx.get_outputs()[vout];
        if (!IsMyChange(output.first)) continue;
        // add it to locked_utxos to prevent duplicate UTXO
        locked_utxos.insert(input_str(tx.get_txid(), vout));

        UnspentOutput utxo;
        utxo.set_txid(tx.get_txid());
        utxo.set_vout(vout);
        utxo.set_address(output.first);
        utxo.set_amount(output.second);
        utxo.set_height(tx.get_height());
        utxo.set_memo(tx.get_memo());
        rs.push_back(utxo);
      }
    }

    if (!include_locked) {
      // remove UTXOs of unconfirmed transactions
      for (auto&& input : tx.get_inputs()) {
        locked_utxos.insert(input_str(input.first, input.second));
      }
    }
  }

  sqlite3_stmt* stmt;
  std::string sql = "SELECT ADDR, UTXO FROM ADDRESS WHERE UTXO IS NOT NULL;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  while (sqlite3_column_text(stmt, 0)) {
    std::string address = std::string((char*)sqlite3_column_text(stmt, 0));
    auto utxostatus_str = std::string((char*)sqlite3_column_text(stmt, 1));
    auto utxostatus = split(utxostatus_str, '|');
    if (utxostatus.empty() || utxostatus[0].empty()) {
      sqlite3_step(stmt);
      continue;
    }
    auto utxo_str = utxostatus[0];
    json utxo_json = json::parse(utxo_str);
    for (auto it = utxo_json.begin(); it != utxo_json.end(); ++it) {
      json item = it.value();
      std::string txid;
      int vout;
      Amount amount;
      if (item["tx_hash"] != nullptr) {  // electrum format
        txid = item["tx_hash"];
        vout = item["tx_pos"];
        amount = Amount(item["value"]);
        if (!include_mempool && item["height"].get<int>() == 0) continue;
      } else {  // bitcoin core rpc format
        txid = item["txid"];
        vout = item["vout"];
        amount = Utils::AmountFromValue(item["amount"].dump());
      }

      if (locked_utxos.find(input_str(txid, vout)) != locked_utxos.end()) {
        continue;
      }
      UnspentOutput utxo;
      utxo.set_txid(txid);
      utxo.set_vout(vout);
      utxo.set_address(address);
      utxo.set_amount(amount);
      utxo.set_height(height_map[txid]);
      utxo.set_memo(memo_map[txid]);
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

    auto signers = GetSigners();
    auto tx = height == -1 ? GetTransactionFromPartiallySignedTransaction(
                                 DecodePsbt(value), signers, m)
                           : GetTransactionFromCMutableTransaction(
                                 DecodeRawTransaction(value), signers, height);
    tx.set_txid(tx_id);
    tx.set_m(m);
    tx.set_fee(Amount(fee));
    tx.set_memo(memo);
    tx.set_change_index(change_pos);
    tx.set_blocktime(blocktime);
    tx.set_receive(false);
    tx.set_sub_amount(0);
    if (height == -1) {
      tx.set_psbt(value);
    } else {
      tx.set_raw(value);
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

  auto desc = GetDescriptorsImportString(GetWallet(true));
  auto provider = SigningProviderCache::getInstance().GetProvider(desc);

  int nin = psbt.tx.value().vin.size();
  for (int i = 0; i < nin; i++) {
    std::string tx_id = psbt.tx.value().vin[i].prevout.hash.GetHex();
    sqlite3_stmt* stmt;
    std::string sql = "SELECT VALUE FROM VTX WHERE ID = ? AND HEIGHT > -1;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
    sqlite3_step(stmt);
    if (sqlite3_column_text(stmt, 0)) {
      std::string raw_tx = std::string((char*)sqlite3_column_text(stmt, 0));
      psbt.inputs[i].non_witness_utxo =
          MakeTransactionRef(DecodeRawTransaction(raw_tx));
      psbt.inputs[i].witness_utxo.SetNull();
    }
    SQLCHECK(sqlite3_finalize(stmt));
  }

  const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);
  for (int i = 0; i < nin; i++) {
    SignPSBTInput(provider, psbt, i, &txdata, 1);
  }

  // Update script/keypath information using descriptor data.
  for (unsigned int i = 0; i < psbt.tx.value().vout.size(); ++i) {
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
    } else if (tx.get_status() == TransactionStatus::NETWORK_REJECTED &&
               extra_json["reject_msg"] != nullptr) {
      tx.set_reject_msg(extra_json["reject_msg"]);
    }
  }
}

// TODO (bakaoh): consider persisting these data
void NunchukWalletDb::FillSendReceiveData(Transaction& tx) {
  Amount total_amount = 0;
  bool is_send_tx = false;
  for (auto&& input : tx.get_inputs()) {
    TxOutput prev_out;
    try {
      prev_out = GetTransaction(input.first).get_outputs()[input.second];
    } catch (StorageException& se) {
      if (se.code() != StorageException::TX_NOT_FOUND) throw;
    }
    if (IsMyAddress(prev_out.first)) {
      total_amount += prev_out.second;
      is_send_tx = true;
    }
  }
  if (is_send_tx) {
    Amount send_amount{0};
    for (size_t i = 0; i < tx.get_outputs().size(); i++) {
      auto output = tx.get_outputs()[i];
      total_amount -= output.second;
      if (!IsMyAddress(output.first)) {
        send_amount += output.second;
      } else if (tx.get_change_index() < 0) {
        tx.set_change_index(i);
      }
    }
    tx.set_fee(total_amount);
    tx.set_receive(false);
    tx.set_sub_amount(send_amount);
  } else {
    Amount receive_amount{0};
    for (auto&& output : tx.get_outputs()) {
      if (IsMyAddress(output.first)) {
        receive_amount += output.second;
        tx.add_receive_output(output);
      }
    }
    tx.set_receive(true);
    tx.set_sub_amount(receive_amount);
  }
}

}  // namespace nunchuk
