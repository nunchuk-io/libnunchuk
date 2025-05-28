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
#include "storage/common.h"

#include <univalue.h>
#include <rpc/util.h>
#include <policy/policy.h>
#include <signingprovider.h>

#include <base58.h>
#include <util/strencodings.h>
#include <util/bip32.h>

using json = nlohmann::json;
namespace ba = boost::algorithm;

namespace nunchuk {

static const int DEFAULT_ADDRESS_LOOK_AHEAD = 20;
static const int ALL_NEW_COINS = -2;

std::map<std::string, std::map<std::string, AddressData>>
    NunchukWalletDb::addr_cache_;
std::map<std::string, std::vector<SingleSigner>> NunchukWalletDb::signer_cache_;
std::map<std::string, std::map<int, bool>>
    NunchukWalletDb::collection_auto_lock_;
std::map<std::string, std::map<std::pair<int, int>, bool>>
    NunchukWalletDb::collection_auto_add_;
std::map<std::string, std::map<std::string, Transaction>>
    NunchukWalletDb::txs_cache_;

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
  PutString(DbKeys::MINISCRIPT, wallet.get_miniscript());

  json immutable_data = {{"m", wallet.get_m()},
                         {"n", wallet.get_n()},
                         {"address_type", wallet.get_address_type()},
                         {"wallet_type", wallet.get_wallet_type()},
                         {"wallet_template", wallet.get_wallet_template()},
                         {"create_date", wallet.get_create_date()}};
  PutString(DbKeys::IMMUTABLE_DATA, immutable_data.dump());
  for (auto&& signer : wallet.get_signers()) {
    AddSigner(signer);
  }
  CreateCoinControlTable();
  CreateDummyTxTable();
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
  if (current_ver < 4) {
    CreateCoinControlTable();
  }
  if (current_ver < 5) {
    CreateDummyTxTable();
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
  txs_cache_.erase(db_file_name_);
  DropTable();
}

bool NunchukWalletDb::SetName(const std::string& value) {
  return PutString(DbKeys::NAME, value);
}

bool NunchukWalletDb::SetDescription(const std::string& value) {
  return PutString(DbKeys::DESCRIPTION, value);
}

bool NunchukWalletDb::SetLastUsed(time_t value) {
  return PutInt(DbKeys::LAST_USED, value);
}

bool NunchukWalletDb::SetGapLimit(int value) {
  return PutInt(DbKeys::GAP_LIMIT, value);
}

bool NunchukWalletDb::SetNeedBackup(bool value) {
  return PutInt(DbKeys::NEED_BACKUP, value ? 1 : 0);
}

bool NunchukWalletDb::SetArchived(bool value) {
  return PutInt(DbKeys::ARCHIVED, value ? 1 : 0);
}

Wallet NunchukWalletDb::GetWallet(bool skip_balance, bool skip_provider) {
  auto data = GetString(DbKeys::IMMUTABLE_DATA);
  if (data.empty())
    throw StorageException(StorageException::WALLET_NOT_FOUND,
                           strprintf("Wallet doesn't exist! id = '%s'", id_));
  json immutable_data = json::parse(data);
  int m = immutable_data["m"];
  int n = immutable_data["n"];
  AddressType address_type = immutable_data["address_type"];
  time_t create_date = immutable_data["create_date"];
  int gap_limit = GetInt(DbKeys::GAP_LIMIT);

  WalletType wallet_type = WalletType::MULTI_SIG;
  if (immutable_data["wallet_type"] != nullptr) {
    wallet_type = immutable_data["wallet_type"];
  } else {  // backward compatible
    bool is_escrow = immutable_data["is_escrow"];
    wallet_type =
        is_escrow ? WalletType::ESCROW
                  : (n == 1 ? WalletType::SINGLE_SIG : WalletType::MULTI_SIG);
  }
  WalletTemplate wallet_template = WalletTemplate::DEFAULT;
  if (immutable_data["wallet_template"] != nullptr) {
    wallet_template = immutable_data["wallet_template"];
  }

  Wallet wallet;
  if (wallet_type == WalletType::MINISCRIPT) {
    wallet = Wallet(GetString(DbKeys::MINISCRIPT), GetSigners(), address_type);
    wallet.set_name(GetString(DbKeys::NAME));
    wallet.set_create_date(create_date);
  } else {
    wallet = Wallet(id_, GetString(DbKeys::NAME), m, n, GetSigners(),
                    address_type, wallet_type, create_date);
  }
  wallet.set_description(GetString(DbKeys::DESCRIPTION));
  wallet.set_last_used(GetInt(DbKeys::LAST_USED));
  wallet.set_gap_limit(gap_limit <= 0 ? DEFAULT_ADDRESS_LOOK_AHEAD : gap_limit);
  wallet.set_need_backup(GetInt(DbKeys::NEED_BACKUP) == 1);
  wallet.set_archived(GetInt(DbKeys::ARCHIVED) == 1);
  wallet.set_wallet_template(wallet_template);
  if (!skip_provider) {
    GetAllAddressData(false);  // update range to max address index
    auto desc = GetDescriptorsImportString(wallet);
    SigningProviderCache::getInstance().PreCalculate(desc);
    // workaround for GetTransactionFromPartiallySignedTransaction bug
    auto txs = GetTransactions();
    for (auto&& tx : txs) {
      for (auto&& output : tx.get_outputs()) UseAddress(output.first);
    }
    try {
      sqlite3_stmt* stmt;
      std::string sql = "SELECT ADDR FROM ADDRESS WHERE USED = 1;";
      sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
      sqlite3_step(stmt);
      while (sqlite3_column_text(stmt, 0)) {
        std::string addr = std::string((char*)sqlite3_column_text(stmt, 0));
        UseAddress(addr);
        sqlite3_step(stmt);
      }
      SQLCHECK(sqlite3_finalize(stmt));
    } catch (...) {
    }
  }
  if (!skip_balance) {
    wallet.set_balance(GetBalance(false));
    wallet.set_unconfirmed_balance(GetBalance(true));
  }
  if (!txs_cache_.count(db_file_name_)) txs_cache_[db_file_name_] = {};
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
                        master_fingerprint, last_health_check, master_id, false,
                        SignerType::UNKNOWN);
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
  auto all = GetAllAddressData();
  if (all.count(address) && all[address].used) return true;
  SetAddress(address, index, internal);
  if (!all.count(address)) {
    addr_cache_[db_file_name_][address] = {address, index, internal, false};
    SigningProviderCache::getInstance().SetMaxIndex(id_, index);
  }
  return true;
}

void NunchukWalletDb::UseAddress(const std::string& address) {
  if (address.empty()) return;
  if (!addr_cache_.count(db_file_name_)) return;
  if (!addr_cache_[db_file_name_].count(address)) return;
  addr_cache_[db_file_name_][address].used = true;
}

bool NunchukWalletDb::IsMyAddress(const std::string& address) {
  return GetAllAddressData().count(address);
}

std::string NunchukWalletDb::GetAddressPath(const std::string& address) {
  if (!IsMyAddress(address)) {
    throw StorageException(StorageException::ADDRESS_NOT_FOUND,
                           "Address not found!");
  }
  bool internal = GetAllAddressData()[address].internal;
  int index = GetAllAddressData()[address].index;

  auto signers = GetSigners();
  std::vector<std::string> paths{};
  for (auto&& signer : signers) {
    std::stringstream path;
    path << "m" << FormalizePath(signer.get_derivation_path())
         << (internal ? "/1/" : "/0/") << index;
    paths.push_back(path.str());
  }
  if (paths.size() == 1) return paths[0];

  std::string suffix{};
  for (int i = 1; i <= paths[0].size(); i++) {
    std::string tem = paths[0].substr(paths[0].size() - i, i);
    int j = 1;
    for (j = 1; j < paths.size(); j++) {
      if (!ba::ends_with(paths[j], tem)) break;
    }
    if (j == paths.size()) suffix = tem;
  }
  if (suffix[0] == 'm') return suffix;

  std::string prefix{};
  for (int i = 1; i <= paths[0].size(); i++) {
    std::string tem = paths[0].substr(0, i);
    int j = 1;
    for (j = 1; j < paths.size(); j++) {
      if (!ba::starts_with(paths[j], tem)) break;
    }
    if (j == paths.size()) prefix = tem;
  }

  std::stringstream path;
  path << prefix << "..." << suffix;
  return path.str();
}

bool NunchukWalletDb::IsMyChange(const std::string& address) {
  auto all = GetAllAddressData();
  return all.count(address) && all.at(address).internal;
}

std::map<std::string, AddressData> NunchukWalletDb::GetAllAddressData(
    bool check_used) {
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
        GetCurrentAddressIndex(true) + wallet.get_gap_limit());
    for (auto&& addr : internal_addr) {
      addresses[addr] = {addr, index++, true, false};
    }
    SigningProviderCache::getInstance().SetMaxIndex(id_, index);
    index = 0;
    auto external_addr = CoreUtils::getInstance().DeriveAddresses(
        wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL), index,
        GetCurrentAddressIndex(false) + wallet.get_gap_limit());
    for (auto&& addr : external_addr) {
      addresses[addr] = {addr, index++, false, false};
    }
    SigningProviderCache::getInstance().SetMaxIndex(id_, index);
  }
  addr_cache_.insert({db_file_name_, std::move(addresses)});
  if (check_used) {
    auto txs = GetTransactions();
    for (auto&& tx : txs) {
      for (auto&& output : tx.get_outputs()) UseAddress(output.first);
    }
    try {
      sqlite3_stmt* stmt;
      std::string sql = "SELECT ADDR FROM ADDRESS WHERE USED = 1;";
      sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
      sqlite3_step(stmt);
      while (sqlite3_column_text(stmt, 0)) {
        std::string addr = std::string((char*)sqlite3_column_text(stmt, 0));
        UseAddress(addr);
        sqlite3_step(stmt);
      }
      SQLCHECK(sqlite3_finalize(stmt));
    } catch (...) {
    }
  }
  return addr_cache_[db_file_name_];
}

std::map<int, bool> NunchukWalletDb::GetAutoLockData() const {
  if (collection_auto_lock_.count(db_file_name_)) {
    return collection_auto_lock_[db_file_name_];
  }
  std::map<int, bool> data;
  auto collections = GetCoinCollections();
  for (auto&& c : collections) {
    data[c.get_id()] = c.is_auto_lock();
  }
  collection_auto_lock_.insert({db_file_name_, data});
  return data;
}

std::map<std::pair<int, int>, bool> NunchukWalletDb::GetAutoAddData() const {
  if (collection_auto_add_.count(db_file_name_)) {
    return collection_auto_add_[db_file_name_];
  }
  std::map<std::pair<int, int>, bool> data;
  auto collections = GetCoinCollections();
  for (auto&& c : collections) {
    data[{c.get_id(), ALL_NEW_COINS}] = c.is_add_new_coin();
    for (auto&& t : c.get_add_coins_with_tag()) {
      data[{c.get_id(), t}] = true;
    }
  }
  collection_auto_add_.insert({db_file_name_, data});
  return data;
}

bool compareAddressData(AddressData a, AddressData b) {
  return a.index < b.index;
}

std::vector<std::string> NunchukWalletDb::GetAddresses(bool used,
                                                       bool internal) {
  auto all = GetAllAddressData();
  auto cur = GetCurrentAddressIndex(internal);
  std::vector<AddressData> ad;
  for (auto&& item : all) {
    auto data = item.second;
    if (data.used == used && data.internal == internal && data.index <= cur)
      ad.push_back(data);
  }
  std::sort(ad.begin(), ad.end(), compareAddressData);
  std::vector<std::string> rs;
  for (auto&& a : ad) {
    rs.push_back(a.address);
  }
  return rs;
}

int NunchukWalletDb::GetAddressIndex(const std::string& address) {
  auto all = GetAllAddressData();
  if (all.count(address)) return all.at(address).index;
  return -1;
}

Amount NunchukWalletDb::GetAddressBalance(const std::string& address) {
  auto coins = GetCoins();
  Amount balance = 0;
  for (auto&& coin : coins) {
    if (coin.get_status() == CoinStatus::SPENT ||
        coin.get_status() == CoinStatus::OUTGOING_PENDING_CONFIRMATION ||
        coin.get_status() == CoinStatus::INCOMING_PENDING_CONFIRMATION)
      continue;
    if (coin.get_address() != address) continue;
    balance += coin.get_amount();
  }
  return balance;
}

bool NunchukWalletDb::MarkAddressAsUsed(const std::string& address) {
  auto all = GetAllAddressData();
  if (!all.count(address)) return false;
  if (all[address].used) return true;
  SetAddress(address, all[address].index, all[address].internal,
             "null|manually");
  addr_cache_[db_file_name_][address].used = true;
  return true;
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

std::vector<std::string> NunchukWalletDb::GetAllAddresses() {
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
  if (!memo.empty()) UpdateTransactionMemo(tx_id, memo);
  txs_cache_[db_file_name_].erase(tx_id);
  auto tx = GetTransaction(tx_id);
  AutoAddNewCoins(tx);
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
    json extra_json = extra.empty() ? json{} : json::parse(extra);
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
  txs_cache_[db_file_name_].erase(old_txid);
}

bool NunchukWalletDb::UpdateTransaction(const std::string& raw_tx, int height,
                                        time_t blocktime,
                                        const std::string& reject_msg) {
  auto wallet = GetWallet(true, true);
  if (height == -1) {
    auto [tx, is_hex_tx] = GetTransactionFromStr(raw_tx, wallet, -1);
    std::string tx_id = tx.get_txid();

    sqlite3_stmt* stmt;
    std::string sql = "SELECT EXTRA FROM VTX WHERE ID = ? AND HEIGHT = -1;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
    sqlite3_step(stmt);

    std::string extra;
    if (sqlite3_column_text(stmt, 0)) {
      extra = std::string((char*)sqlite3_column_text(stmt, 0));
      json extra_json = extra.empty() ? json{} : json::parse(extra);
      extra_json["signers"] = tx.get_signers();
      extra = extra_json.dump();

      SQLCHECK(sqlite3_finalize(stmt));
    } else {
      SQLCHECK(sqlite3_finalize(stmt));
      throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
    }

    sql = extra.empty()
              ? "UPDATE VTX SET VALUE = ?1 WHERE ID = ?2;"
              : "UPDATE VTX SET VALUE = ?1, EXTRA = ?3 WHERE ID = ?2;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, raw_tx.c_str(), raw_tx.size(), NULL);
    sqlite3_bind_text(stmt, 2, tx_id.c_str(), tx_id.size(), NULL);
    if (!extra.empty()) {
      sqlite3_bind_text(stmt, 3, extra.c_str(), extra.size(), NULL);
    }

    sqlite3_step(stmt);
    bool updated = (sqlite3_changes(db_) == 1);
    SQLCHECK(sqlite3_finalize(stmt));
    txs_cache_[db_file_name_].erase(tx_id);
    if (updated) GetTransaction(tx_id);
    return updated;
  }

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
      auto [tx, is_hex_tx] = GetTransactionFromStr(value, wallet, -1);

      json extra_json = extra.empty() ? json{} : json::parse(extra);
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
  txs_cache_[db_file_name_].erase(tx_id);
  if (updated) GetTransaction(tx_id);
  return updated;
}

bool NunchukWalletDb::UpdateTransactionSchedule(const std::string& tx_id,
                                                time_t value) {
  sqlite3_stmt* select_stmt;
  std::string select_sql = "SELECT EXTRA FROM VTX WHERE ID = ?;";
  sqlite3_prepare_v2(db_, select_sql.c_str(), -1, &select_stmt, NULL);
  sqlite3_bind_text(select_stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(select_stmt);
  bool updated = false;
  if (sqlite3_column_text(select_stmt, 0)) {
    std::string extra = std::string((char*)sqlite3_column_text(select_stmt, 0));
    json extra_json = extra.empty() ? json{} : json::parse(extra);
    extra_json["schedule_time"] = value;
    extra = extra_json.dump();

    sqlite3_stmt* update_stmt;
    std::string update_sql = "UPDATE VTX SET EXTRA = ?1 WHERE ID = ?2;";
    sqlite3_prepare_v2(db_, update_sql.c_str(), -1, &update_stmt, NULL);
    sqlite3_bind_text(update_stmt, 1, extra.c_str(), extra.size(), NULL);
    sqlite3_bind_text(update_stmt, 2, tx_id.c_str(), tx_id.size(), NULL);
    sqlite3_step(update_stmt);
    SQLCHECK(sqlite3_finalize(update_stmt));
    updated = true;
  }
  SQLCHECK(sqlite3_finalize(select_stmt));
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
  if (!memo.empty()) UpdateTransactionMemo(tx_id, memo);
  txs_cache_[db_file_name_].erase(tx_id);
  auto tx = GetTransaction(tx_id);
  AutoAddNewCoins(tx);
  return tx;
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
  txs_cache_[db_file_name_].erase(tx_id);
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
    int64_t fee = sqlite3_column_int64(stmt, 3);
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

bool NunchukWalletDb::ReplaceTxId(const std::string& txid,
                                  const std::string& replace_txid) {
  SetReplacedBy(replace_txid, txid);

  // Get tx extra
  sqlite3_stmt* select_stmt;
  std::string select_sql = "SELECT EXTRA FROM VTX WHERE ID = ?;";
  sqlite3_prepare_v2(db_, select_sql.c_str(), -1, &select_stmt, NULL);
  sqlite3_bind_text(select_stmt, 1, txid.c_str(), txid.size(), NULL);
  sqlite3_step(select_stmt);
  bool updated = false;
  if (sqlite3_column_text(select_stmt, 0)) {
    // Update tx extra
    std::string extra = std::string((char*)sqlite3_column_text(select_stmt, 0));
    json extra_json = extra.empty() ? json{} : json::parse(extra);
    extra_json["replace_txid"] = replace_txid;
    extra = extra_json.dump();

    sqlite3_stmt* update_stmt;
    std::string update_sql = "UPDATE VTX SET EXTRA = ?1 WHERE ID = ?2;";
    sqlite3_prepare_v2(db_, update_sql.c_str(), -1, &update_stmt, NULL);
    sqlite3_bind_text(update_stmt, 1, extra.c_str(), extra.size(), NULL);
    sqlite3_bind_text(update_stmt, 2, txid.c_str(), txid.size(), NULL);
    sqlite3_step(update_stmt);
    updated = (sqlite3_changes(db_) == 1);
    SQLCHECK(sqlite3_finalize(update_stmt));
  }
  SQLCHECK(sqlite3_finalize(select_stmt));
  txs_cache_[db_file_name_].erase(txid);
  if (updated) GetTransaction(txid);
  return updated;
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

std::pair<std::string, bool> NunchukWalletDb::GetPsbtOrRawTx(
    const std::string& tx_id) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT VALUE FROM VTX WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    std::string rs = std::string((char*)sqlite3_column_text(stmt, 0));
    SQLCHECK(sqlite3_finalize(stmt));
    auto [tx, is_hex_tx] = GetTransactionFromStr(rs, {}, -1);
    return {rs, is_hex_tx};
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    return {"", false};
  }
}

Transaction NunchukWalletDb::GetTransaction(const std::string& tx_id) {
  if (txs_cache_[db_file_name_].count(tx_id))
    return txs_cache_[db_file_name_][tx_id];
  auto wallet = GetWallet(true, true);

  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM VTX WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    std::string value = std::string((char*)sqlite3_column_text(stmt, 1));
    int height = sqlite3_column_int(stmt, 2);
    int64_t fee = sqlite3_column_int64(stmt, 3);
    std::string memo = std::string((char*)sqlite3_column_text(stmt, 4));
    int change_pos = sqlite3_column_int(stmt, 5);
    time_t blocktime = sqlite3_column_int64(stmt, 6);

    auto [tx, is_hex_tx] = GetTransactionFromStr(value, wallet, height);
    tx.set_txid(tx_id);
    tx.set_m(wallet.get_m());
    tx.set_wallet_type(wallet.get_wallet_type());
    tx.set_address_type(wallet.get_address_type());
    tx.set_fee(Amount(fee));
    tx.set_fee_rate(0);
    tx.set_change_index(change_pos);
    tx.set_blocktime(blocktime);
    tx.set_schedule_time(-1);
    // Default value, will set in FillSendReceiveData
    // TODO: Replace this asap. This code is fragile and potentially dangerous,
    // since it relies on external assumptions (flow of outside code) that might
    // become false
    tx.set_receive(false);
    tx.set_sub_amount(0);
    if (is_hex_tx) {
      tx.set_raw(value);
    } else {
      tx.set_psbt(value);
    }

    if (sqlite3_column_text(stmt, 7)) {
      std::string extra = std::string((char*)sqlite3_column_text(stmt, 7));
      FillExtra(extra, tx);
    }
    SQLCHECK(sqlite3_finalize(stmt));
    for (auto&& output : tx.get_outputs()) UseAddress(output.first);
    auto new_memo = GetTransactionMemo(tx_id);
    if (new_memo) {
      tx.set_memo(new_memo.value());
    } else {
      tx.set_memo(memo);
      if (!memo.empty()) UpdateTransactionMemo(tx_id, memo);
    }
    txs_cache_[db_file_name_][tx_id] = tx;
    return tx;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
  }
}

bool NunchukWalletDb::DeleteTransaction(const std::string& tx_id) {
  sqlite3_stmt* stmt;
  std::string sql = "DELETE FROM VTX WHERE ID = ? AND HEIGHT <= 0;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  txs_cache_[db_file_name_].erase(tx_id);
  return updated;
}

bool NunchukWalletDb::SetUtxos(const std::string& address,
                               const std::string& utxo) {
  auto all = GetAllAddressData();
  if (!all.count(address)) return false;
  SetAddress(address, all[address].index, all[address].internal, utxo);
  return true;
}

Amount NunchukWalletDb::GetBalance(bool include_mempool) {
  auto coins = GetCoins();
  Amount balance = 0;
  for (auto&& coin : coins) {
    if (coin.get_status() == CoinStatus::SPENT ||
        coin.get_status() == CoinStatus::OUTGOING_PENDING_CONFIRMATION)
      continue;
    if (!include_mempool && !coin.is_change() &&
        coin.get_status() == CoinStatus::INCOMING_PENDING_CONFIRMATION)
      continue;
    balance += coin.get_amount();
  }
  return balance;
}

std::vector<Transaction> NunchukWalletDb::GetTransactions(int count, int skip) {
  auto wallet = GetWallet(true, true);

  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM VTX;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  std::vector<Transaction> rs;
  while (sqlite3_column_text(stmt, 0)) {
    std::string tx_id = std::string((char*)sqlite3_column_text(stmt, 0));
    if (!txs_cache_[db_file_name_].count(tx_id)) {
      std::string value = std::string((char*)sqlite3_column_text(stmt, 1));
      int height = sqlite3_column_int(stmt, 2);
      int64_t fee = sqlite3_column_int64(stmt, 3);
      std::string memo = std::string((char*)sqlite3_column_text(stmt, 4));
      int change_pos = sqlite3_column_int(stmt, 5);
      time_t blocktime = sqlite3_column_int64(stmt, 6);

      auto [tx, is_hex_tx] = GetTransactionFromStr(value, wallet, height);
      tx.set_txid(tx_id);
      tx.set_m(wallet.get_m());
      tx.set_wallet_type(wallet.get_wallet_type());
      tx.set_address_type(wallet.get_address_type());
      tx.set_fee(Amount(fee));
      tx.set_fee_rate(0);
      tx.set_change_index(change_pos);
      tx.set_blocktime(blocktime);
      tx.set_schedule_time(-1);
      tx.set_receive(false);
      tx.set_sub_amount(0);
      tx.set_memo(memo);
      if (is_hex_tx) {
        tx.set_raw(value);
      } else {
        tx.set_psbt(value);
      }

      if (sqlite3_column_text(stmt, 7)) {
        std::string extra = std::string((char*)sqlite3_column_text(stmt, 7));
        FillExtra(extra, tx);
      }
      txs_cache_[db_file_name_][tx_id] = tx;
    }
    rs.push_back(txs_cache_[db_file_name_][tx_id]);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  auto all_memo = GetAllMemo();
  for (auto&& tx : rs) {
    if (all_memo.count(tx.get_txid())) {
      tx.set_memo(all_memo[tx.get_txid()]);
      txs_cache_[db_file_name_][tx.get_txid()].set_memo(
          all_memo[tx.get_txid()]);
    } else if (!tx.get_memo().empty()) {
      UpdateTransactionMemo(tx.get_txid(), tx.get_memo());
    }
  }
  return rs;
}

std::string NunchukWalletDb::FillPsbt(const std::string& base64_psbt) {
  auto psbt = DecodePsbt(base64_psbt);
  if (!psbt.tx.has_value()) return base64_psbt;

  auto wallet = GetWallet(true);
  auto desc = GetDescriptorsImportString(wallet);
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
    SignPSBTInput(provider, psbt, i, &txdata, 1, nullptr, false);
  }

  // Update script/keypath information using descriptor data.
  for (unsigned int i = 0; i < psbt.tx.value().vout.size(); ++i) {
    UpdatePSBTOutput(provider, psbt, i);
  }

  for (auto&& signer : wallet.get_signers()) {
    std::vector<unsigned char> key;
    if (DecodeBase58Check(signer.get_xpub(), key, 78)) {
      auto value = ParseHex(signer.get_master_fingerprint());
      std::vector<uint32_t> keypath;
      std::string formalized = signer.get_derivation_path();
      std::replace(formalized.begin(), formalized.end(), 'h', '\'');
      if (ParseHDKeypath(formalized, keypath)) {
        for (uint32_t index : keypath) {
          value.push_back(index);
          value.push_back(index >> 8);
          value.push_back(index >> 16);
          value.push_back(index >> 24);
        }
      }
      key.insert(key.begin(), 1);
      psbt.unknown[key] = value;
    }
  }

  return EncodePsbt(psbt);
}

void NunchukWalletDb::FillExtra(const std::string& extra,
                                Transaction& tx) const {
  if (!extra.empty()) {
    json extra_json = json::parse(extra);
    if (extra_json["signers"] != nullptr &&
        (tx.get_height() >= 0 || !tx.get_raw().empty())) {
      for (auto&& signer : tx.get_signers()) {
        if (!signer.second)
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
    if (extra_json["replace_txid"] != nullptr) {
      tx.set_replace_txid(extra_json["replace_txid"]);
    }
    if (extra_json["schedule_time"] != nullptr) {
      tx.set_schedule_time(extra_json["schedule_time"]);
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
  auto allAddr = GetAllAddressData();
  auto isMyAddress = [&](const std::string& address) {
    return allAddr.count(address);
  };

  auto isMyChange = [&](const std::string& address) {
    return allAddr.count(address) && allAddr.at(address).internal;
  };

  Amount total_amount = 0;
  bool is_send_tx = false;
  bool extract_signers = false;
  for (size_t i = 0; i < tx.get_inputs().size(); i++) {
    auto input = tx.get_inputs()[i];
    TxOutput prev_out;
    try {
      auto prev_tx = GetTransaction(input.first);
      prev_out = prev_tx.get_outputs()[input.second];
      if (!extract_signers && tx.get_wallet_type() == WalletType::MULTI_SIG &&
          tx.get_address_type() != AddressType::TAPROOT &&
          !tx.get_raw().empty() && !prev_tx.get_raw().empty()) {
        try {
          for (auto&& signer : tx.get_signers()) {
            tx.set_signer(signer.first, false);
          }
          auto mtx = DecodeRawTransaction(tx.get_raw());
          auto vout =
              DecodeRawTransaction(prev_tx.get_raw()).vout[input.second];
          auto extract = DataFromTransaction(mtx, i, vout);
          for (auto&& sig : extract.signatures) {
            KeyOriginInfo info;
            if (SigningProviderCache::getInstance().GetKeyOrigin(sig.first,
                                                                 info)) {
              tx.set_signer(strprintf("%08x", ReadBE32(info.fingerprint)),
                            true);
            }
          }
          extract_signers = true;
        } catch (...) {
        }
      }
    } catch (StorageException& se) {
      if (se.code() != StorageException::TX_NOT_FOUND) throw;
    }
    if (isMyAddress(prev_out.first)) {
      total_amount += prev_out.second;
      is_send_tx = true;
    }
  }
  if (is_send_tx) {
    Amount send_amount{0};
    for (size_t i = 0; i < tx.get_outputs().size(); i++) {
      auto output = tx.get_outputs()[i];
      total_amount -= output.second;
      if (!isMyAddress(output.first)) {
        send_amount += output.second;
      } else if (tx.get_change_index() < 0 && isMyChange(output.first)) {
        tx.set_change_index(i);
      }
    }
    tx.set_fee(total_amount);
    tx.set_receive(false);
    tx.set_sub_amount(send_amount);
    if (tx.get_fee_rate() == 0 && !tx.get_raw().empty()) {
      auto vsize = GetVirtualTransactionSize(
          CTransaction(DecodeRawTransaction(tx.get_raw())));
      tx.set_fee_rate(total_amount * 1000 / vsize);
    }
  } else {
    Amount receive_amount{0};
    for (auto&& output : tx.get_outputs()) {
      if (isMyAddress(output.first)) {
        receive_amount += output.second;
        tx.add_receive_output(output);
      }
    }
    tx.set_receive(true);
    tx.set_sub_amount(receive_amount);
  }
}

void NunchukWalletDb::ForceRefresh() {
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM VTX;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM ADDRESS;", NULL, 0, NULL));
  addr_cache_.erase(db_file_name_);
  txs_cache_.erase(db_file_name_);
}

void NunchukWalletDb::CreateCoinControlTable() {
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS TAGS("
                        "ID INTEGER PRIMARY KEY,"
                        "NAME            TEXT    NOT NULL UNIQUE,"
                        "COLOR           TEXT    NOT NULL);",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS COLLECTIONS("
                        "ID INTEGER PRIMARY KEY,"
                        "NAME            TEXT    NOT NULL UNIQUE,"
                        "SETTINGS        TEXT    NOT NULL);",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS COINTAGS("
                        "COIN            TEXT    NOT NULL,"
                        "TAGID           INT     NOT NULL,"
                        "PRIMARY KEY (COIN, TAGID));",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS COINCOLLECTIONS("
                        "COIN            TEXT    NOT NULL,"
                        "COLLECTIONID    INT     NOT NULL,"
                        "PRIMARY KEY (COIN, COLLECTIONID));",
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS COININFO("
                        "COIN TEXT PRIMARY KEY   NOT NULL,"
                        "MEMO            TEXT    NOT NULL,"
                        "LOCKED          INT     NOT NULL);",
                        NULL, 0, NULL));
}

void NunchukWalletDb::CreateDummyTxTable() {
  SQLCHECK(sqlite3_exec(db_,
                        "CREATE TABLE IF NOT EXISTS DUMMYTX("
                        "ID TEXT PRIMARY KEY     NOT NULL,"
                        "PSBT            TEXT    NOT NULL,"
                        "STOKEN          TEXT    NOT NULL,"
                        "LTOKEN          TEXT    NOT NULL);",
                        NULL, 0, NULL));
}

std::string NunchukWalletDb::CoinId(const std::string& tx_id, int vout) const {
  return strprintf("%s:%d", tx_id, vout);
}

bool NunchukWalletDb::UpdateTransactionMemo(const std::string& tx_id,
                                            const std::string& memo) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO COININFO(COIN, MEMO, LOCKED) VALUES (?1, ?2, ?3) "
      "ON CONFLICT(COIN) DO UPDATE SET MEMO=excluded.MEMO;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_bind_text(stmt, 2, memo.c_str(), memo.size(), NULL);
  sqlite3_bind_int(stmt, 3, 0);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  // if (updated) SetLastModified(std::time(0));
  return updated;
}

std::optional<std::string> NunchukWalletDb::GetTransactionMemo(
    const std::string& tx_id) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM COININFO WHERE COIN = ?1;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);

  if (sqlite3_column_text(stmt, 0)) {
    std::string rs = std::string((char*)sqlite3_column_text(stmt, 1));
    SQLCHECK(sqlite3_finalize(stmt));
    return rs;
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return {};
}

bool NunchukWalletDb::UpdateCoinMemo(const std::string& tx_id, int vout,
                                     const std::string& memo) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO COININFO(COIN, MEMO, LOCKED) VALUES (?1, ?2, ?3) "
      "ON CONFLICT(COIN) DO UPDATE SET MEMO=excluded.MEMO;";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_text(stmt, 2, memo.c_str(), memo.size(), NULL);
  sqlite3_bind_int(stmt, 3, 0);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  // if (updated) SetLastModified(std::time(0));

  return updated;
}

std::string NunchukWalletDb::GetCoinMemo(const std::string& tx_id,
                                         int vout) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM COININFO WHERE COIN = ?1;";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_step(stmt);

  std::string rs = "";
  while (sqlite3_column_text(stmt, 0)) {
    rs = std::string((char*)sqlite3_column_text(stmt, 1));
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

std::map<std::string, std::string> NunchukWalletDb::GetAllMemo() const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM COININFO;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  std::map<std::string, std::string> rs;
  while (sqlite3_column_text(stmt, 0)) {
    std::string coin = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string memo = std::string((char*)sqlite3_column_text(stmt, 1));
    int locked = sqlite3_column_int(stmt, 2);
    rs[coin] = memo;
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

bool NunchukWalletDb::LockCoin(const std::string& coin, bool update_ts) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO COININFO(COIN, MEMO, LOCKED) VALUES (?1, ?2, ?3) "
      "ON CONFLICT(COIN) DO UPDATE SET LOCKED=excluded.LOCKED;";
  std::string memo;
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_text(stmt, 2, memo.c_str(), memo.size(), NULL);
  sqlite3_bind_int(stmt, 3, 1);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated && update_ts) SetLastModified(std::time(0));
  return updated;
}

bool NunchukWalletDb::LockCoin(const std::string& tx_id, int vout,
                               bool update_ts) {
  return LockCoin(CoinId(tx_id, vout), update_ts);
}

bool NunchukWalletDb::UnlockCoin(const std::string& tx_id, int vout) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO COININFO(COIN, MEMO, LOCKED) VALUES (?1, ?2, ?3) "
      "ON CONFLICT(COIN) DO UPDATE SET LOCKED=excluded.LOCKED;";
  std::string coin = CoinId(tx_id, vout);
  std::string memo;
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_text(stmt, 2, memo.c_str(), memo.size(), NULL);
  sqlite3_bind_int(stmt, 3, 0);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated) SetLastModified(std::time(0));
  return updated;
}

bool NunchukWalletDb::IsLock(const std::string& tx_id, int vout) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM COININFO WHERE COIN = ?1;";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_step(stmt);

  bool rs = false;
  while (sqlite3_column_text(stmt, 0)) {
    rs = sqlite3_column_int(stmt, 2) == 1;
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

int NunchukWalletDb::CreateCoinTag(const std::string& name,
                                   const std::string& color) {
  sqlite3_exec(db_, "BEGIN TRANSACTION;", NULL, NULL, NULL);
  sqlite3_stmt* stmt;
  std::string sql = "INSERT INTO TAGS(NAME, COLOR) VALUES (?1, ?2);";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, name.c_str(), name.size(), NULL);
  sqlite3_bind_text(stmt, 2, color.c_str(), color.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_changes(db_) != 1) {
    SQLCHECK(sqlite3_finalize(stmt));
    throw StorageException(StorageException::TAG_EXISTS, "Tag exists");
  }

  sql = "SELECT last_insert_rowid()";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  int id = -1;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    id = sqlite3_column_int(stmt, 0);
  }

  sqlite3_exec(db_, "COMMIT;", NULL, NULL, NULL);
  SQLCHECK(sqlite3_finalize(stmt));
  SetLastModified(std::time(0));
  return id;
}

std::vector<CoinTag> NunchukWalletDb::GetCoinTags() const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM TAGS;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  std::vector<CoinTag> rs;
  while (sqlite3_column_text(stmt, 0)) {
    int id = sqlite3_column_int(stmt, 0);
    std::string name = std::string((char*)sqlite3_column_text(stmt, 1));
    std::string color = std::string((char*)sqlite3_column_text(stmt, 2));
    rs.push_back({id, name, color});
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

bool NunchukWalletDb::UpdateCoinTag(const CoinTag& tag) {
  sqlite3_stmt* stmt;
  std::string sql = "UPDATE TAGS SET NAME = ?1, COLOR = ?2 WHERE ID = ?3;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  std::string name = tag.get_name();
  std::string color = tag.get_color();
  sqlite3_bind_text(stmt, 1, name.c_str(), name.size(), NULL);
  sqlite3_bind_text(stmt, 2, color.c_str(), color.size(), NULL);
  sqlite3_bind_int64(stmt, 3, tag.get_id());
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated) SetLastModified(std::time(0));

  return updated;
}

bool NunchukWalletDb::DeleteCoinTag(int tag_id) {
  sqlite3_stmt* stmt;
  std::string sql = "DELETE FROM TAGS WHERE ID = ?;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, tag_id);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));

  sql = "DELETE FROM COINTAGS WHERE TAGID = ?1;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, tag_id);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated) SetLastModified(std::time(0));
  return updated;
}

bool NunchukWalletDb::AddToCoinTag(int tag_id, const std::string& tx_id,
                                   int vout) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT OR IGNORE INTO COINTAGS(COIN, TAGID) VALUES (?1, ?2);";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_int64(stmt, 2, tag_id);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated) {
    SetLastModified(std::time(0));
    auto auto_add = GetAutoAddData();
    for (auto&& [col_tag, is_auto_add] : auto_add) {
      if (is_auto_add && col_tag.second == tag_id) {
        AddToCoinCollection(col_tag.first, tx_id, vout, false);
      }
    }
  }
  return updated;
}

bool NunchukWalletDb::RemoveFromCoinTag(int tag_id, const std::string& tx_id,
                                        int vout) {
  sqlite3_stmt* stmt;
  std::string sql = "DELETE FROM COINTAGS WHERE COIN = ?1 AND TAGID = ?2;";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_int64(stmt, 2, tag_id);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated) SetLastModified(std::time(0));
  return updated;
}

std::vector<std::string> NunchukWalletDb::GetCoinByTag(int tag_id) {
  if (tag_id == CoinCollection::COINS_WITHOUT_TAGS) {
    return GetCoinWithoutTag();
  }
  sqlite3_stmt* stmt;
  std::string sql = "SELECT COIN FROM COINTAGS WHERE TAGID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, tag_id);
  sqlite3_step(stmt);

  std::vector<std::string> rs;
  while (sqlite3_column_text(stmt, 0)) {
    std::string coin = std::string((char*)sqlite3_column_text(stmt, 0));
    rs.push_back(coin);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

std::vector<std::string> NunchukWalletDb::GetCoinWithoutTag() {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT COIN FROM COINTAGS;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  std::set<std::string> coinswithtag;
  while (sqlite3_column_text(stmt, 0)) {
    std::string coin = std::string((char*)sqlite3_column_text(stmt, 0));
    coinswithtag.insert(coin);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));

  auto transactions = GetTransactions();
  auto allcoins = GetCoinsFromTransactions(transactions);
  std::vector<std::string> rs;
  for (auto&& coin : allcoins) {
    if (coinswithtag.find(coin.first) != coinswithtag.end()) continue;
    rs.push_back(coin.first);
  }
  return rs;
}

std::vector<int> NunchukWalletDb::GetAddedTags(const std::string& tx_id,
                                               int vout) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT TAGID FROM COINTAGS WHERE COIN = ?;";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_step(stmt);

  std::vector<int> rs;
  while (sqlite3_column_text(stmt, 0)) {
    int id = sqlite3_column_int(stmt, 0);
    rs.push_back(id);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

int NunchukWalletDb::CreateCoinCollection(const std::string& name) {
  json default_settings = {{"add_new_coin", false}, {"auto_lock", false}};
  std::string settings = default_settings.dump();

  sqlite3_exec(db_, "BEGIN TRANSACTION;", NULL, NULL, NULL);
  sqlite3_stmt* stmt;
  std::string sql = "INSERT INTO COLLECTIONS(NAME, SETTINGS) VALUES (?1, ?2);";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, name.c_str(), name.size(), NULL);
  sqlite3_bind_text(stmt, 2, settings.c_str(), settings.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_changes(db_) != 1) {
    SQLCHECK(sqlite3_finalize(stmt));
    throw StorageException(StorageException::COLLECTION_EXISTS,
                           "Collection exists");
  }

  sql = "SELECT last_insert_rowid()";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  int id = -1;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    id = sqlite3_column_int(stmt, 0);
  }

  sqlite3_exec(db_, "COMMIT;", NULL, NULL, NULL);
  SQLCHECK(sqlite3_finalize(stmt));
  SetLastModified(std::time(0));
  return id;
}

std::vector<CoinCollection> NunchukWalletDb::GetCoinCollections() const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM COLLECTIONS;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  std::vector<CoinCollection> rs;
  while (sqlite3_column_text(stmt, 0)) {
    int id = sqlite3_column_int(stmt, 0);
    std::string name = std::string((char*)sqlite3_column_text(stmt, 1));
    std::string settings = std::string((char*)sqlite3_column_text(stmt, 2));
    CoinCollection collection{id, name};
    json parsed_settings = json::parse(settings);
    collection.set_add_new_coin(parsed_settings["add_new_coin"]);
    collection.set_auto_lock(parsed_settings["auto_lock"]);
    if (parsed_settings["add_tagged_coins"] != nullptr) {
      collection.set_add_coins_with_tag(parsed_settings["add_tagged_coins"]);
    }
    rs.push_back(collection);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

bool NunchukWalletDb::UpdateCoinCollection(const CoinCollection& collection,
                                           bool apply_to_existing_coins) {
  sqlite3_stmt* stmt;
  std::string sql =
      "UPDATE COLLECTIONS SET NAME = ?1, SETTINGS = ?2 WHERE ID = ?3;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  std::string name = collection.get_name();
  json new_settings = {
      {"add_new_coin", collection.is_add_new_coin()},
      {"auto_lock", collection.is_auto_lock()},
      {"add_tagged_coins", collection.get_add_coins_with_tag()}};
  std::string settings = new_settings.dump();
  sqlite3_bind_text(stmt, 1, name.c_str(), name.size(), NULL);
  sqlite3_bind_text(stmt, 2, settings.c_str(), settings.size(), NULL);
  sqlite3_bind_int64(stmt, 3, collection.get_id());
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated) {
    SetLastModified(std::time(0));
    collection_auto_lock_.erase(db_file_name_);
    collection_auto_add_.erase(db_file_name_);
    if (apply_to_existing_coins &&
        !collection.get_add_coins_with_tag().empty()) {
      for (auto&& t : collection.get_add_coins_with_tag()) {
        auto coins = GetCoinByTag(t);
        for (auto&& coin : coins) {
          AddToCoinCollection(collection.get_id(), coin, false);
        }
      }
    }
  }
  return updated;
}

bool NunchukWalletDb::DeleteCoinCollection(int collection_id) {
  sqlite3_stmt* stmt;
  std::string sql = "DELETE FROM COLLECTIONS WHERE ID = ?;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, collection_id);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));

  sql = "DELETE FROM COINCOLLECTIONS WHERE COLLECTIONID = ?1;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, collection_id);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated) SetLastModified(std::time(0));
  return updated;
}

bool NunchukWalletDb::AddToCoinCollection(int collection_id,
                                          const std::string& coin,
                                          bool update_ts) {
  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT OR IGNORE INTO COINCOLLECTIONS(COIN, COLLECTIONID) "
      "VALUES (?1, ?2);";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_int64(stmt, 2, collection_id);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (GetAutoLockData()[collection_id]) LockCoin(coin, update_ts);
  if (updated && update_ts) SetLastModified(std::time(0));
  return updated;
}

bool NunchukWalletDb::AddToCoinCollection(int collection_id,
                                          const std::string& tx_id, int vout,
                                          bool update_ts) {
  return AddToCoinCollection(collection_id, CoinId(tx_id, vout), update_ts);
}

bool NunchukWalletDb::RemoveFromCoinCollection(int collection_id,
                                               const std::string& tx_id,
                                               int vout) {
  sqlite3_stmt* stmt;
  std::string sql =
      "DELETE FROM COINCOLLECTIONS WHERE COIN = ?1 AND COLLECTIONID = ?2;";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_bind_int64(stmt, 2, collection_id);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  if (updated) SetLastModified(std::time(0));
  return updated;
}

std::vector<std::string> NunchukWalletDb::GetCoinInCollection(
    int collection_id) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT COIN FROM COINCOLLECTIONS WHERE COLLECTIONID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, collection_id);
  sqlite3_step(stmt);

  std::vector<std::string> rs;
  while (sqlite3_column_text(stmt, 0)) {
    std::string coin = std::string((char*)sqlite3_column_text(stmt, 0));
    rs.push_back(coin);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

std::vector<int> NunchukWalletDb::GetAddedCollections(const std::string& tx_id,
                                                      int vout) const {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT COLLECTIONID FROM COINCOLLECTIONS WHERE COIN = ?;";
  std::string coin = CoinId(tx_id, vout);
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
  sqlite3_step(stmt);

  std::vector<int> rs;
  while (sqlite3_column_text(stmt, 0)) {
    int id = sqlite3_column_int(stmt, 0);
    rs.push_back(id);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

std::string NunchukWalletDb::ExportCoinControlData() {
  json data;
  data["export_ts"] = std::time(0);
  data["last_modified_ts"] = GetLastModified();
  // export tags
  data["tags"] = json::array();
  auto tags = GetCoinTags();
  for (auto&& i : tags) {
    json tag = {
        {"id", i.get_id()}, {"name", i.get_name()}, {"color", i.get_color()}};
    tag["coins"] = json::array();
    auto coins = GetCoinByTag(i.get_id());
    for (auto&& coin : coins) {
      tag["coins"].push_back(coin);
    }
    data["tags"].push_back(tag);
  }
  // export collections
  data["collections"] = json::array();
  auto collections = GetCoinCollections();
  for (auto&& i : collections) {
    json collection = {{"id", i.get_id()},
                       {"name", i.get_name()},
                       {"add_new_coin", i.is_add_new_coin()},
                       {"auto_lock", i.is_auto_lock()},
                       {"add_tagged_coins", i.get_add_coins_with_tag()}};
    collection["coins"] = json::array();
    auto coins = GetCoinInCollection(i.get_id());
    for (auto&& coin : coins) {
      collection["coins"].push_back(coin);
    }
    data["collections"].push_back(collection);
  }
  // export coininfo
  data["coininfo"] = json::array();
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM COININFO;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  while (sqlite3_column_text(stmt, 0)) {
    std::string coin = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string memo = std::string((char*)sqlite3_column_text(stmt, 1));
    int locked = sqlite3_column_int(stmt, 2);
    data["coininfo"].push_back(
        {{"coin", coin}, {"memo", memo}, {"locked", locked}});
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));

  return data.dump();
}

void NunchukWalletDb::ClearCoinControlData() {
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM TAGS;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM COINTAGS;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM COLLECTIONS;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM COINCOLLECTIONS;", NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(db_, "DELETE FROM COININFO;", NULL, 0, NULL));
  collection_auto_lock_.erase(db_file_name_);
  collection_auto_add_.erase(db_file_name_);
}

bool NunchukWalletDb::ImportCoinControlData(const std::string& dataStr,
                                            bool force, bool merge) {
  if (dataStr.empty()) return false;
  json data = json::parse(dataStr);
  if (data["last_modified_ts"] == nullptr) return false;
  time_t ts = data["last_modified_ts"];
  if (!force && ts <= GetLastModified()) return false;

  auto currentData = ExportCoinControlData();
  auto current = json::parse(currentData);
  current.erase("last_modified_ts");
  current.erase("export_ts");

  data.erase("last_modified_ts");
  data.erase("export_ts");

  if (current == data) {
    return false;
  }

  if (!merge) ClearCoinControlData();
  auto oldTags = GetCoinTags();
  std::map<std::string, int> tagMap{};
  for (auto&& i : oldTags) tagMap[i.get_name()] = i.get_id();
  auto oldCollections = GetCoinCollections();
  std::map<std::string, int> collectionMap{};
  for (auto&& i : oldCollections) collectionMap[i.get_name()] = i.get_id();

  // import tags
  json tags = data["tags"];
  for (auto&& tag : tags) {
    std::string name = tag["name"];
    std::string color = tag["color"];
    int id = -1;
    if (tagMap.count(name)) {
      id = tagMap[name];
      UpdateCoinTag({id, name, color});
    } else if (tag["id"] != nullptr) {
      id = tag["id"];
      sqlite3_stmt* stmt;
      std::string sql =
          "INSERT INTO TAGS(ID, NAME, COLOR) VALUES (?1, ?2, ?3) "
          "ON CONFLICT(ID) DO UPDATE SET NAME=excluded.NAME, "
          "COLOR=excluded.COLOR;";
      sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
      sqlite3_bind_int(stmt, 1, id);
      sqlite3_bind_text(stmt, 2, name.c_str(), name.size(), NULL);
      sqlite3_bind_text(stmt, 3, color.c_str(), color.size(), NULL);
      sqlite3_step(stmt);
      SQLCHECK(sqlite3_finalize(stmt));
    } else {
      id = CreateCoinTag(name, color);
      tagMap[name] = id;
    }

    for (auto&& i : tag["coins"]) {
      sqlite3_stmt* stmt;
      std::string sql = "INSERT INTO COINTAGS(COIN, TAGID) VALUES (?1, ?2);";
      std::string coin = i.get<std::string>();
      sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
      sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
      sqlite3_bind_int64(stmt, 2, id);
      sqlite3_step(stmt);
      SQLCHECK(sqlite3_finalize(stmt));
    }
  }

  // import collections
  json collections = data["collections"];
  for (auto&& collection : collections) {
    std::string name = collection["name"];
    int id = -1;
    std::vector<int> add_tagged_coins{};
    if (collection["add_tagged"] != nullptr) {
      std::vector<std::string> tag_names = collection["add_tagged"];
      for (auto&& tag_name : tag_names) {
        add_tagged_coins.push_back(tagMap[tag_name]);
      }
    }
    if (collection["add_tagged_coins"] != nullptr) {
      std::vector<int> tag_ids = collection["add_tagged_coins"];
      for (auto&& tag_id : tag_ids) {
        add_tagged_coins.push_back(tag_id);
      }
    }

    if (collectionMap.count(name) == 0 && collection["id"] != nullptr) {
      id = collection["id"];
      sqlite3_stmt* stmt;
      std::string sql =
          "INSERT INTO COLLECTIONS(ID, NAME, SETTINGS) VALUES (?1, ?2, ?3) "
          "ON CONFLICT(ID) DO UPDATE SET NAME=excluded.NAME, "
          "SETTINGS=excluded.SETTINGS;";
      json jsettings = {{"add_new_coin", collection["add_new_coin"]},
                        {"auto_lock", collection["auto_lock"]},
                        {"add_tagged_coins", add_tagged_coins}};
      std::string settings = jsettings.dump();
      sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
      sqlite3_bind_int(stmt, 1, id);
      sqlite3_bind_text(stmt, 2, name.c_str(), name.size(), NULL);
      sqlite3_bind_text(stmt, 3, settings.c_str(), settings.size(), NULL);
      sqlite3_step(stmt);
      SQLCHECK(sqlite3_finalize(stmt));
    } else {
      if (collectionMap.count(name)) {
        id = collectionMap[name];
      } else {
        id = CreateCoinCollection(name);
      }
      CoinCollection c{id, name};
      c.set_add_new_coin(collection["add_new_coin"]);
      c.set_auto_lock(collection["auto_lock"]);
      c.set_add_coins_with_tag(add_tagged_coins);
      UpdateCoinCollection(c, false);
    }

    for (auto&& i : collection["coins"]) {
      sqlite3_stmt* stmt;
      std::string sql =
          "INSERT INTO COINCOLLECTIONS(COIN, COLLECTIONID) VALUES (?1, ?2);";
      std::string coin = i.get<std::string>();
      sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
      sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
      sqlite3_bind_int64(stmt, 2, id);
      sqlite3_step(stmt);
      SQLCHECK(sqlite3_finalize(stmt));
    }
  }
  // import coininfo
  json coininfo = data["coininfo"];
  for (auto&& i : coininfo) {
    std::string coin = i["coin"];
    std::string memo = i["memo"];
    int locked = i["locked"];
    sqlite3_stmt* stmt;
    std::string sql =
        "INSERT INTO COININFO(COIN, MEMO, LOCKED) VALUES (?1, ?2, ?3) "
        "ON CONFLICT(COIN) DO UPDATE SET LOCKED=excluded.LOCKED, "
        "MEMO=excluded.MEMO;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
    sqlite3_bind_text(stmt, 2, memo.c_str(), memo.size(), NULL);
    sqlite3_bind_int(stmt, 3, locked);
    sqlite3_step(stmt);
    SQLCHECK(sqlite3_finalize(stmt));
  }

  SetLastModified(ts);
  return true;
}

std::string NunchukWalletDb::ExportBIP329() {
  std::map<std::string, std::string> all_label;
  std::map<std::string, bool> spendable;
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM COININFO;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  while (sqlite3_column_text(stmt, 0)) {
    std::string coin = std::string((char*)sqlite3_column_text(stmt, 0));
    all_label[coin] = std::string((char*)sqlite3_column_text(stmt, 1));
    spendable[coin] = (sqlite3_column_int(stmt, 2) != 1);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));

  auto tags = GetCoinTags();
  for (auto&& i : tags) {
    auto coins = GetCoinByTag(i.get_id());
    for (auto&& coin : coins) {
      all_label[coin] += " " + i.get_name();
    }
  }

  auto collections = GetCoinCollections();
  for (auto&& i : collections) {
    auto coins = GetCoinInCollection(i.get_id());
    for (auto&& coin : coins) {
      all_label[coin] += " #collection_" + i.get_name();
    }
  }

  std::stringstream bip329;
  for (auto&& [coin, label] : all_label) {
    std::string type = coin.find(':') != std::string::npos ? "output" : "tx";
    json line = {
        {"type", type}, {"ref", coin}, {"label", boost::trim_copy(label)}};
    if (type == "output")
      line["spendable"] = spendable[coin] ? "true" : "false";
    bip329 << line.dump() << std::endl;
  }
  return bip329.str();
}

void NunchukWalletDb::ImportBIP329(const std::string& data) {
  std::istringstream content_stream(data);
  std::string line;
  while (safeGetline(content_stream, line) && !line.empty()) {
    json json_line = json::parse(line);
    std::string type = json_line["type"];
    if (type != "output" && type != "tx") continue;
    std::string coin = json_line["ref"];
    std::string memo = json_line["label"];
    int locked = 0;
    if (json_line["spendable"] != nullptr) {
      bool spendable = json_line["spendable"] == "true";
      locked = spendable ? 0 : 1;
    }

    sqlite3_stmt* stmt;
    std::string sql =
        "INSERT INTO COININFO(COIN, MEMO, LOCKED) VALUES (?1, ?2, ?3) "
        "ON CONFLICT(COIN) DO UPDATE SET LOCKED=excluded.LOCKED, "
        "MEMO=excluded.MEMO;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, coin.c_str(), coin.size(), NULL);
    sqlite3_bind_text(stmt, 2, memo.c_str(), memo.size(), NULL);
    sqlite3_bind_int(stmt, 3, locked);
    sqlite3_step(stmt);
    SQLCHECK(sqlite3_finalize(stmt));
  }
  SetLastModified(std::time(0));
}

std::map<std::string, UnspentOutput> NunchukWalletDb::GetCoinsFromTransactions(
    const std::vector<Transaction>& transactions) {
  auto allAddr = GetAllAddressData();
  auto isMyAddress = [&](const std::string& address) {
    return allAddr.count(address);
  };

  auto isMyChange = [&](const std::string& address) {
    return allAddr.count(address) && allAddr.at(address).internal;
  };

  std::map<std::string, Transaction> tx_map;
  std::map<std::string, std::string> used_by;
  for (auto&& tx : transactions) {
    tx_map.insert(std::make_pair(tx.get_txid(), tx));
    if (tx.get_height() <= 0) continue;
    for (auto&& input : tx.get_inputs()) {
      used_by[CoinId(input.first, input.second)] = tx.get_txid();
    }
  }

  std::map<std::string, UnspentOutput> coins;
  auto set_status = [&](const std::string& id, const CoinStatus& status) {
    if (coins[id].get_status() < status) coins[id].set_status(status);
  };

  for (auto&& tx : transactions) {
    if (tx.get_status() == TransactionStatus::REPLACED ||
        tx.get_status() == TransactionStatus::NETWORK_REJECTED)
      continue;

    bool invalid = false;
    for (auto&& input : tx.get_inputs()) {
      auto id = CoinId(input.first, input.second);
      if (id ==
          "0000000000000000000000000000000000000000000000000000000000000000:-1")
        continue;  // coinbase input
      if (used_by.count(id) && used_by[id] != tx.get_txid()) invalid = true;
    }
    if (invalid) continue;

    for (auto&& input : tx.get_inputs()) {
      if (tx_map.count(input.first) == 0) continue;
      auto prev_tx = tx_map[input.first];
      auto address = prev_tx.get_outputs()[input.second].first;
      if (!isMyAddress(address)) continue;
      auto id = CoinId(input.first, input.second);
      coins[id].set_txid(input.first);
      coins[id].set_vout(input.second);
      coins[id].set_address(address);
      coins[id].set_amount(prev_tx.get_outputs()[input.second].second);
      coins[id].set_height(prev_tx.get_height());
      coins[id].set_blocktime(prev_tx.get_blocktime());
      if (tx.get_schedule_time() > coins[id].get_schedule_time()) {
        coins[id].set_schedule_time(tx.get_schedule_time());
      }
      if (tx.get_status() == TransactionStatus::CONFIRMED) {
        set_status(id, CoinStatus::SPENT);
      } else if (tx.get_status() == TransactionStatus::PENDING_CONFIRMATION) {
        set_status(id, CoinStatus::OUTGOING_PENDING_CONFIRMATION);
      } else if (tx.get_status() == TransactionStatus::READY_TO_BROADCAST) {
        set_status(id, CoinStatus::OUTGOING_PENDING_BROADCAST);
      } else if (tx.get_status() == TransactionStatus::PENDING_SIGNATURES) {
        set_status(id, CoinStatus::OUTGOING_PENDING_SIGNATURES);
      } else if (tx.get_status() == TransactionStatus::PENDING_NONCE) {
        set_status(id, CoinStatus::OUTGOING_PENDING_SIGNATURES);
      }
      coins[id].set_memo(prev_tx.get_memo());
      coins[id].set_change(isMyChange(address));
    }

    int nout = tx.get_outputs().size();
    for (int vout = 0; vout < nout; vout++) {
      auto output = tx.get_outputs()[vout];
      if (!isMyAddress(output.first)) continue;
      if (tx.get_height() < 0) continue;
      auto id = CoinId(tx.get_txid(), vout);
      coins[id].set_txid(tx.get_txid());
      coins[id].set_vout(vout);
      coins[id].set_address(output.first);
      coins[id].set_amount(output.second);
      coins[id].set_height(tx.get_height());
      coins[id].set_blocktime(tx.get_blocktime());
      set_status(id, tx.get_height() > 0
                         ? CoinStatus::CONFIRMED
                         : CoinStatus::INCOMING_PENDING_CONFIRMATION);
      coins[id].set_memo(tx.get_memo());
      coins[id].set_change(isMyChange(output.first));
    }
  }
  return coins;
}

std::vector<UnspentOutput> NunchukWalletDb::GetCoins() {
  auto transactions = GetTransactions();
  auto coins = GetCoinsFromTransactions(transactions);
  std::vector<UnspentOutput> rs;
  for (auto&& coin : coins) {
    rs.push_back(coin.second);
  }
  return rs;
}

std::vector<std::vector<UnspentOutput>> NunchukWalletDb::GetAncestry(
    const std::string& tx_id, int vout) {
  auto transactions = GetTransactions();
  auto coins = GetCoinsFromTransactions(transactions);
  std::map<std::string, Transaction> tx_map;
  for (auto&& tx : transactions) {
    tx_map.insert(std::make_pair(tx.get_txid(), tx));
  }

  std::vector<std::vector<UnspentOutput>> ancestry{};
  std::vector<UnspentOutput> parents{};
  parents.push_back(coins[CoinId(tx_id, vout)]);
  while (true) {
    std::vector<UnspentOutput> grandparents{};
    for (auto&& coin : parents) {
      if (tx_map.count(coin.get_txid()) == 0) continue;
      auto tx = tx_map[coin.get_txid()];
      for (auto&& input : tx.get_inputs()) {
        auto id = CoinId(input.first, input.second);
        if (coins.count(id)) grandparents.push_back(coins[id]);
      }
    }
    if (grandparents.empty()) {
      break;
    } else {
      ancestry.push_back(grandparents);
      parents = grandparents;
    }
  }

  return ancestry;
}

void NunchukWalletDb::AutoAddNewCoins(const Transaction& tx) {
  std::vector<int> my_vout{};
  for (size_t i = 0; i < tx.get_outputs().size(); i++) {
    if (IsMyAddress(tx.get_outputs()[i].first)) my_vout.push_back(i);
  }

  auto auto_add = GetAutoAddData();
  for (auto&& [col_tag, is_auto_add] : auto_add) {
    if (is_auto_add && col_tag.second < 0) {
      for (auto&& vout : my_vout) {
        AddToCoinCollection(col_tag.first, tx.get_txid(), vout, false);
      }
    }
  }
}

time_t NunchukWalletDb::GetLastModified() const {
  return GetInt(DbKeys::SYNC_TS);
}

bool NunchukWalletDb::SetLastModified(time_t value) {
  return PutInt(DbKeys::SYNC_TS, value);
}

Transaction NunchukWalletDb::ImportDummyTx(
    const std::string& id, const std::string& body,
    const std::vector<std::string>& tokens) {
  auto wallet = GetWallet(true, true);
  std::string psbt = Utils::GetHealthCheckDummyTx(wallet, body);

  sqlite3_stmt* stmt;
  std::string sql =
      "INSERT INTO DUMMYTX(ID, PSBT, STOKEN, LTOKEN)"
      "VALUES (?1, ?2, ?3, '')"
      "ON CONFLICT(ID) DO UPDATE SET STOKEN=excluded.STOKEN;";
  std::string stoken = join(tokens, ',');
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, id.c_str(), id.size(), NULL);
  sqlite3_bind_text(stmt, 2, psbt.c_str(), psbt.size(), NULL);
  sqlite3_bind_text(stmt, 3, stoken.c_str(), stoken.size(), NULL);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
  return GetDummyTx(id);
}

RequestTokens NunchukWalletDb::SaveDummyTxRequestToken(
    const std::string& id, const std::string& token) {
  auto wallet = GetWallet(true, true);
  std::vector<std::string> local_tokens{};
  {
    sqlite3_stmt* stmt;
    std::string sql = "SELECT * FROM DUMMYTX WHERE ID = ?;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, id.c_str(), id.size(), NULL);
    sqlite3_step(stmt);
    std::map<std::string, bool> rs;
    if (sqlite3_column_text(stmt, 0)) {
      std::string psbt = std::string((char*)sqlite3_column_text(stmt, 1));
      std::string ltoken = std::string((char*)sqlite3_column_text(stmt, 3));
      local_tokens = split(ltoken, ',');
      SQLCHECK(sqlite3_finalize(stmt));

      // Verify token
      if (wallet.get_address_type() == AddressType::NATIVE_SEGWIT) {
        auto dummyPsbt = DecodePsbt(psbt);
        PSBTInput& input = dummyPsbt.inputs[0];
        auto amountIn = input.witness_utxo.nValue;
        CScript scriptCode = input.witness_script;
        const CMutableTransaction& tx = *dummyPsbt.tx;
        MutableTransactionSignatureCreator creator(tx, 0, amountIn,
                                                   SIGHASH_DEFAULT);

        auto pair = split(token, '.');
        for (const auto& key : input.hd_keypaths) {
          if (HexStr(key.second.fingerprint) != pair[0]) continue;
          if (!creator.Checker().CheckECDSASignature(
                  ParseHex(pair[1]),
                  {key.first.data(), key.first.data() + key.first.size()},
                  scriptCode, SigVersion::WITNESS_V0)) {
            throw NunchukException(NunchukException::INVALID_SIGNATURE,
                                   "Invalid signature!");
          }
        }
      }
    } else {
      SQLCHECK(sqlite3_finalize(stmt));
      throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
    }
  }
  local_tokens.push_back(token);

  sqlite3_stmt* stmt;
  std::string sql = "UPDATE DUMMYTX SET LTOKEN=?1 WHERE ID = ?2;";
  std::string ltoken = join(local_tokens, ',');
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, ltoken.c_str(), ltoken.size(), NULL);
  sqlite3_bind_text(stmt, 2, id.c_str(), id.size(), NULL);
  sqlite3_step(stmt);
  SQLCHECK(sqlite3_finalize(stmt));
  return GetDummyTxRequestToken(id);
}

bool NunchukWalletDb::DeleteDummyTx(const std::string& id) {
  sqlite3_stmt* stmt;
  std::string sql = "DELETE FROM DUMMYTX WHERE ID = ?;";
  sqlite3_prepare(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, id.c_str(), id.size(), NULL);
  sqlite3_step(stmt);
  bool updated = (sqlite3_changes(db_) == 1);
  SQLCHECK(sqlite3_finalize(stmt));
  return updated;
}

RequestTokens NunchukWalletDb::GetDummyTxRequestToken(const std::string& id) {
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM DUMMYTX WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, id.c_str(), id.size(), NULL);
  sqlite3_step(stmt);
  std::map<std::string, bool> rs;
  if (sqlite3_column_text(stmt, 0)) {
    std::string stoken = std::string((char*)sqlite3_column_text(stmt, 2));
    std::string ltoken = std::string((char*)sqlite3_column_text(stmt, 3));
    auto server_tokens = split(stoken, ',');
    auto local_tokens = split(ltoken, ',');
    for (auto&& token : local_tokens) rs[token] = false;
    for (auto&& token : server_tokens) rs[token] = true;
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

std::map<std::string, Transaction> NunchukWalletDb::GetDummyTxs() {
  auto wallet = GetWallet(true, true);
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM DUMMYTX;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  std::map<std::string, Transaction> rs;
  while (sqlite3_column_text(stmt, 0)) {
    std::string id = std::string((char*)sqlite3_column_text(stmt, 0));
    std::string psbt = std::string((char*)sqlite3_column_text(stmt, 1));
    std::string stoken = std::string((char*)sqlite3_column_text(stmt, 2));
    std::string ltoken = std::string((char*)sqlite3_column_text(stmt, 3));

    auto tx =
        GetTransactionFromPartiallySignedTransaction(DecodePsbt(psbt), wallet);
    tx.set_fee(150);
    tx.set_sub_amount(10000);
    tx.set_change_index(-1);
    tx.set_subtract_fee_from_amount(false);
    tx.set_psbt(psbt);
    tx.set_receive(false);
    auto server_tokens = split(stoken, ',');
    auto local_tokens = split(ltoken, ',');
    for (auto&& token : server_tokens) {
      auto pair = split(token, '.');
      tx.set_signer(pair[0], true);
    }
    for (auto&& token : local_tokens) {
      auto pair = split(token, '.');
      tx.set_signer(pair[0], true);
    }
    rs.insert({id, tx});
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

Transaction NunchukWalletDb::GetDummyTx(const std::string& id) {
  auto wallet = GetWallet(true, true);
  sqlite3_stmt* stmt;
  std::string sql = "SELECT * FROM DUMMYTX WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, id.c_str(), id.size(), NULL);
  sqlite3_step(stmt);
  std::map<std::string, bool> rs;
  if (sqlite3_column_text(stmt, 0)) {
    std::string psbt = std::string((char*)sqlite3_column_text(stmt, 1));
    std::string stoken = std::string((char*)sqlite3_column_text(stmt, 2));
    std::string ltoken = std::string((char*)sqlite3_column_text(stmt, 3));

    auto tx =
        GetTransactionFromPartiallySignedTransaction(DecodePsbt(psbt), wallet);
    tx.set_fee(150);
    tx.set_sub_amount(10000);
    tx.set_change_index(-1);
    tx.set_subtract_fee_from_amount(false);
    tx.set_psbt(psbt);
    tx.set_receive(false);
    auto server_tokens = split(stoken, ',');
    auto local_tokens = split(ltoken, ',');
    for (auto&& token : server_tokens) {
      auto pair = split(token, '.');
      tx.set_signer(pair[0], true);
    }
    for (auto&& token : local_tokens) {
      auto pair = split(token, '.');
      tx.set_signer(pair[0], true);
    }
    SQLCHECK(sqlite3_finalize(stmt));
    return tx;
  } else {
    SQLCHECK(sqlite3_finalize(stmt));
    throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
  }
}

std::string NunchukWalletDb::GetMiniscript() {
  return GetString(DbKeys::MINISCRIPT);
}

}  // namespace nunchuk
