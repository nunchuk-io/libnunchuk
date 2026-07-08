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
#include <regex>
#include <sstream>
#include "storage/common.h"

#include <univalue.h>
#include <rpc/util.h>
#include <policy/policy.h>
#include <signingprovider.h>

#include <base58.h>
#include <util/strencodings.h>
#include <util/bip32.h>
#include <liquid/wallysigner.hpp>
#include <liquid/wallyutils.hpp>

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

void NunchukWalletDb::SetWallySigner(
    std::shared_ptr<wally::WallySigner> signer) {
  wally_signer_ = std::move(signer);
  if (!wally_signer_ || !IsSupportLiquid()) return;
  // The new signer instance starts with an empty script-pubkey cache. Re-derive
  // the wallet's external/internal addresses up to the current index plus the
  // gap limit so it can recognize wallet outputs immediately. We skip the
  // signing-provider path (skip_provider=true) to avoid recursing back into
  // GetAllAddressData which can short-circuit on the static cache.
  try {
    auto wallet = GetWallet(/*skip_balance=*/true, /*skip_provider=*/true);
    if (wallet.get_wallet_type() != WalletType::LIQUID) return;
    const std::string path = wallet.get_signers()[0].get_derivation_path();
    const int gap = wallet.get_gap_limit();
    int internal_end = GetCurrentAddressIndex(true) + gap;
    int external_end = GetCurrentAddressIndex(false) + gap;
    if (internal_end > 0) {
      wally_signer_->CacheAddresses(path, 0, internal_end, /*is_change=*/true);
    }
    if (external_end > 0) {
      wally_signer_->CacheAddresses(path, 0, external_end, /*is_change=*/false);
    }
  } catch (...) {
    // Best-effort: callers that need addresses will trigger GetAllAddressData
    // which can still populate the cache lazily.
  }
}

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
  json basic_data = {
      {"xpub", signer.get_xpub()},
      {"public_key", signer.get_public_key()},
      {"derivation_path", signer.get_derivation_path()},
      {"external_internal_index", signer.get_external_internal_index()},
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
    wallet = Wallet(GetMiniscript(), GetSigners(), address_type, m);
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
  if (!skip_provider && wallet.get_wallet_type() == WalletType::LIQUID) {
    GetAllAddressData(true);
  } else if (!skip_provider) {
    GetAllAddressData(false);  // update range to max address index
    auto desc = GetDescriptorsImportString(wallet);
    SigningProviderCache::getInstance().PreCalculate(desc);
    // workaround for GetTransactionFromPartiallySignedTransaction bug
    auto txs = GetTransactions();
    for (auto&& tx : txs) {
      for (auto&& output : tx.get_outputs()) UseAddress(output.address);
    }
    try {
      sqlite3_stmt* stmt;
      std::string sql = std::string("SELECT ADDR FROM ") + AddressTable() +
                        " WHERE USED = 1;";
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
    auto asset_balances = GetAssetBalances();
    for (auto&& asset_balance : asset_balances) {
      wallet.set_asset_balance(asset_balance.first, asset_balance.second);
    }
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
    std::pair<int, int> external_internal_index = {0, 1};
    if (basic_info["external_internal_index"] != nullptr) {
      external_internal_index = basic_info["external_internal_index"];
    }
    ba::to_lower(master_fingerprint);
    time_t last_health_check = sqlite3_column_int64(stmt, 3);
    SingleSigner signer(name, xpub, public_key, derivation_path,
                        external_internal_index, master_fingerprint,
                        last_health_check, master_id, false,
                        SignerType::UNKNOWN);
    signers.push_back(signer);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  signer_cache_[db_file_name_] = signers;
  return signers;
}

const char* NunchukWalletDb::TxTable() const { return "VTX"; }

const char* NunchukWalletDb::AddressTable() const { return "ADDRESS"; }

void NunchukWalletDb::SetAddress(const std::string& address, int index,
                                 bool internal, const std::string& utxos) {
  if (address.empty()) return;
  sqlite3_stmt* stmt;
  std::string sql = std::string("INSERT INTO ") + AddressTable() +
                    "(ADDR, IDX, INTERNAL, USED, UTXO)"
                    "VALUES (?1, ?2, ?3, ?4, ?5)"
                    "ON CONFLICT(ADDR) DO UPDATE SET USED=excluded.USED, "
                    "UTXO=excluded.UTXO;";
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
  if (address.empty()) return false;
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
    auto eii = signer.get_external_internal_index();
    path << "m" << FormalizePath(signer.get_derivation_path()) << "/"
         << (internal ? eii.second : eii.first) << "/" << index;
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

std::string NunchukWalletDb::GetAddressPath(const std::string& address,
                                            const SingleSigner& signer) {
  auto all = GetAllAddressData();
  if (!all.count(address)) {
    throw StorageException(StorageException::ADDRESS_NOT_FOUND,
                           "Address not found!");
  }

  const auto signer_key = GetSingleSignerKey(signer);
  for (auto&& wallet_signer : GetSigners()) {
    if (GetSingleSignerKey(wallet_signer) != signer_key) continue;

    const auto data = all.at(address);
    auto eii = wallet_signer.get_external_internal_index();
    std::stringstream path;
    path << "m" << FormalizePath(wallet_signer.get_derivation_path()) << "/"
         << (data.internal ? eii.second : eii.first) << "/" << data.index;
    return path.str();
  }

  throw StorageException(StorageException::SIGNER_NOT_FOUND,
                         "Signer not found!");
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
  } else if (wallet.get_wallet_type() == WalletType::LIQUID) {
    if (!wally_signer_) {
      throw NunchukException(
          NunchukException::INVALID_PARAMETER,
          "Liquid wallet signer is not available (unlock signer passphrase "
          "before opening the wallet)");
    }
    std::string path = wallet.get_signers()[0].get_derivation_path();
    int index = GetCurrentAddressIndex(true) + wallet.get_gap_limit();
    auto internal_addr = wally_signer_->CacheAddresses(path, 0, index, true);
    for (auto&& addr : internal_addr) {
      addresses[addr.address] = {addr.address, int(addr.index), true, false};
    }
    SigningProviderCache::getInstance().SetMaxIndex(id_, index);
    index = GetCurrentAddressIndex(false) + wallet.get_gap_limit();
    auto external_addr = wally_signer_->CacheAddresses(path, 0, index, false);
    for (auto&& addr : external_addr) {
      addresses[addr.address] = {addr.address, int(addr.index), false, false};
    }
    SigningProviderCache::getInstance().SetMaxIndex(id_, index);
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
      for (auto&& output : tx.get_outputs()) UseAddress(output.address);
    }
    try {
      sqlite3_stmt* stmt;
      std::string sql = std::string("SELECT ADDR FROM ") + AddressTable() +
                        " WHERE USED = 1;";
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

std::pair<int, bool> NunchukWalletDb::GetAddressIndex(
    const std::string& address) {
  auto all = GetAllAddressData();
  if (all.count(address))
    return {all.at(address).index, all.at(address).internal};
  return {-1, false};
}

Amount NunchukWalletDb::GetAddressBalance(const std::string& address) {
  if (IsSupportLiquid()) {
    return 0;
  }
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

std::map<AssetId, Amount> NunchukWalletDb::GetAddressAssets(
    const std::string& address) {
  if (!IsSupportLiquid()) {
    return {};
  }

  std::vector<std::string> txs = GetVtxValues();
  std::vector<wally::LiquidUtxos> utxos{};
  for (auto&& tx : txs) {
    utxos.push_back(wally_signer_->GetUtxosFromTx(tx, address));
  }

  std::set<std::pair<std::vector<unsigned char>, uint32_t>> spent_utxos;
  for (auto&& utxo : utxos) {
    for (size_t i = 0; i < utxo.vins_tx_id.size(); i++) {
      spent_utxos.insert({utxo.vins_tx_id[i], utxo.vins_vout[i]});
    }
  }

  std::map<AssetId, Amount> asset_balances{};
  for (auto&& utxo : utxos) {
    for (size_t i = 0; i < utxo.values_in.size(); i++) {
      if (spent_utxos.count({utxo.tx_id, utxo.vouts_in[i]})) continue;
      AssetId asset_id(utxo.asset_ids_in.begin() + i * 32,
                       utxo.asset_ids_in.begin() + i * 32 + 32);
      Amount amount(utxo.values_in[i]);
      asset_balances[asset_id] += amount;
    }
  }
  return asset_balances;
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
  std::string sql = std::string("SELECT UTXO FROM ") + AddressTable() +
                    " WHERE ADDR = ? AND UTXO IS NOT NULL;";
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
  std::string sql = std::string("SELECT MAX(IDX) FROM ") + AddressTable() +
                    " WHERE INTERNAL = ? GROUP BY INTERNAL";
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
      std::string("INSERT INTO ") + TxTable() +
      "(ID, VALUE, HEIGHT, FEE, MEMO, CHANGEPOS, BLOCKTIME, EXTRA)"
      "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '')"
      "ON CONFLICT(ID) DO UPDATE SET VALUE=excluded.VALUE, "
      "HEIGHT=excluded.HEIGHT;";
  std::string tx_id = IsSupportLiquid()
                          ? wally::WallyUtils::GetTxid(raw_tx)
                          : DecodeRawTransaction(raw_tx).GetHash().GetHex();
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
  std::string select_sql =
      std::string("SELECT EXTRA FROM ") + TxTable() + " WHERE ID = ?;";
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
    std::string update_sql =
        std::string("UPDATE ") + TxTable() + " SET EXTRA = ?1 WHERE ID = ?2;";
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
    auto tx = GetTransactionFromVtxValue(raw_tx, wallet, -1);
    std::string tx_id = tx.get_txid();

    sqlite3_stmt* stmt;
    std::string sql = std::string("SELECT EXTRA FROM ") + TxTable() +
                      " WHERE ID = ? AND HEIGHT = -1;";
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

    sql = extra.empty() ? (std::string("UPDATE ") + TxTable() +
                           " SET VALUE = ?1 WHERE ID = ?2;")
                        : (std::string("UPDATE ") + TxTable() +
                           " SET VALUE = ?1, EXTRA = ?3 WHERE ID = ?2;");
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

  std::string tx_id = IsSupportLiquid()
                          ? wally::WallyUtils::GetTxid(raw_tx)
                          : DecodeRawTransaction(raw_tx).GetHash().GetHex();

  std::string extra = "";
  if (height <= 0) {
    // Persist signers to extra if the psbt existed
    sqlite3_stmt* stmt;
    std::string sql = std::string("SELECT VALUE, EXTRA FROM ") + TxTable() +
                      " WHERE ID = ? AND HEIGHT = -1;";
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
    sqlite3_step(stmt);
    if (sqlite3_column_text(stmt, 1)) {
      std::string value = std::string((char*)sqlite3_column_text(stmt, 0));
      extra = std::string((char*)sqlite3_column_text(stmt, 1));
      auto tx = GetTransactionFromVtxValue(value, wallet, -1);

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
      extra.empty()
          ? (std::string("UPDATE ") + TxTable() +
             " SET VALUE = ?1, HEIGHT = ?2, BLOCKTIME = ?3 WHERE ID = ?4;")
          : (std::string("UPDATE ") + TxTable() +
             " SET VALUE = ?1, HEIGHT = ?2, BLOCKTIME = ?3, EXTRA = ?5 WHERE "
             "ID = ?4;");
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
  std::string select_sql =
      std::string("SELECT EXTRA FROM ") + TxTable() + " WHERE ID = ?;";
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
    std::string update_sql =
        std::string("UPDATE ") + TxTable() + " SET EXTRA = ?1 WHERE ID = ?2;";
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
  if (IsSupportLiquid()) {
    throw NunchukException(NunchukException::INVALID_WALLET_TYPE,
                           "Liquid wallet is not supported psbt creation");
  }
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
      std::string("INSERT INTO ") + TxTable() +
      "(ID, VALUE, HEIGHT, FEE, MEMO, CHANGEPOS, BLOCKTIME, EXTRA)"
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

void NunchukWalletDb::PrepareLiquidTransaction(
    const std::map<AssetId, std::map<std::string, Amount>>& outputs,
    Amount fee_rate, bool allow_insufficient_lbtc, bool subtract_fee_from_amount,
    std::string* unsigned_hex, uint64_t& fee_sats) {
  if (!IsSupportLiquid() || !wally_signer_) {
    throw NunchukException(NunchukException::INVALID_WALLET_TYPE,
                           "Wallet is not a Liquid wallet");
  }
  if (outputs.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "outputs must be non-empty");
  }
  if (fee_rate <= 0) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "fee_rate must be > 0 sat/kvB");
  }

  const AssetId LBTC = wally::WallyUtils::C().LBTC_ASSET_ID;

  // 1) Per-asset targets and destination map for wally::WallySigner::CreateTx.
  std::map<AssetId, Amount> targets;
  wally::WallySigner::AssetDestinations destinations;
  for (const auto& [aid, dest_map] : outputs) {
    if (aid.size() != 32) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid asset id (must be 32 bytes)");
    }
    Amount sum = 0;
    for (const auto& [addr, amount] : dest_map) {
      if (!Utils::IsLiquidAddress(addr)) {
        throw NunchukException(NunchukException::INVALID_PARAMETER,
                               "Invalid liquid address");
      }
      if (amount <= 0) {
        throw NunchukException(NunchukException::INVALID_PARAMETER,
                               "Output amount must be > 0");
      }
      destinations[aid][addr] = static_cast<uint64_t>(amount);
      sum += amount;
    }
    targets[aid] = sum;
  }
  if (!targets.count(LBTC)) targets[LBTC] = 0;  // still needed to pay fee

  // 2) Load all known transactions and unblind their outputs that belong to
  // this wallet. Each call returns one LiquidUtxos per source tx that contains
  // every wallet-owned output of that tx (multi-asset capable).
  std::vector<std::string> tx_hexes = GetVtxValues();
  std::vector<wally::LiquidUtxos> per_tx_utxos;
  per_tx_utxos.reserve(tx_hexes.size());
  for (const auto& hex : tx_hexes) {
    per_tx_utxos.push_back(wally_signer_->GetUtxosFromTx(hex));
  }

  // 3) Compute the set of spent outpoints by scanning inputs of every known tx.
  std::set<std::pair<std::vector<unsigned char>, uint32_t>> spent;
  for (const auto& u : per_tx_utxos) {
    for (size_t i = 0; i < u.vins_tx_id.size(); ++i) {
      spent.insert({u.vins_tx_id[i], u.vins_vout[i]});
    }
  }

  // 4) Flatten available coins (txIdx, k) for greedy selection.
  struct Coin {
    size_t tx_idx;
    size_t k;
    AssetId asset_id;
    Amount value;
  };
  std::vector<Coin> coins;
  for (size_t t = 0; t < per_tx_utxos.size(); ++t) {
    const auto& u = per_tx_utxos[t];
    for (size_t k = 0; k < u.vouts_in.size(); ++k) {
      if (spent.count({u.tx_id, u.vouts_in[k]})) continue;
      AssetId aid(u.asset_ids_in.begin() + k * 32,
                  u.asset_ids_in.begin() + (k + 1) * 32);
      coins.push_back({t, k, std::move(aid), Amount(u.values_in[k])});
    }
  }

  std::map<AssetId, std::vector<size_t>> coins_by_asset;
  for (size_t i = 0; i < coins.size(); ++i) {
    coins_by_asset[coins[i].asset_id].push_back(i);
  }
  for (auto& [_, v] : coins_by_asset) {
    std::sort(v.begin(), v.end(), [&](size_t a, size_t b) {
      return coins[a].value > coins[b].value;  // largest-first
    });
  }

  // 5) Change address: prefer an unused internal address already tracked by
  // the wallet; otherwise derive a fresh one via the WallySigner.
  std::string change_addr;
  {
    auto unused_internal = GetAddresses(/*used=*/false, /*internal=*/true);
    if (!unused_internal.empty()) {
      change_addr = unused_internal.front();
    } else {
      auto wallet_dto =
          GetWallet(/*skip_balance=*/true, /*skip_provider=*/true);
      const std::string path =
          wallet_dto.get_signers()[0].get_derivation_path();
      int idx = GetCurrentAddressIndex(/*internal=*/true) + 1;
      if (idx < 0) idx = 0;
      auto fresh = wally_signer_->CacheAddresses(
          path, static_cast<uint32_t>(idx), static_cast<uint32_t>(idx + 1),
          /*is_change=*/true);
      if (fresh.empty()) {
        throw NunchukException(
            NunchukException::INVALID_ADDRESS,
            "Failed to derive a fresh internal Liquid change address");
      }
      change_addr = fresh.front().address;
    }
  }

  // 6) Helpers.
  auto select_for_asset = [&](const AssetId& aid,
                              Amount needed) -> std::vector<size_t> {
    std::vector<size_t> picked;
    auto it = coins_by_asset.find(aid);
    if (it == coins_by_asset.end()) {
      if (needed > 0) {
        throw NunchukException(NunchukException::COIN_SELECTION_ERROR,
                               "No UTXOs available for an asset");
      }
      return picked;
    }
    Amount accum = 0;
    for (auto ci : it->second) {
      picked.push_back(ci);
      accum += coins[ci].value;
      if (accum >= needed) break;
    }
    if (accum < needed) {
      throw NunchukException(NunchukException::COIN_SELECTION_ERROR,
                             "Insufficient balance for an asset");
    }
    return picked;
  };

  auto build_inputs = [&](const std::vector<size_t>& selected_idx) {
    std::map<size_t, std::vector<size_t>> by_src;
    for (auto ci : selected_idx) {
      by_src[coins[ci].tx_idx].push_back(coins[ci].k);
    }
    std::vector<wally::LiquidUtxos> rs;
    rs.reserve(by_src.size());
    for (auto& [src, k_list] : by_src) {
      std::sort(k_list.begin(), k_list.end());
      const auto& s = per_tx_utxos[src];
      wally::LiquidUtxos picked;
      picked.tx_id = s.tx_id;
      picked.vins_tx_id = s.vins_tx_id;
      picked.vins_vout = s.vins_vout;
      for (auto k : k_list) {
        picked.asset_generators_in.insert(
            picked.asset_generators_in.end(),
            s.asset_generators_in.begin() + k * ASSET_GENERATOR_LEN,
            s.asset_generators_in.begin() + (k + 1) * ASSET_GENERATOR_LEN);
        picked.asset_ids_in.insert(picked.asset_ids_in.end(),
                                   s.asset_ids_in.begin() + k * 32,
                                   s.asset_ids_in.begin() + (k + 1) * 32);
        picked.values_in.push_back(s.values_in[k]);
        picked.abfs_in.insert(picked.abfs_in.end(), s.abfs_in.begin() + k * 32,
                              s.abfs_in.begin() + (k + 1) * 32);
        picked.vbfs_in.insert(picked.vbfs_in.end(), s.vbfs_in.begin() + k * 32,
                              s.vbfs_in.begin() + (k + 1) * 32);
        picked.script_pubkeys_in.push_back(s.script_pubkeys_in[k]);
        picked.value_commitments_in.push_back(s.value_commitments_in[k]);
        picked.vouts_in.push_back(s.vouts_in[k]);
      }
      rs.push_back(std::move(picked));
    }
    return rs;
  };

  auto select_non_lbtc = [&]() {
    std::vector<size_t> picked;
    for (const auto& [aid, target] : targets) {
      if (aid == LBTC) continue;
      auto sel = select_for_asset(aid, target);
      picked.insert(picked.end(), sel.begin(), sel.end());
    }
    return picked;
  };

  auto total_lbtc_balance = [&]() -> Amount {
    auto it = coins_by_asset.find(LBTC);
    if (it == coins_by_asset.end()) return 0;
    Amount sum = 0;
    for (auto ci : it->second) sum += coins[ci].value;
    return sum;
  };

  auto append_inputs = [](std::vector<wally::LiquidUtxos>& dst,
                          const std::vector<wally::LiquidUtxos>& extra) {
    dst.insert(dst.end(), extra.begin(), extra.end());
  };

  struct FeeInputs {
    uint64_t fee_sats;
    std::vector<wally::LiquidUtxos> inputs;
  };

  const auto non_lbtc_selected = select_non_lbtc();

  auto compute_trial_fee =
      [&](const std::vector<wally::LiquidUtxos>& dummies) -> uint64_t {
    auto lbtc_it = coins_by_asset.find(LBTC);
    std::vector<size_t> trial = non_lbtc_selected;
    if (lbtc_it != coins_by_asset.end()) {
      trial.insert(trial.end(), lbtc_it->second.begin(), lbtc_it->second.end());
    }
    auto trial_inputs = build_inputs(trial);
    append_inputs(trial_inputs, dummies);
    const size_t vsize = wally_signer_->EstimateSignedVsize(
        trial_inputs, destinations, change_addr);
    return wally::WallySigner::FeeSatsFromVsizeAndKvBRate(
        vsize, static_cast<uint64_t>(fee_rate));
  };

  auto compute_fee_and_inputs =
      [&](const std::vector<size_t>& non_lbtc_selected,
          const std::vector<wally::LiquidUtxos>& estimate_dummies)
      -> FeeInputs {
    auto lbtc_it = coins_by_asset.find(LBTC);
    if (lbtc_it == coins_by_asset.end() && estimate_dummies.empty()) {
      throw NunchukException(NunchukException::COIN_SELECTION_ERROR,
                             "No LBTC UTXOs available to pay fee");
    }

    uint64_t feeSats = compute_trial_fee(estimate_dummies);

    std::vector<size_t> lbtc_sel;
    try {
      lbtc_sel =
          select_for_asset(LBTC, targets[LBTC] + static_cast<Amount>(feeSats));
    } catch (const NunchukException& e) {
      if (e.code() != NunchukException::COIN_SELECTION_ERROR ||
          estimate_dummies.empty()) {
        throw;
      }
      // Estimate with dummy fee input: real LBTC covers destinations only.
      lbtc_sel = select_for_asset(LBTC, targets[LBTC]);
    }
    auto with_lbtc = [&]() {
      std::vector<size_t> all = non_lbtc_selected;
      all.insert(all.end(), lbtc_sel.begin(), lbtc_sel.end());
      return all;
    };
    auto final_inputs = build_inputs(with_lbtc());
    append_inputs(final_inputs, estimate_dummies);
    {
      size_t vsize = wally_signer_->EstimateSignedVsize(
          final_inputs, destinations, change_addr, feeSats);
      uint64_t refined = wally::WallySigner::FeeSatsFromVsizeAndKvBRate(
          vsize, static_cast<uint64_t>(fee_rate));
      if (refined > feeSats) {
        try {
          lbtc_sel = select_for_asset(LBTC, targets[LBTC] +
                                              static_cast<Amount>(refined));
        } catch (const NunchukException& e) {
          if (e.code() != NunchukException::COIN_SELECTION_ERROR ||
              estimate_dummies.empty()) {
            throw;
          }
          lbtc_sel = select_for_asset(LBTC, targets[LBTC]);
        }
        final_inputs = build_inputs(with_lbtc());
        append_inputs(final_inputs, estimate_dummies);
      }
      feeSats = refined;
    }
    return {feeSats, std::move(final_inputs)};
  };

  auto apply_subtract_fee_lbtc_dests =
      [&](wally::WallySigner::AssetDestinations& dests, uint64_t gross_balance,
          uint64_t fee_sats) {
        if (fee_sats >= gross_balance) {
          throw NunchukException(NunchukException::COIN_SELECTION_ERROR,
                                 "Insufficient balance for an asset");
        }
        const uint64_t net = gross_balance - fee_sats;
        auto& lbtc_dests = dests[LBTC];
        uint64_t dest_sum = 0;
        for (const auto& [addr, amt] : lbtc_dests) dest_sum += amt;
        if (dest_sum == 0) {
          throw NunchukException(NunchukException::INVALID_PARAMETER,
                                 "LBTC destination amount must be > 0");
        }
        for (auto& [addr, amt] : lbtc_dests) {
          amt = (amt * net) / dest_sum;
        }
        uint64_t new_sum = 0;
        for (const auto& [addr, amt] : lbtc_dests) new_sum += amt;
        if (new_sum < net) {
          lbtc_dests.begin()->second += net - new_sum;
        }
      };

  if (subtract_fee_from_amount && targets[LBTC] > 0) {
    const Amount gross_balance = total_lbtc_balance();
    if (gross_balance <= 0) {
      throw NunchukException(NunchukException::COIN_SELECTION_ERROR,
                             "No LBTC UTXOs available to pay fee");
    }
    auto lbtc_it = coins_by_asset.find(LBTC);
    std::vector<size_t> selected = non_lbtc_selected;
    selected.insert(selected.end(), lbtc_it->second.begin(),
                    lbtc_it->second.end());
    auto inputs = build_inputs(selected);

    wally::WallySigner::AssetDestinations sweep_dests = destinations;
    uint64_t feeSats = 1;
    for (int iter = 0; iter < 20; ++iter) {
      apply_subtract_fee_lbtc_dests(
          sweep_dests, static_cast<uint64_t>(gross_balance), feeSats);
      const size_t vsize = wally_signer_->EstimateSignedVsize(
          inputs, sweep_dests, change_addr, feeSats);
      const uint64_t refined =
          wally::WallySigner::FeeSatsFromVsizeAndKvBRate(
              vsize, static_cast<uint64_t>(fee_rate));
      if (refined == feeSats) {
        fee_sats = feeSats;
        if (unsigned_hex != nullptr) {
          *unsigned_hex = wally_signer_->CreateTx(inputs, sweep_dests,
                                                  change_addr, feeSats);
        }
        return;
      }
      feeSats = refined;
    }
    fee_sats = feeSats;
    if (unsigned_hex != nullptr) {
      apply_subtract_fee_lbtc_dests(
          sweep_dests, static_cast<uint64_t>(gross_balance), feeSats);
      *unsigned_hex = wally_signer_->CreateTx(inputs, sweep_dests, change_addr,
                                              feeSats);
    }
    return;
  }

  if (!allow_insufficient_lbtc) {
    auto result = compute_fee_and_inputs(non_lbtc_selected, {});
    fee_sats = result.fee_sats;
    if (unsigned_hex != nullptr) {
      *unsigned_hex = wally_signer_->CreateTx(result.inputs, destinations,
                                              change_addr, result.fee_sats);
    }
    return;
  }

  // Estimate: destinations must be covered by real LBTC. When LBTC cannot also
  // pay the fee, size the tx with one high-value dummy input (users typically
  // top up more than the bare minimum fee anyway).
  if (total_lbtc_balance() < targets[LBTC]) {
    throw NunchukException(NunchukException::COIN_SELECTION_ERROR,
                           "Insufficient balance for an asset");
  }

  constexpr uint64_t kEstimateDummyLbtcSats = 10000;

  try {
    fee_sats = compute_fee_and_inputs(non_lbtc_selected, {}).fee_sats;
    return;
  } catch (const NunchukException& e) {
    if (e.code() != NunchukException::COIN_SELECTION_ERROR) throw;
  } catch (const std::runtime_error&) {
  }

  fee_sats = compute_fee_and_inputs(
                 non_lbtc_selected,
                 {wally_signer_->MakeDummyLbtcUtxo(kEstimateDummyLbtcSats)})
                 .fee_sats;
}

Amount NunchukWalletDb::EstimateFeeForLiquidTransaction(
    const std::map<AssetId, std::map<std::string, Amount>>& outputs,
    Amount fee_rate, bool subtract_fee_from_amount) {
  uint64_t fee_sats = 0;
  PrepareLiquidTransaction(outputs, fee_rate, /*allow_insufficient_lbtc=*/true,
                           subtract_fee_from_amount, /*unsigned_hex=*/nullptr,
                           fee_sats);
  return static_cast<Amount>(fee_sats);
}

Transaction NunchukWalletDb::CreateLiquidTransaction(
    const std::map<AssetId, std::map<std::string, Amount>>& outputs,
    Amount fee_rate, const std::string& memo, bool persist,
    bool subtract_fee_from_amount) {
  std::string unsigned_hex;
  uint64_t fee_sats = 0;
  PrepareLiquidTransaction(outputs, fee_rate, /*allow_insufficient_lbtc=*/false,
                           subtract_fee_from_amount, &unsigned_hex, fee_sats);
  const size_t signed_vsize =
      wally::WallySigner::ComputeSignedVsize(unsigned_hex);

  // Persist (optional). When `persist` is false (draft), reconstruct a
  // Transaction object from the unsigned hex without touching the DB.
  Transaction tx;
  if (persist) {
    tx = InsertTransaction(unsigned_hex, /*height=*/-1, /*blocktime=*/0,
                           /*fee=*/Amount(fee_sats), memo, /*change_pos=*/-1);
  } else {
    tx = wally_signer_->GetTransactionFromTx(unsigned_hex, /*height=*/-1);
    tx.set_m(1);
    tx.set_wallet_type(WalletType::LIQUID);
    tx.set_address_type(AddressType::NATIVE_SEGWIT);
  }
  tx.set_fee(Amount(fee_sats));
  tx.set_fee_rate(fee_rate);
  tx.set_vsize(static_cast<int>(signed_vsize));
  tx.set_status(TransactionStatus::PENDING_SIGNATURES);
  tx.set_subtract_fee_from_amount(false);
  tx.set_receive(false);
  tx.set_sub_amount(0);
  tx.set_signer(wally_signer_->GetMasterFingerprint(), false);
  if (!memo.empty()) tx.set_memo(memo);
  return tx;
}

Transaction NunchukWalletDb::SignLiquidTransaction(const std::string& tx_id) {
  if (!IsSupportLiquid() || !wally_signer_) {
    throw NunchukException(NunchukException::INVALID_WALLET_TYPE,
                           "Wallet is not a Liquid wallet");
  }
  Transaction tx = GetTransaction(tx_id);
  const std::string unsigned_hex = tx.get_raw();
  if (unsigned_hex.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "No raw tx found for tx_id=" + tx_id);
  }
  if (wally_signer_->IsTxSigned(unsigned_hex)) {
    return tx;  // already signed
  }

  // Rebuild prevout data from all known wallet UTXOs. SignTx will look up
  // each input's (txid, vout) and only use what it needs; spent ones are
  // harmless to include since GetVtxValues only returns confirmed txs.
  std::vector<std::string> tx_hexes = GetVtxValues();
  std::vector<wally::LiquidUtxos> inputs;
  inputs.reserve(tx_hexes.size());
  for (const auto& hex : tx_hexes) {
    inputs.push_back(wally_signer_->GetUtxosFromTx(hex));
  }

  std::string signed_hex = wally_signer_->SignTx(unsigned_hex, inputs);

  // Liquid txid is computed without witness, so it stays the same after
  // signing. Update the existing row's VALUE in place.
  UpdateTransaction(signed_hex, /*height=*/-1, /*blocktime=*/0,
                    /*reject_msg=*/{});
  return GetTransaction(tx_id);
}

bool NunchukWalletDb::UpdatePsbt(const std::string& psbt) {
  if (IsSupportLiquid()) {
    throw NunchukException(NunchukException::INVALID_WALLET_TYPE,
                           "Liquid wallet is not supported psbt update");
  }
  sqlite3_stmt* stmt;
  std::string sql = std::string("UPDATE ") + TxTable() +
                    " SET VALUE = ?1 WHERE ID = ?2 AND HEIGHT = -1;";
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
  std::string sql = std::string("SELECT * FROM ") + TxTable() +
                    " WHERE ID = ? AND HEIGHT = -1;;";
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
        std::string("INSERT INTO ") + TxTable() +
        "(ID, VALUE, HEIGHT, FEE, MEMO, CHANGEPOS, BLOCKTIME, EXTRA)"
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
  std::string select_sql =
      std::string("SELECT EXTRA FROM ") + TxTable() + " WHERE ID = ?;";
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
    std::string update_sql =
        std::string("UPDATE ") + TxTable() + " SET EXTRA = ?1 WHERE ID = ?2;";
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
  if (IsSupportLiquid()) {
    return "";
  }
  sqlite3_stmt* stmt;
  std::string sql = std::string("SELECT VALUE FROM ") + TxTable() +
                    " WHERE ID = ? AND HEIGHT = -1;";
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
  std::string sql =
      std::string("SELECT VALUE FROM ") + TxTable() + " WHERE ID = ?;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, tx_id.c_str(), tx_id.size(), NULL);
  sqlite3_step(stmt);
  if (sqlite3_column_text(stmt, 0)) {
    std::string rs = std::string((char*)sqlite3_column_text(stmt, 0));
    SQLCHECK(sqlite3_finalize(stmt));
    if (IsSupportLiquid()) {
      return {rs, true};
    }
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
  std::string sql =
      std::string("SELECT * FROM ") + TxTable() + " WHERE ID = ?;";
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
    std::string extra = sqlite3_column_text(stmt, 7)
                            ? std::string((char*)sqlite3_column_text(stmt, 7))
                            : "";
    SQLCHECK(sqlite3_finalize(stmt));

    auto tx = GetTransactionFromVtxValue(value, wallet, height);
    tx.set_txid(tx_id);
    tx.set_m(wallet.get_m());
    tx.set_wallet_type(wallet.get_wallet_type());
    tx.set_address_type(wallet.get_address_type());
    if (tx.get_fee() == 0) tx.set_fee(Amount(fee));
    if (change_pos >= 0 &&
        static_cast<size_t>(change_pos) < tx.mutable_outputs().size()) {
      tx.mutable_outputs()[change_pos].isChange = true;
    }
    tx.set_blocktime(blocktime);
    tx.set_schedule_time(-1);
    tx.set_receive(false);
    tx.set_sub_amount(0);

    if (!extra.empty()) {
      FillExtra(extra, tx);
    }
    for (auto&& output : tx.get_outputs()) UseAddress(output.address);
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
  std::string sql = std::string("DELETE FROM ") + TxTable() +
                    " WHERE ID = ? AND HEIGHT <= 0;";
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
  if (IsSupportLiquid()) {
    return 0;
  }
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

std::map<AssetId, Amount> NunchukWalletDb::GetAssetBalances() {
  return GetAddressAssets({});
}

std::vector<Transaction> NunchukWalletDb::GetTransactions(int count, int skip) {
  auto wallet = GetWallet(true, true);

  sqlite3_stmt* stmt;
  std::string sql = std::string("SELECT * FROM ") + TxTable() + ";";
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

      Transaction tx;
      try {
        tx = GetTransactionFromVtxValue(value, wallet, height);
      } catch (...) {
        sqlite3_step(stmt);
        continue;
      }
      tx.set_txid(tx_id);
      tx.set_m(wallet.get_m());
      tx.set_wallet_type(wallet.get_wallet_type());
      tx.set_address_type(wallet.get_address_type());
      if (tx.get_fee() == 0) tx.set_fee(Amount(fee));
      if (change_pos >= 0 &&
          static_cast<size_t>(change_pos) < tx.mutable_outputs().size()) {
        tx.mutable_outputs()[change_pos].isChange = true;
      }
      tx.set_blocktime(blocktime);
      tx.set_schedule_time(-1);
      tx.set_receive(false);
      tx.set_sub_amount(0);
      tx.set_memo(memo);

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

std::vector<std::string> NunchukWalletDb::GetVtxValues() {
  sqlite3_stmt* stmt;
  std::string sql =
      std::string("SELECT * FROM ") + TxTable() + " WHERE HEIGHT > -1;";
  sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, NULL);
  sqlite3_step(stmt);

  std::vector<std::string> rs;
  while (sqlite3_column_text(stmt, 0)) {
    std::string value = std::string((char*)sqlite3_column_text(stmt, 1));
    rs.push_back(value);
    sqlite3_step(stmt);
  }
  SQLCHECK(sqlite3_finalize(stmt));
  return rs;
}

Transaction NunchukWalletDb::GetTransactionFromVtxValue(
    const std::string& value, const nunchuk::Wallet& wallet, int height) {
  if (wallet.get_wallet_type() == WalletType::LIQUID) {
    auto tx = wally_signer_->GetTransactionFromTx(value, height);
    SingleSigner signer = wallet.get_signers()[0];
    if (tx.get_status() == TransactionStatus::PENDING_CONFIRMATION ||
        tx.get_status() == TransactionStatus::READY_TO_BROADCAST ||
        tx.get_status() == TransactionStatus::CONFIRMED) {
      tx.set_signed({signer});
      tx.set_signer(signer.get_master_fingerprint(), true);
    } else {
      tx.set_signed({});
      tx.set_signer(signer.get_master_fingerprint(), false);
    }
    return tx;
  }
  auto [tx, is_hex_tx] = GetTransactionFromStr(value, wallet, height);
  if (is_hex_tx) {
    tx.set_raw(value);
  } else {
    tx.set_psbt(value);
  }
  return tx;
}

std::string NunchukWalletDb::FillPsbt(const std::string& base64_psbt) {
  if (IsSupportLiquid()) {
    throw NunchukException(NunchukException::INVALID_WALLET_TYPE,
                           "Liquid wallet is not supported psbt fill");
  }
  auto psbt = DecodePsbt(base64_psbt);
  if (!psbt.tx.has_value()) return base64_psbt;

  auto wallet = GetWallet(true);
  auto desc = GetDescriptorsImportString(wallet);
  auto provider = SigningProviderCache::getInstance().GetProvider(desc);

  int nin = psbt.tx.value().vin.size();
  for (int i = 0; i < nin; i++) {
    std::string tx_id = psbt.tx.value().vin[i].prevout.hash.GetHex();
    sqlite3_stmt* stmt;
    std::string sql = std::string("SELECT VALUE FROM ") + TxTable() +
                      " WHERE ID = ? AND HEIGHT > -1;";
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
    const std::optional<int> sighash = psbt.inputs[i].sighash_type;
    SignPSBTInput(provider, psbt, i, &txdata, sighash, nullptr, false);
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
      for (auto& output : tx.mutable_outputs()) {
        auto amount = extra_json["outputs"][output.address];
        if (amount != nullptr) {
          output.userAmount = Amount(amount);
        }
      }
    }
    if (extra_json["fee_rate"] != nullptr) {
      tx.set_fee_rate(extra_json["fee_rate"]);
    }
    if (extra_json["vsize"] != nullptr) {
      tx.set_vsize(extra_json["vsize"]);
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

namespace {
const TxOutput* FindOutputByVout(const Transaction& tx, uint32_t vout) {
  for (const auto& output : tx.get_outputs()) {
    if (output.vout == vout) return &output;
  }
  return nullptr;
}
}  // namespace

// TODO (bakaoh): consider persisting these data
void NunchukWalletDb::FillSendReceiveData(Transaction& tx) {
  if (IsSupportLiquid()) {
    int send_count = 0;
    int send_index = -1;
    for (size_t i = 0; i < tx.get_outputs().size(); i++) {
      const auto& output = tx.get_outputs()[i];
      if (!output.isReceive) {
        send_count++;
        send_index = i;
      }
    }
    std::map<AssetId, Amount> asset_amounts{};
    bool is_receive = true;
    for (auto& input : tx.get_inputs()) {
      try {
        auto prev_tx = GetTransaction(input.txid);
        const auto* prev_out = FindOutputByVout(prev_tx, input.vout);
        if (prev_out == nullptr || !prev_out->isReceive) continue;
        asset_amounts[prev_out->assetId] += prev_out->amount;
        is_receive = false;
      } catch (StorageException& se) {
        if (se.code() != StorageException::TX_NOT_FOUND) throw;
      }
    }
    tx.set_receive(is_receive);
    if (is_receive || send_count != 1) return;
    AssetId asset_id = asset_amounts.size() == 1
                           ? wally::WallyUtils::C().LBTC_ASSET_ID
                           : wally::WallyUtils::C().USDT_ASSET_ID;
    Amount send_amount = asset_amounts[asset_id];
    for (auto& output : tx.mutable_outputs()) {
      if (output.isReceive && output.assetId == asset_id) {
        send_amount -= output.amount;
      }
    }
    if (asset_id == wally::WallyUtils::C().LBTC_ASSET_ID) {
      send_amount -= tx.get_fee();
    }
    tx.mutable_outputs()[send_index].amount = send_amount;
    tx.mutable_outputs()[send_index].assetId = asset_id;
    return;
  }
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
      auto prev_tx = GetTransaction(input.txid);
      prev_out = prev_tx.get_outputs()[input.vout];
      if (!extract_signers && tx.get_wallet_type() == WalletType::MULTI_SIG &&
          tx.get_address_type() != AddressType::TAPROOT &&
          !tx.get_raw().empty() && !prev_tx.get_raw().empty()) {
        try {
          for (auto&& signer : tx.get_signers()) {
            tx.set_signer(signer.first, false);
          }
          auto mtx = DecodeRawTransaction(tx.get_raw());
          auto vout = DecodeRawTransaction(prev_tx.get_raw()).vout[input.vout];
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
    if (isMyAddress(prev_out.address)) {
      total_amount += prev_out.amount;
      is_send_tx = true;
    }
  }
  if (is_send_tx) {
    Amount send_amount{0};
    auto& outputs = tx.mutable_outputs();
    for (size_t i = 0; i < outputs.size(); i++) {
      auto& output = outputs[i];
      total_amount -= output.amount;
      output.isReceive = true;
      if (!isMyAddress(output.address)) {
        send_amount += output.amount;
        output.isReceive = false;
      } else if (!output.isChange && isMyChange(output.address)) {
        output.isChange = true;
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
    for (auto& output : tx.mutable_outputs()) {
      if (isMyAddress(output.address)) {
        receive_amount += output.amount;
        output.isReceive = true;
      }
    }
    tx.set_receive(true);
    tx.set_sub_amount(receive_amount);
  }
}

void NunchukWalletDb::ForceRefresh() {
  SQLCHECK(sqlite3_exec(db_,
                        (std::string("DELETE FROM ") + TxTable() + ";").c_str(),
                        NULL, 0, NULL));
  SQLCHECK(sqlite3_exec(
      db_, (std::string("DELETE FROM ") + AddressTable() + ";").c_str(), NULL,
      0, NULL));
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
      std::string sql =
          "INSERT INTO COINTAGS(COIN, TAGID) VALUES (?1, ?2) "
          "ON CONFLICT(COIN, TAGID) DO NOTHING;";
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
          "INSERT INTO COINCOLLECTIONS(COIN, COLLECTIONID) VALUES (?1, ?2) "
          "ON CONFLICT(COIN, COLLECTIONID) DO NOTHING;";
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
  if (IsSupportLiquid()) {
    throw NunchukException(
        NunchukException::INVALID_WALLET_TYPE,
        "Liquid wallet is not supported get coins from transactions");
  }
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
      used_by[CoinId(input.txid, input.vout)] = tx.get_txid();
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
      auto id = CoinId(input.txid, input.vout);
      if (id ==
          "0000000000000000000000000000000000000000000000000000000000000000:-1")
        continue;  // coinbase input
      if (used_by.count(id) && used_by[id] != tx.get_txid()) invalid = true;
    }
    if (invalid) continue;

    for (auto&& input : tx.get_inputs()) {
      if (tx_map.count(input.txid) == 0) continue;
      auto prev_tx = tx_map[input.txid];
      auto address = prev_tx.get_outputs()[input.vout].address;
      if (!isMyAddress(address)) continue;
      auto id = CoinId(input.txid, input.vout);
      coins[id].set_txid(input.txid);
      coins[id].set_vout(input.vout);
      coins[id].set_address(address);
      coins[id].set_amount(prev_tx.get_outputs()[input.vout].amount);
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
      if (!isMyAddress(output.address)) continue;
      if (tx.get_height() < 0) continue;
      auto id = CoinId(tx.get_txid(), vout);
      coins[id].set_txid(tx.get_txid());
      coins[id].set_vout(vout);
      coins[id].set_address(output.address);
      coins[id].set_amount(output.amount);
      coins[id].set_height(tx.get_height());
      coins[id].set_blocktime(tx.get_blocktime());
      set_status(id, tx.get_height() > 0
                         ? CoinStatus::CONFIRMED
                         : CoinStatus::INCOMING_PENDING_CONFIRMATION);
      coins[id].set_memo(tx.get_memo());
      coins[id].set_change(isMyChange(output.address));
    }
  }
  return coins;
}

std::vector<UnspentOutput> NunchukWalletDb::GetCoins() {
  if (IsSupportLiquid()) {
    return {};
  }
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
  if (IsSupportLiquid()) {
    throw NunchukException(NunchukException::INVALID_WALLET_TYPE,
                           "Liquid wallet is not supported get ancestry");
  }
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
        auto id = CoinId(input.txid, input.vout);
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
    if (IsMyAddress(tx.get_outputs()[i].address)) my_vout.push_back(i);
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
        bool isValid = false;
        for (const auto& key : input.hd_keypaths) {
          if (HexStr(key.second.fingerprint) == pair[0] &&
              creator.Checker().CheckECDSASignature(
                  ParseHex(pair[1]),
                  {key.first.data(), key.first.data() + key.first.size()},
                  scriptCode, SigVersion::WITNESS_V0)) {
            isValid = true;
            break;
          }
        }
        if (!isValid) {
          throw NunchukException(NunchukException::INVALID_SIGNATURE,
                                 "Invalid signature!");
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
  std::string miniscript = GetString(DbKeys::MINISCRIPT);
  if (miniscript.empty()) return miniscript;
  const std::string target_format = chain_ == Chain::MAIN ? "xpub" : "tpub";
  static const std::regex kXpubRegex(R"(\b(xpub[1-9A-HJ-NP-Za-km-z]{10,})\b)");
  static const std::regex kTpubRegex(R"(\b(tpub[1-9A-HJ-NP-Za-km-z]{10,})\b)");
  const std::regex& wrong_format =
      target_format == "xpub" ? kTpubRegex : kXpubRegex;
  if (!std::regex_search(miniscript, wrong_format)) return miniscript;

  std::string out;
  out.reserve(miniscript.size());
  size_t last = 0;
  for (std::sregex_iterator
           it(miniscript.begin(), miniscript.end(), wrong_format),
       end;
       it != end; ++it) {
    const std::smatch& m = *it;
    out.append(miniscript, last, static_cast<size_t>(m.position()) - last);
    const std::string extpub = m.str(1);
    try {
      out.append(Utils::SanitizeBIP32Input(extpub, target_format));
    } catch (...) {
      out.append(extpub);
    }
    last = static_cast<size_t>(m.position() + m.length());
  }
  out.append(miniscript, last, std::string::npos);
  return out;
}

bool NunchukWalletDb::IsSupportLiquid() const {
  try {
    auto data = GetString(DbKeys::IMMUTABLE_DATA);
    if (!data.empty()) {
      json immutable_data = json::parse(data);
      if (immutable_data["wallet_type"] != nullptr) {
        return immutable_data["wallet_type"] == WalletType::LIQUID;
      }
    }
  } catch (...) {
  }
  return false;
}

}  // namespace nunchuk
