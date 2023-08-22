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

#ifndef NUNCHUK_STORAGE_WALLETDB_H
#define NUNCHUK_STORAGE_WALLETDB_H

#include "db.h"
#include <nunchuk.h>
#include <sqlcipher/sqlite3.h>
#include <vector>
#include <string>
#include <optional>

namespace nunchuk {

struct AddressData {
  std::string address;
  int index;
  bool internal;
  bool used;
};

class NunchukWalletDb : public NunchukDb {
 public:
  using NunchukDb::NunchukDb;

  void InitWallet(const Wallet &wallet);
  void MaybeMigrate();
  void DeleteWallet();
  bool SetName(const std::string &value);
  bool SetDescription(const std::string &value);
  bool SetLastUsed(time_t value);
  bool SetGapLimit(int value);
  bool AddAddress(const std::string &address, int index, bool internal);
  Wallet GetWallet(bool skip_balance = false, bool skip_provider = false);
  std::vector<SingleSigner> GetSigners() const;
  std::vector<std::string> GetAddresses(bool used, bool internal);
  std::vector<std::string> GetAllAddresses();
  int GetCurrentAddressIndex(bool internal) const;
  Transaction InsertTransaction(const std::string &raw_tx, int height,
                                time_t blocktime, Amount fee,
                                const std::string &memo, int change_pos);
  Transaction GetTransaction(const std::string &tx_id);
  bool UpdateTransaction(const std::string &raw_tx, int height,
                         time_t blocktime, const std::string &reject_msg);
  bool UpdateTransactionSchedule(const std::string &tx_id, time_t value);
  bool DeleteTransaction(const std::string &tx_id);
  Transaction CreatePsbt(const std::string &psbt, Amount fee,
                         const std::string &memo, int change_pos,
                         const std::map<std::string, Amount> &outputs,
                         Amount fee_rate, bool subtract_fee_from_amount,
                         const std::string &replace_tx);
  bool UpdatePsbt(const std::string &psbt);
  bool UpdatePsbtTxId(const std::string &old_id, const std::string &new_id);
  std::string GetPsbt(const std::string &tx_id) const;
  std::pair<std::string, bool> GetPsbtOrRawTx(const std::string &tx_id) const;
  std::vector<Transaction> GetTransactions(int count = 1000, int skip = 0);
  bool SetUtxos(const std::string &address, const std::string &utxo);
  Amount GetBalance(bool include_mempool);
  std::string FillPsbt(const std::string &psbt);
  void FillSendReceiveData(Transaction &tx);
  void FillExtra(const std::string &extra, Transaction &tx) const;
  int GetAddressIndex(const std::string &address);
  Amount GetAddressBalance(const std::string &address);
  std::string GetAddressStatus(const std::string &address) const;
  void ForceRefresh();

  bool UpdateTransactionMemo(const std::string &tx_id, const std::string &memo);
  std::optional<std::string> GetTransactionMemo(const std::string &tx_id) const;
  bool UpdateCoinMemo(const std::string &tx_id, int vout,
                      const std::string &memo);
  std::string GetCoinMemo(const std::string &tx_id, int vout) const;
  std::map<std::string, std::string> GetAllMemo() const;
  bool LockCoin(const std::string &tx_id, int vout);
  bool UnlockCoin(const std::string &tx_id, int vout);
  bool IsLock(const std::string &tx_id, int vout) const;
  std::vector<std::string> GetCoinLocked() const;

  int CreateCoinTag(const std::string &name, const std::string &color);
  std::vector<CoinTag> GetCoinTags() const;
  bool UpdateCoinTag(const CoinTag &tag);
  bool DeleteCoinTag(int tag_id);
  bool AddToCoinTag(int tag_id, const std::string &tx_id, int vout);
  bool RemoveFromCoinTag(int tag_id, const std::string &tx_id, int vout);
  std::vector<std::string> GetCoinByTag(int tag_id) const;
  std::vector<int> GetAddedTags(const std::string &tx_id, int vout) const;

  int CreateCoinCollection(const std::string &name);
  std::vector<CoinCollection> GetCoinCollections() const;
  bool UpdateCoinCollection(const CoinCollection &collection);
  bool DeleteCoinCollection(int collection_id);
  bool AddToCoinCollection(int collection_id, const std::string &tx_id,
                           int vout);
  bool RemoveFromCoinCollection(int collection_id, const std::string &tx_id,
                                int vout);
  std::vector<std::string> GetCoinInCollection(int collection_id) const;
  std::vector<int> GetAddedCollections(const std::string &tx_id,
                                       int vout) const;
  std::string ExportCoinControlData();
  bool ImportCoinControlData(const std::string &data, bool force);
  std::string ExportBIP329();
  void ImportBIP329(const std::string &data);
  time_t GetLastModified() const;
  bool SetLastModified(time_t value);

  bool IsMyAddress(const std::string &address);
  std::vector<UnspentOutput> GetCoins();
  std::vector<std::vector<UnspentOutput>> GetAncestry(const std::string &tx_id,
                                                      int vout);

  Transaction ImportDummyTx(const std::string &id, const std::string &body,
                            const std::vector<std::string> &tokens);
  RequestTokens SaveDummyTxRequestToken(const std::string &id,
                                      const std::string &token);
  bool DeleteDummyTx(const std::string &id);
  RequestTokens GetDummyTxRequestToken(const std::string &id);
  std::map<std::string, Transaction> GetDummyTxs();
  Transaction GetDummyTx(const std::string &id);

 private:
  void CreateCoinControlTable();
  void CreateDummyTxTable();
  void ClearCoinControlData();
  void SetReplacedBy(const std::string &old_txid, const std::string &new_txid);
  std::string GetSingleSignerKey(const SingleSigner &signer);
  bool AddSigner(const SingleSigner &signer);
  std::map<std::string, AddressData> GetAllAddressData(bool check_used = true);
  std::map<int, bool> GetAutoLockData() const;
  std::map<int, bool> GetAutoAddData() const;
  void AutoAddNewCoins(const Transaction &tx);
  void SetAddress(const std::string &address, int index, bool internal,
                  const std::string &utxos = {});
  void UseAddress(const std::string &address);
  std::string CoinId(const std::string &tx_id, int vout) const;
  bool IsMyChange(const std::string &address);
  std::map<std::string, UnspentOutput> GetCoinsFromTransactions(
      const std::vector<Transaction> &transactions);
  static std::map<std::string, std::map<std::string, AddressData>> addr_cache_;
  static std::map<std::string, std::vector<SingleSigner>> signer_cache_;
  static std::map<std::string, std::map<int, bool>> collection_auto_lock_;
  static std::map<std::string, std::map<int, bool>> collection_auto_add_;
  static std::map<std::string, std::map<std::string, Transaction>> txs_cache_;
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_WALLETDB_H
