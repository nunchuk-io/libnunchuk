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
  bool AddAddress(const std::string &address, int index, bool internal);
  Wallet GetWallet(bool skip_balance = false, bool skip_provider = false) const;
  std::vector<SingleSigner> GetSigners() const;
  std::vector<std::string> GetAddresses(bool used, bool internal) const;
  std::vector<std::string> GetAllAddresses() const;
  int GetCurrentAddressIndex(bool internal) const;
  Transaction InsertTransaction(const std::string &raw_tx, int height,
                                time_t blocktime, Amount fee,
                                const std::string &memo, int change_pos);
  Transaction GetTransaction(const std::string &tx_id) const;
  bool UpdateTransaction(const std::string &raw_tx, int height,
                         time_t blocktime, const std::string &reject_msg);
  bool UpdateTransactionMemo(const std::string &tx_id, const std::string &memo);
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
  std::vector<Transaction> GetTransactions(int count = 1000,
                                           int skip = 0) const;
  bool SetUtxos(const std::string &address, const std::string &utxo);
  Amount GetBalance(bool include_mempool) const;
  std::string FillPsbt(const std::string &psbt);
  void FillSendReceiveData(Transaction &tx);
  void FillExtra(const std::string &extra, Transaction &tx) const;
  int GetAddressIndex(const std::string &address) const;
  Amount GetAddressBalance(const std::string &address) const;
  std::string GetAddressStatus(const std::string &address) const;
  void ForceRefresh();

  bool UpdateCoinMemo(const std::string &tx_id, int vout,
                      const std::string &memo);
  bool LockCoin(const std::string &tx_id, int vout);
  bool UnlockCoin(const std::string &tx_id, int vout);
  bool IsLock(const std::string &tx_id, int vout);
  std::vector<std::string> GetCoinLocked();

  int CreateCoinTag(const std::string &name, const std::string &color);
  std::vector<CoinTag> GetCoinTags();
  bool UpdateCoinTag(const CoinTag &tag);
  bool DeleteCoinTag(int tag_id);
  bool AddToCoinTag(int tag_id, const std::string &tx_id, int vout);
  bool RemoveFromCoinTag(int tag_id, const std::string &tx_id, int vout);
  std::vector<std::string> GetCoinByTag(int tag_id);
  std::vector<int> GetAddedTags(const std::string &tx_id, int vout);

  int CreateCoinCollection(const std::string &name);
  std::vector<CoinCollection> GetCoinCollections();
  bool UpdateCoinCollection(const CoinCollection &collection);
  bool DeleteCoinCollection(int collection_id);
  bool AddToCoinCollection(int collection_id, const std::string &tx_id,
                           int vout);
  bool RemoveFromCoinCollection(int collection_id, const std::string &tx_id,
                                int vout);
  std::vector<std::string> GetCoinInCollection(int collection_id);
  std::vector<int> GetAddedCollections(const std::string &tx_id, int vout);
  std::string ExportCoinControlData();
  void ImportCoinControlData(const std::string &data);

  bool IsMyAddress(const std::string &address) const;
  std::vector<UnspentOutput> GetCoins() const;
  std::vector<std::vector<UnspentOutput>> GetAncestry(const std::string &tx_id,
                                                      int vout) const;

 private:
  void CreateCoinControlTable();
  void ClearCoinControlData();
  void SetReplacedBy(const std::string &old_txid, const std::string &new_txid);
  std::string GetSingleSignerKey(const SingleSigner &signer);
  bool AddSigner(const SingleSigner &signer);
  std::map<std::string, AddressData> GetAllAddressData() const;
  void SetAddress(const std::string &address, int index, bool internal,
                  const std::string &utxos = {});
  void UseAddress(const std::string &address) const;
  std::string CoinId(const std::string &tx_id, int vout) const;
  bool IsMyChange(const std::string &address) const;
  std::map<std::string, UnspentOutput> GetCoinsFromTransactions(
      const std::vector<Transaction> &transactions) const;
  static std::map<std::string, std::map<std::string, AddressData>> addr_cache_;
  static std::map<std::string, std::vector<SingleSigner>> signer_cache_;
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_WALLETDB_H
