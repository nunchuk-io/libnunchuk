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
  std::vector<UnspentOutput> GetUtxos(bool include_locked,
                                      bool include_mempool) const;
  bool SetUtxos(const std::string &address, const std::string &utxo);
  Amount GetBalance() const;
  std::string FillPsbt(const std::string &psbt);
  void FillSendReceiveData(Transaction &tx);
  void FillExtra(const std::string &extra, Transaction &tx) const;
  int GetAddressIndex(const std::string &address) const;
  Amount GetAddressBalance(const std::string &address) const;
  std::string GetAddressStatus(const std::string &address) const;
  void ForceRefresh();

 private:
  void SetReplacedBy(const std::string &old_txid, const std::string &new_txid);
  std::string GetSingleSignerKey(const SingleSigner &signer);
  bool AddSigner(const SingleSigner &signer);
  std::map<std::string, AddressData> GetAllAddressData() const;
  void SetAddress(const std::string &address, int index, bool internal,
                  const std::string &utxos = {});
  void UseAddress(const std::string &address) const;
  bool IsMyAddress(const std::string &address) const;
  bool IsMyChange(const std::string &address) const;
  static std::map<std::string, std::map<std::string, AddressData>> addr_cache_;
  static std::map<std::string, std::vector<SingleSigner>> signer_cache_;
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_WALLETDB_H
