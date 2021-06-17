// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_STORAGE_WALLETDB_H
#define NUNCHUK_STORAGE_WALLETDB_H

#include "common.h"
#include "db.h"
#include <nunchuk.h>
#include <sqlcipher/sqlite3.h>
#include <vector>
#include <string>

namespace nunchuk {

class NunchukWalletDb : public NunchukDb {
 public:
  using NunchukDb::NunchukDb;

  static std::string GetSingleSignerKey(const SingleSigner &signer);

  void InitWallet(const std::string &name, int m, int n,
                  const std::vector<SingleSigner> &signers,
                  AddressType address_type, bool is_escrow, time_t create_date,
                  const std::string &description);
  void MaybeMigrate();
  void DeleteWallet();
  bool SetName(const std::string &value);
  bool SetDescription(const std::string &value);
  bool AddAddress(const std::string &address, int index, bool internal);
  bool UseAddress(const std::string &address);
  Wallet GetWallet() const;
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
  bool DeleteTransaction(const std::string &tx_id);
  Transaction CreatePsbt(const std::string &psbt, Amount fee,
                         const std::string &memo, int change_pos,
                         const std::map<std::string, Amount> &outputs,
                         Amount fee_rate, bool subtract_fee_from_amount,
                         const std::string &replace_tx);
  bool UpdatePsbt(const std::string &psbt);
  bool UpdatePsbtTxId(const std::string &old_id, const std::string &new_id);
  std::string GetPsbt(const std::string &tx_id) const;
  std::vector<UnspentOutput> GetUnspentOutputs(bool remove_locked) const;
  std::vector<Transaction> GetTransactions(int count = 1000,
                                           int skip = 0) const;
  bool SetUtxos(const std::string &address, const std::string &utxo);
  Amount GetBalance() const;
  std::string FillPsbt(const std::string &psbt);
  std::string GetMultisigConfig(bool is_cobo = false) const;
  void FillSendReceiveData(Transaction &tx);
  void FillExtra(const std::string &extra, Transaction &tx) const;
  int GetAddressIndex(const std::string &address) const;
  Amount GetAddressBalance(const std::string &address) const;

 private:
  void SetReplacedBy(const std::string &old_txid, const std::string &new_txid);
  bool AddSigner(const SingleSigner &signer);
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_WALLETDB_H
