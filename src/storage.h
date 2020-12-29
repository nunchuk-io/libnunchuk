// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_STORAGE_H
#define NUNCHUK_STORAGE_H
#define SQLITE_HAS_CODEC
#define STORAGE_VER 3
#define HAVE_CONFIG_H
#ifdef NDEBUG
#undef NDEBUG
#endif

#include <nunchuk.h>
#include <sqlcipher/sqlite3.h>

#include <boost/filesystem.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <iostream>
#include <map>
#include <string>

namespace nunchuk {

namespace DbKeys {
const int ID = 0;
const int IMMUTABLE_DATA = 1;
const int NAME = 2;
const int FINGERPRINT = 3;
const int ESCROW_INDEX = 5;
const int LAST_HEALTH_CHECK = 6;
const int VERSION = 7;
const int DESCRIPTION = 8;
const int CHAIN_TIP = 9;
const int SELECTED_WALLET = 10;
}  // namespace DbKeys

class NunchukStorage;
class NunchukDb {
 public:
  NunchukDb(Chain chain, const std::string &id, const std::string &file_name,
            const std::string &passphrase);
  ~NunchukDb() { close(); }
  std::string GetId() const;

 protected:
  void CreateTable();
  void DropTable();
  void ReKey(const std::string &new_passphrase);
  void EncryptDb(const std::string &new_file_name,
                 const std::string &new_passphrase);
  void DecryptDb(const std::string &new_file_name);
  bool PutString(int key, const std::string &value);
  bool PutInt(int key, int64_t value);
  std::string GetString(int key) const;
  int64_t GetInt(int key) const;
  bool TableExists(const std::string &table_name) const;
  sqlite3 *db_;
  std::string id_;
  Chain chain_;

 private:
  NunchukDb() = delete;
  void close();
  std::string db_file_name_;
  friend class NunchukStorage;
};

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
  std::string GetDescriptor(bool internal) const;
  std::vector<UnspentOutput> GetUnspentOutputs(bool remove_locked) const;
  std::vector<Transaction> GetTransactions(int count = 1000,
                                           int skip = 0) const;
  bool SetUtxos(const std::string &address, const std::string &utxo);
  Amount GetBalance() const;
  std::string FillPsbt(const std::string &psbt);
  std::string GetColdcardFile() const;
  void FillSendReceiveData(Transaction &tx);
  void FillExtra(const std::string &extra, Transaction &tx) const;
  int GetAddressIndex(const std::string &address) const;

 private:
  void SetReplacedBy(const std::string &old_txid, const std::string &new_txid);
  bool AddSigner(const SingleSigner &signer);
  friend class NunchukStorage;
};

class NunchukSignerDb : public NunchukDb {
 public:
  using NunchukDb::NunchukDb;
  void InitSigner(const std::string &name, const std::string &fingerprint);
  void DeleteSigner();
  bool SetName(const std::string &value);
  bool SetLastHealthCheck(time_t value);
  bool AddXPub(const std::string &path, const std::string &xpub,
               const std::string &type);
  bool AddXPub(const WalletType &wallet_type, const AddressType &address_type,
               int index, const std::string &xpub);
  bool UseIndex(const WalletType &wallet_type, const AddressType &address_type,
                int index);
  std::string GetXpub(const std::string &path);
  std::string GetXpub(const WalletType &wallet_type,
                      const AddressType &address_type, int index);
  int GetUnusedIndex(const WalletType &wallet_type,
                     const AddressType &address_type);
  int GetCachedIndex(const WalletType &wallet_type,
                     const AddressType &address_type);
  std::string GetFingerprint() const;
  std::string GetName() const;
  time_t GetLastHealthCheck() const;
  std::vector<SingleSigner> GetSingleSigners() const;
  bool IsMaster() const;
  void InitRemote();
  bool AddRemote(const std::string &name, const std::string &xpub,
                 const std::string &public_key,
                 const std::string &derivation_path, bool used = false);
  SingleSigner GetRemoteSigner(const std::string &derivation_path) const;
  bool DeleteRemoteSigner(const std::string &derivation_path);
  bool UseRemote(const std::string &derivation_path);
  bool SetRemoteName(const std::string &derivation_path,
                     const std::string &value);
  bool SetRemoteLastHealthCheck(const std::string &derivation_path,
                                time_t value);
  std::vector<SingleSigner> GetRemoteSigners() const;

 private:
  friend class NunchukStorage;
};

class NunchukAppStateDb : public NunchukDb {
 public:
  using NunchukDb::NunchukDb;

  void Init();
  int GetChainTip() const;
  bool SetChainTip(int value);
  std::string GetSelectedWallet() const;
  bool SetSelectedWallet(const std::string &value);
  int64_t GetStorageVersion() const;
  bool SetStorageVersion(int64_t value);

 private:
  friend class NunchukStorage;
};

class NunchukStorage {
 public:
  NunchukStorage(const std::string &datadir = "",
                 const std::string &passphrase = "");

  void MaybeMigrate(Chain chain);
  bool WriteFile(const std::string &file_path, const std::string &value);
  std::string LoadFile(const std::string &file_path);
  bool ExportWallet(Chain chain, const std::string &wallet_id,
                    const std::string &file_path, ExportFormat format);
  std::string ImportWalletDb(Chain chain, const std::string &file_path);
  void SetPassphrase(Chain chain, const std::string &new_passphrase);
  Wallet CreateWallet(Chain chain, const std::string &name, int m, int n,
                      const std::vector<SingleSigner> &signers,
                      AddressType address_type, bool is_escrow,
                      const std::string &description);
  std::string CreateMasterSigner(Chain chain, const std::string &name,
                                 const std::string &fingerprint);
  SingleSigner CreateSingleSigner(Chain chain, const std::string &name,
                                  const std::string &xpub,
                                  const std::string &public_key,
                                  const std::string &derivation_path,
                                  const std::string &master_fingerprint);
  SingleSigner GetSignerFromMasterSigner(Chain chain,
                                         const std::string &mastersigner_id,
                                         const WalletType &wallet_type,
                                         const AddressType &address_type,
                                         int index);

  std::vector<std::string> ListWallets(Chain chain);
  std::vector<std::string> ListMasterSigners(Chain chain);

  Wallet GetWallet(Chain chain, const std::string &id,
                   bool create_signers_if_not_exist = false);
  MasterSigner GetMasterSigner(Chain chain, const std::string &id);

  bool UpdateWallet(Chain chain, const Wallet &wallet);
  bool UpdateMasterSigner(Chain chain, const MasterSigner &mastersigner);

  bool DeleteWallet(Chain chain, const std::string &id);
  bool DeleteMasterSigner(Chain chain, const std::string &id);

  std::vector<SingleSigner> GetSignersFromMasterSigner(
      Chain chain, const std::string &mastersigner_id);
  bool CacheMasterSignerXPub(Chain chain, const std::string &mastersigner_id,
                             const WalletType &wallet_type,
                             const AddressType &address_type, int index,
                             const std::string &xpub);
  bool CacheMasterSignerXPub(Chain chain, const std::string &mastersigner_id,
                             const std::string &path, const std::string &xpub);
  int GetCurrentIndexFromMasterSigner(Chain chain,
                                      const std::string &mastersigner_id,
                                      const WalletType &wallet_type,
                                      const AddressType &address_type);
  int GetCachedIndexFromMasterSigner(Chain chain,
                                     const std::string &mastersigner_id,
                                     const WalletType &wallet_type,
                                     const AddressType &address_type);
  std::string GetMasterSignerXPub(Chain chain,
                                  const std::string &mastersigner_id,
                                  const std::string &path);
  bool SetHealthCheckSuccess(Chain chain, const std::string &mastersigner_id);
  bool SetHealthCheckSuccess(Chain chain, const SingleSigner &signer);
  std::string GetDescriptor(Chain chain, const std::string &wallet_id,
                            bool internal);
  bool AddAddress(Chain chain, const std::string &wallet_id,
                  const std::string &address, int index, bool internal);
  bool UseAddress(Chain chain, const std::string &wallet_id,
                  const std::string &address);
  std::vector<std::string> GetAddresses(Chain chain,
                                        const std::string &wallet_id, bool used,
                                        bool internal);
  std::vector<std::string> GetAllAddresses(Chain chain,
                                           const std::string &wallet_id);
  int GetCurrentAddressIndex(Chain chain, const std::string &wallet_id,
                             bool internal);
  Transaction InsertTransaction(Chain chain, const std::string &wallet_id,
                                const std::string &raw_tx, int height,
                                time_t blocktime, Amount fee = 0,
                                const std::string &memo = {},
                                int change_pos = -1);
  std::vector<Transaction> GetTransactions(Chain chain,
                                           const std::string &wallet_id,
                                           int count, int skip);
  std::vector<UnspentOutput> GetUnspentOutputs(Chain chain,
                                               const std::string &wallet_id,
                                               bool remove_locked = true);
  Transaction GetTransaction(Chain chain, const std::string &wallet_id,
                             const std::string &tx_id);
  bool UpdateTransaction(Chain chain, const std::string &wallet_id,
                         const std::string &raw_tx, int height,
                         time_t blocktime, const std::string &reject_msg = {});
  bool UpdateTransactionMemo(Chain chain, const std::string &wallet_id,
                             const std::string &tx_id, const std::string &memo);
  bool DeleteTransaction(Chain chain, const std::string &wallet_id,
                         const std::string &tx_id);
  Transaction CreatePsbt(Chain chain, const std::string &wallet_id,
                         const std::string &psbt, Amount fee = 0,
                         const std::string &memo = {}, int change_pos = -1,
                         const std::map<std::string, Amount> &outputs = {},
                         Amount fee_rate = -1,
                         bool subtract_fee_from_amount = false,
                         const std::string &replace_tx = {});
  bool UpdatePsbt(Chain chain, const std::string &wallet_id,
                  const std::string &psbt);
  bool UpdatePsbtTxId(Chain chain, const std::string &wallet_id,
                      const std::string &old_id, const std::string &new_id);
  std::string GetPsbt(Chain chain, const std::string &wallet_id,
                      const std::string &tx_id);
  bool SetUtxos(Chain chain, const std::string &wallet_id,
                const std::string &address, const std::string &utxo);
  Amount GetBalance(Chain chain, const std::string &wallet_id);
  std::string FillPsbt(Chain chain, const std::string &wallet_id,
                       const std::string &psbt);

  int GetChainTip(Chain chain);
  bool SetChainTip(Chain chain, int height);
  std::string GetSelectedWallet(Chain chain);
  bool SetSelectedWallet(Chain chain, const std::string &wallet_id);

  std::vector<SingleSigner> GetRemoteSigners(Chain chain);
  bool DeleteRemoteSigner(Chain chain, const std::string &master_fingerprint,
                          const std::string &derivation_path);
  bool UpdateRemoteSigner(Chain chain, const SingleSigner &remotesigner);
  bool IsMasterSigner(Chain chain, const std::string &id);
  int GetAddressIndex(Chain chain, const std::string &wallet_id,
                      const std::string &address);

 private:
  NunchukWalletDb GetWalletDb(Chain chain, const std::string &id);
  NunchukSignerDb GetSignerDb(Chain chain, const std::string &id);
  NunchukAppStateDb GetAppStateDb(Chain chain);
  std::string ChainStr(Chain chain) const;
  boost::filesystem::path GetWalletDir(Chain chain,
                                       const std::string &id) const;
  boost::filesystem::path GetSignerDir(Chain chain,
                                       const std::string &id) const;
  boost::filesystem::path GetAppStateDir(Chain chain) const;
  boost::filesystem::path GetDefaultDataDir() const;
  boost::filesystem::path datadir_;
  std::string passphrase_;
  boost::shared_mutex access_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_H
