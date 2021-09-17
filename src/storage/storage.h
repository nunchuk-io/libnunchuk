// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_STORAGE_H
#define NUNCHUK_STORAGE_H

#include "walletdb.h"
#include "signerdb.h"
#include "appstatedb.h"
#include "roomdb.h"

#include <boost/filesystem.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <iostream>
#include <map>
#include <string>

namespace nunchuk {

class NunchukStorage {
 public:
  NunchukStorage(const std::string &datadir = "",
                 const std::string &passphrase = "",
                 const std::string &account = "");

  void MaybeMigrate(Chain chain);
  bool WriteFile(const std::string &file_path, const std::string &value);
  std::string LoadFile(const std::string &file_path);
  bool ExportWallet(Chain chain, const std::string &wallet_id,
                    const std::string &file_path, ExportFormat format);
  std::string ImportWalletDb(Chain chain, const std::string &file_path);
  void SetPassphrase(const std::string &new_passphrase);
  Wallet CreateWallet(Chain chain, const std::string &name, int m, int n,
                      const std::vector<SingleSigner> &signers,
                      AddressType address_type, bool is_escrow,
                      const std::string &description);
  std::string CreateMasterSigner(Chain chain, const std::string &name,
                                 const Device &device,
                                 const std::string &mnemonic = {});
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
  SoftwareSigner GetSoftwareSigner(Chain chain, const std::string &id);

  bool UpdateWallet(Chain chain, const Wallet &wallet);
  bool UpdateMasterSigner(Chain chain, const MasterSigner &mastersigner);

  bool DeleteWallet(Chain chain, const std::string &id);
  bool DeleteMasterSigner(Chain chain, const std::string &id);

  std::vector<SingleSigner> GetSignersFromMasterSigner(
      Chain chain, const std::string &mastersigner_id);
  void CacheMasterSignerXPub(Chain chain, const std::string &mastersigner_id,
                             std::function<std::string(std::string)> getxpub,
                             std::function<bool(int)> progress, bool first);
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
  Amount GetAddressBalance(Chain chain, const std::string &wallet_id,
                           const std::string &address);
  std::string GetMultisigConfig(Chain chain, const std::string &wallet_id,
                                bool is_cobo);
  void SendSignerPassphrase(Chain chain, const std::string &mastersigner_id,
                            const std::string &passphrase);
  void ClearSignerPassphrase(Chain chain, const std::string &mastersigner_id);
  NunchukRoomDb GetRoomDb(Chain chain);
  std::string ExportBackup();
  bool SyncWithBackup(const std::string &data,
                      std::function<bool(int)> progress);

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
  boost::filesystem::path GetRoomDir(Chain chain) const;
  boost::filesystem::path GetDefaultDataDir() const;
  void SetPassphrase(Chain chain, const std::string &new_passphrase);
  Wallet CreateWallet0(Chain chain, const std::string &name, int m, int n,
                       const std::vector<SingleSigner> &signers,
                       AddressType address_type, bool is_escrow,
                       const std::string &description, time_t create_date);
  boost::filesystem::path datadir_;
  std::string passphrase_;
  std::string account_;
  boost::shared_mutex access_;
  std::map<std::string, std::string> signer_passphrase_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_H
