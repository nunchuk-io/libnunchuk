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

#ifndef NUNCHUK_STORAGE_H
#define NUNCHUK_STORAGE_H

#include "primarydb.h"
#include "walletdb.h"
#include "signerdb.h"
#include "appstatedb.h"
#include "roomdb.h"
#include "tapprotocoldb.h"

#include <boost/filesystem.hpp>
#include <shared_mutex>
#include <iostream>
#include <map>
#include <string>

namespace nunchuk {

class NunchukStorage {
 public:
  static std::shared_ptr<NunchukStorage> get(const std::string &account);

  NunchukStorage(const std::string &account);
  void Init(const std::string &datadir, const std::string &passphrase = "");
  void MaybeMigrate(Chain chain);
  bool WriteFile(const std::string &file_path, const std::string &value);
  std::string LoadFile(const std::string &file_path);
  bool ExportWallet(Chain chain, const std::string &wallet_id,
                    const std::string &file_path, ExportFormat format);
  std::string GetWalletExportData(Chain chain, const std::string &wallet_id,
                                  ExportFormat format);
  std::string ImportWalletDb(Chain chain, const std::string &file_path);
  void SetPassphrase(Chain chain, const std::string &new_passphrase);
  Wallet CreateWallet(Chain chain, const Wallet &wallet);
  std::string CreateMasterSigner(Chain chain, const std::string &name,
                                 const Device &device,
                                 const std::string &mnemonic = {});
  std::string CreateMasterSignerFromMasterXprv(
      Chain chain, const std::string &name, const Device &device,
      const std::string &master_xprv = {});
  SingleSigner CreateSingleSigner(Chain chain, const std::string &name,
                                  const std::string &xpub,
                                  const std::string &public_key,
                                  const std::string &derivation_path,
                                  const std::string &master_fingerprint,
                                  SignerType signer_type = SignerType::AIRGAP);
  SingleSigner GetSignerFromMasterSigner(Chain chain,
                                         const std::string &mastersigner_id,
                                         const WalletType &wallet_type,
                                         const AddressType &address_type,
                                         int index);
  SingleSigner GetSignerFromMasterSigner(Chain chain,
                                         const std::string &mastersigner_id,
                                         const std::string &path);

  std::vector<std::string> ListWallets(Chain chain);
  std::vector<std::string> ListRecentlyUsedWallets(Chain chain);
  std::vector<std::string> ListMasterSigners(Chain chain);

  Wallet GetWallet(Chain chain, const std::string &id,
                   bool create_signers_if_not_exist = false);
  bool HasWallet(Chain chain, const std::string &wallet_id);
  MasterSigner GetMasterSigner(Chain chain, const std::string &id);
  SoftwareSigner GetSoftwareSigner(Chain chain, const std::string &id);
  bool HasSigner(Chain chain, const SingleSigner &signer);

  bool UpdateWallet(Chain chain, const Wallet &wallet);
  bool UpdateMasterSigner(Chain chain, const MasterSigner &mastersigner);

  bool DeleteWallet(Chain chain, const std::string &id);
  bool DeleteMasterSigner(Chain chain, const std::string &id);

  std::vector<SingleSigner> GetSignersFromMasterSigner(
      Chain chain, const std::string &mastersigner_id);
  void CacheMasterSignerXPub(Chain chain, const std::string &mastersigner_id,
                             std::function<std::string(std::string)> getxpub,
                             std::function<bool(int)> progress, bool first);
  bool CacheDefaultMasterSignerXpub(
      Chain chain, const std::string &mastersigner_id,
      std::function<std::string(std::string)> getxpub,
      std::function<bool(int)> progress);

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
  std::vector<UnspentOutput> GetUtxos(Chain chain,
                                      const std::string &wallet_id);
  Transaction GetTransaction(Chain chain, const std::string &wallet_id,
                             const std::string &tx_id);
  bool UpdateTransaction(Chain chain, const std::string &wallet_id,
                         const std::string &raw_tx, int height,
                         time_t blocktime, const std::string &reject_msg = {});
  bool UpdateTransactionMemo(Chain chain, const std::string &wallet_id,
                             const std::string &tx_id, const std::string &memo);
  bool UpdateTransactionSchedule(Chain chain, const std::string &wallet_id,
                                 const std::string &tx_id, time_t value);
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
  std::pair<std::string, bool> GetPsbtOrRawTx(Chain chain,
                                              const std::string &wallet_id,
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
  std::string GetAddressStatus(Chain chain, const std::string &wallet_id,
                               const std::string &address);
  std::string GetMultisigConfig(Chain chain, const std::string &wallet_id);
  void SendSignerPassphrase(Chain chain, const std::string &mastersigner_id,
                            const std::string &passphrase);
  void ClearSignerPassphrase(Chain chain, const std::string &mastersigner_id);
  NunchukRoomDb GetRoomDb(Chain chain);
  std::string ExportBackup();
  bool SyncWithBackup(const std::string &data,
                      std::function<bool(int)> progress);
  time_t GetLastSyncTs();
  time_t GetLastExportTs();

  std::vector<PrimaryKey> GetPrimaryKeys(Chain chain);
  bool AddPrimaryKey(Chain chain, const PrimaryKey &key);
  bool RemovePrimaryKey(Chain chain, const std::string &account);

  bool AddTapsigner(Chain chain, const TapsignerStatus &status);
  TapsignerStatus GetTapsignerStatusFromCardIdent(
      Chain chain, const std::string &card_ident);
  TapsignerStatus GetTapsignerStatusFromMasterSigner(
      Chain chain, const std::string &master_signer_id);
  bool DeleteTapsigner(Chain chain, const std::string &master_signer_id);

 private:
  static std::map<std::string, std::shared_ptr<NunchukStorage>> instances_;
  static std::shared_mutex access_;

  NunchukWalletDb GetWalletDb(Chain chain, const std::string &id);
  NunchukSignerDb GetSignerDb(Chain chain, const std::string &id);
  NunchukAppStateDb GetAppStateDb(Chain chain);
  NunchukPrimaryDb GetPrimaryDb(Chain chain);
  NunchukTapprotocolDb GetTaprotocolDb(Chain chain);
  std::string ChainStr(Chain chain) const;
  boost::filesystem::path GetWalletDir(Chain chain,
                                       const std::string &id) const;
  boost::filesystem::path GetSignerDir(Chain chain,
                                       const std::string &id) const;
  boost::filesystem::path GetAppStateDir(Chain chain) const;
  boost::filesystem::path GetPrimaryDir(Chain chain) const;
  boost::filesystem::path GetRoomDir(Chain chain) const;
  boost::filesystem::path GetTapprotocolDir(Chain chain) const;
  boost::filesystem::path GetDefaultDataDir() const;
  Wallet CreateWallet0(Chain chain, const Wallet &wallet);
  SingleSigner GetTrueSigner0(Chain chain, const SingleSigner &signer,
                              bool create_if_not_exist) const;
  std::vector<std::string> ListWallets0(Chain chain);
  std::vector<std::string> ListMasterSigners0(Chain chain);
  SoftwareSigner GetSoftwareSigner0(Chain chain, const std::string &id);

  boost::filesystem::path basedatadir_;
  boost::filesystem::path datadir_;
  std::string passphrase_;
  std::string account_;
  std::map<std::string, std::string> signer_passphrase_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_H
