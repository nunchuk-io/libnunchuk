// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_NUNCHUKIMPL_H
#define NUNCHUK_NUNCHUKIMPL_H

#include <descriptor.h>
#include <hwiservice.h>
#include <nunchuk.h>
#include <coreutils.h>
#include <storage/storage.h>
#include <backend/synchronizer.h>

namespace nunchuk {

const int ESTIMATE_FEE_CACHE_SIZE = 6;

class NunchukImpl : public Nunchuk {
 public:
  NunchukImpl(const AppSettings& appsettings, const std::string& passphrase,
              const std::string& account);
  NunchukImpl(const NunchukImpl&) = delete;
  NunchukImpl& operator=(const NunchukImpl&) = delete;
  ~NunchukImpl() override;

  void SetPassphrase(const std::string& passphrase) override;
  Wallet CreateWallet(const std::string& name, int m, int n,
                      const std::vector<SingleSigner>& signers,
                      AddressType address_type, bool is_escrow,
                      const std::string& description = {}) override;
  std::string DraftWallet(const std::string& name, int m, int n,
                          const std::vector<SingleSigner>& signers,
                          AddressType address_type, bool is_escrow,
                          const std::string& desc = {}) override;
  std::vector<Wallet> GetWallets() override;
  Wallet GetWallet(const std::string& wallet_id) override;
  bool DeleteWallet(const std::string& wallet_id) override;
  bool UpdateWallet(const Wallet& wallet) override;
  bool ExportWallet(const std::string& wallet_id, const std::string& file_path,
                    ExportFormat format) override;
  Wallet ImportWalletDb(const std::string& file_path) override;
  Wallet ImportWalletDescriptor(const std::string& file_path,
                                const std::string& name,
                                const std::string& description = {}) override;
  Wallet ImportWalletConfigFile(const std::string& file_path,
                                const std::string& description = {}) override;

  std::vector<Device> GetDevices() override;
  MasterSigner CreateMasterSigner(
      const std::string& name, const Device& device,
      std::function<bool /* stop */ (int /* percent */)> progress) override;
  MasterSigner CreateSoftwareSigner(
      const std::string& name, const std::string& mnemonic,
      const std::string& passphrase,
      std::function<bool /* stop */ (int /* percent */)> progress) override;
  void SendSignerPassphrase(const std::string& mastersigner_id,
                            const std::string& passphrase) override;
  void ClearSignerPassphrase(const std::string& mastersigner_id) override;
  SingleSigner GetSignerFromMasterSigner(const std::string& mastersigner_id,
                                         const WalletType& wallet_type,
                                         const AddressType& address_type,
                                         int index) override;
  SingleSigner CreateSigner(const std::string& name, const std::string& xpub,
                            const std::string& public_key,
                            const std::string& derivation_path,
                            const std::string& master_fingerprint) override;
  int GetCurrentIndexFromMasterSigner(const std::string& mastersigner_id,
                                      const WalletType& wallet_type,
                                      const AddressType& address_type) override;
  SingleSigner GetUnusedSignerFromMasterSigner(
      const std::string& mastersigner_id, const WalletType& wallet_type,
      const AddressType& address_type) override;
  std::vector<SingleSigner> GetSignersFromMasterSigner(
      const std::string& mastersigner_id) override;
  int GetNumberOfSignersFromMasterSigner(
      const std::string& mastersigner_id) override;
  std::vector<MasterSigner> GetMasterSigners() override;
  MasterSigner GetMasterSigner(const std::string& mastersigner_id) override;
  bool DeleteMasterSigner(const std::string& mastersigner_id) override;
  bool UpdateMasterSigner(const MasterSigner& mastersigner_id) override;
  std::vector<SingleSigner> GetRemoteSigners() override;
  bool DeleteRemoteSigner(const std::string& master_fingerprint,
                          const std::string& derivation_path) override;
  bool UpdateRemoteSigner(const SingleSigner& remotesigner) override;
  std::string GetHealthCheckPath() override;
  HealthStatus HealthCheckMasterSigner(const std::string& fingerprint,
                                       std::string& message,
                                       std::string& signature,
                                       std::string& path) override;
  HealthStatus HealthCheckSingleSigner(const SingleSigner& signer,
                                       const std::string& message,
                                       const std::string& signature) override;

  std::vector<Transaction> GetTransactionHistory(const std::string& wallet_id,
                                                 int count, int skip) override;
  bool ExportTransactionHistory(const std::string& wallet_id,
                                const std::string& file_path,
                                ExportFormat format) override;
  AppSettings GetAppSettings() override;
  AppSettings UpdateAppSettings(const AppSettings& app_settings) override;

  std::vector<std::string> GetAddresses(const std::string& wallet_id,
                                        bool used = false,
                                        bool internal = false) override;
  std::string NewAddress(const std::string& wallet_id,
                         bool internal = false) override;
  Amount GetAddressBalance(const std::string& wallet_id,
                           const std::string& address) override;
  std::vector<UnspentOutput> GetUnspentOutputs(
      const std::string& wallet_id) override;
  bool ExportUnspentOutputs(const std::string& wallet_id,
                            const std::string& file_path,
                            ExportFormat format) override;
  Transaction CreateTransaction(const std::string& wallet_id,
                                const std::map<std::string, Amount> outputs,
                                const std::string& memo = {},
                                const std::vector<UnspentOutput> inputs = {},
                                Amount fee_rate = -1,
                                bool subtract_fee_from_amount = false) override;
  bool ExportTransaction(const std::string& wallet_id, const std::string& tx_id,
                         const std::string& file_path) override;
  Transaction ImportTransaction(const std::string& wallet_id,
                                const std::string& file_path) override;
  Transaction ImportPsbt(const std::string& wallet_id,
                         const std::string& psbt) override;
  Transaction SignTransaction(const std::string& wallet_id,
                              const std::string& tx_id,
                              const Device& device) override;
  Transaction BroadcastTransaction(const std::string& wallet_id,
                                   const std::string& tx_id) override;
  Transaction GetTransaction(const std::string& wallet_id,
                             const std::string& tx_id) override;
  bool DeleteTransaction(const std::string& wallet_id,
                         const std::string& tx_id) override;

  Transaction DraftTransaction(const std::string& wallet_id,
                               const std::map<std::string, Amount> outputs,
                               const std::vector<UnspentOutput> inputs = {},
                               Amount fee_rate = -1,
                               bool subtract_fee_from_amount = false) override;
  Transaction ReplaceTransaction(const std::string& wallet_id,
                                 const std::string& tx_id,
                                 Amount new_fee_rate) override;
  bool UpdateTransactionMemo(const std::string& wallet_id,
                             const std::string& tx_id,
                             const std::string& new_memo) override;
  bool ExportHealthCheckMessage(const std::string& message,
                                const std::string& file_path) override;
  std::string ImportHealthCheckSignature(const std::string& file_path) override;

  void CacheMasterSignerXPub(const std::string& mastersigner_id,
                             std::function<bool(int)> progress) override;
  Amount EstimateFee(int conf_target = 6, bool use_mempool = true) override;
  int GetChainTip() override;
  Amount GetTotalAmount(const std::string& wallet_id,
                        const std::vector<TxInput>& inputs) override;
  std::string GetSelectedWallet() override;
  bool SetSelectedWallet(const std::string& wallet_id) override;
  void DisplayAddressOnDevice(
      const std::string& wallet_id, const std::string& address,
      const std::string& device_fingerprint = {}) override;
  void PromtPinOnDevice(const Device& device) override;
  void SendPinToDevice(const Device& device, const std::string& pin) override;
  std::string ExportBackup() override;
  bool SyncWithBackup(
      const std::string& data,
      std::function<bool /* stop */ (int /* percent */)> progress) override;

  SingleSigner CreateCoboSigner(const std::string& name,
                                const std::string& json_info) override;
  std::vector<std::string> ExportCoboWallet(
      const std::string& wallet_id) override;
  std::vector<std::string> ExportCoboTransaction(
      const std::string& wallet_id, const std::string& tx_id) override;
  Transaction ImportCoboTransaction(
      const std::string& wallet_id,
      const std::vector<std::string>& qr_data) override;
  Wallet ImportCoboWallet(const std::vector<std::string>& qr_data,
                          const std::string& description = {}) override;

  SingleSigner ParseKeystoneSigner(const std::string& qr_data) override;
  std::vector<std::string> ExportKeystoneWallet(
      const std::string& wallet_id) override;
  std::vector<std::string> ExportKeystoneTransaction(
      const std::string& wallet_id, const std::string& tx_id) override;
  Transaction ImportKeystoneTransaction(
      const std::string& wallet_id,
      const std::vector<std::string>& qr_data) override;
  Wallet ImportKeystoneWallet(const std::vector<std::string>& qr_data,
                              const std::string& description = {}) override;

  void RescanBlockchain(int start_height, int stop_height = -1) override;

  void AddBalanceListener(
      std::function<void(std::string, Amount)> listener) override;
  void AddBlockListener(
      std::function<void(int, std::string)> listener) override;
  void AddTransactionListener(
      std::function<void(std::string, TransactionStatus, std::string)> listener)
      override;
  void AddDeviceListener(
      std::function<void(std::string, bool)> listener) override;
  void AddBlockchainConnectionListener(
      std::function<void(ConnectionStatus, int)> listener) override;
  void AddStorageUpdateListener(std::function<void()> listener) override;

 private:
  std::string CreatePsbt(const std::string& wallet_id,
                         const std::map<std::string, Amount> outputs,
                         const std::vector<UnspentOutput> inputs,
                         Amount fee_rate, bool subtract_fee_from_amount,
                         bool utxo_update_psbt, Amount& fee, int& change_pos);
  Wallet ImportWalletFromConfig(const std::string& config,
                                const std::string& description);
  void ScanNewWallet(const std::string wallet_id, bool is_escrow);
  // Find the first unused address that the next 19 addresses are unused too
  std::string GetUnusedAddress(const std::string wallet_id, int& index,
                               bool internal);

  AppSettings app_settings_;
  NunchukStorage storage_;
  Chain chain_;
  HWIService hwi_;
  std::unique_ptr<Synchronizer> synchronizer_;
  boost::signals2::signal<void(std::string, bool)> device_listener_;
  boost::signals2::signal<void()> storage_listener_;
  std::vector<std::future<void>> scan_new_wallet_;

  // Cache
  time_t estimate_fee_cached_time_[ESTIMATE_FEE_CACHE_SIZE];
  Amount estimate_fee_cached_value_[ESTIMATE_FEE_CACHE_SIZE];
};

}  // namespace nunchuk

#endif  // NUNCHUK_NUNCHUKIMPL_H
