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

#ifndef NUNCHUK_NUNCHUKIMPL_H
#define NUNCHUK_NUNCHUKIMPL_H

#include <descriptor.h>
#include <hwiservice.h>
#include <groupservice.h>
#include <nunchuk.h>
#include <coreutils.h>
#include <storage/storage.h>
#include <backend/synchronizer.h>
#include <map>
#include <tap_protocol/hwi_tapsigner.h>

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
                      const std::string& description = {},
                      bool allow_used_signer = false,
                      const std::string& decoy_pin = {}) override;
  Wallet CreateWallet(const std::string& name, int m, int n,
                      const std::vector<SingleSigner>& signers,
                      AddressType address_type, WalletType wallet_type,
                      const std::string& description = {},
                      bool allow_used_signer = false,
                      const std::string& decoy_pin = {}) override;
  Wallet CreateWallet(const Wallet& wallet, bool allow_used_signer = false,
                      const std::string& decoy_pin = {}) override;
  Wallet CloneWallet(const std::string& wallet_id,
                     const std::string& decoy_pin) override;
  Wallet CreateHotWallet(const std::string& mnemonic = {},
                         const std::string& passphrase = {},
                         bool need_backup = true, bool replace = true) override;
  std::string GetHotWalletMnemonic(const std::string& wallet_id,
                                   const std::string& passphrase = {}) override;
  std::string DraftWallet(const std::string& name, int m, int n,
                          const std::vector<SingleSigner>& signers,
                          AddressType address_type, bool is_escrow,
                          const std::string& desc = {}) override;
  std::string DraftWallet(const std::string& name, int m, int n,
                          const std::vector<SingleSigner>& signers,
                          AddressType address_type, WalletType wallet_type,
                          const std::string& desc = {}) override;
  std::vector<Wallet> GetWallets(const std::vector<OrderBy>& orders = {
                                     OrderBy::OLDEST_FIRST}) override;
  Wallet GetWallet(const std::string& wallet_id) override;
  bool HasWallet(const std::string& wallet_id) override;
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
  void ForceRefreshWallet(const std::string& wallet_id) override;

  std::vector<Device> GetDevices() override;
  MasterSigner CreateMasterSigner(
      const std::string& name, const Device& device,
      std::function<bool /* stop */ (int /* percent */)> progress) override;
  MasterSigner CreateSoftwareSigner(
      const std::string& name, const std::string& mnemonic,
      const std::string& passphrase,
      std::function<bool /* stop */ (int /* percent */)> progress,
      bool is_primary = false, bool replace = true) override;
  MasterSigner CreateSoftwareSignerFromMasterXprv(
      const std::string& name, const std::string& master_xprv,
      std::function<bool /* stop */ (int /* percent */)> progress,
      bool is_primary = false, bool replace = true) override;
  bool DeletePrimaryKey() override;
  std::string SignLoginMessage(const std::string& mastersigner_id,
                               const std::string& message) override;
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
                            const std::string& master_fingerprint,
                            SignerType signer_type = SignerType::AIRGAP,
                            std::vector<SignerTag> tags = {},
                            bool replace = false) override;
  bool HasSigner(const SingleSigner& signer) override;
  int GetCurrentIndexFromMasterSigner(const std::string& mastersigner_id,
                                      const WalletType& wallet_type,
                                      const AddressType& address_type) override;
  SingleSigner GetUnusedSignerFromMasterSigner(
      const std::string& mastersigner_id, const WalletType& wallet_type,
      const AddressType& address_type) override;
  SingleSigner GetDefaultSignerFromMasterSigner(
      const std::string& mastersigner_id, const WalletType& wallet_type,
      const AddressType& address_type) override;
  SingleSigner GetSigner(const std::string& xfp, const WalletType& wallet_type,
                         const AddressType& address_type, int index) override;
  int GetLastUsedSignerIndex(const std::string& xfp,
                             const WalletType& wallet_type,
                             const AddressType& address_type) override;
  SingleSigner GetSignerFromMasterSigner(const std::string& mastersigner_id,
                                         const std::string& path) override;
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
  std::string SignMessage(const SingleSigner& signer,
                          const std::string& message) override;
  std::string GetSignerAddress(
      const SingleSigner& signer,
      AddressType address_type = AddressType::LEGACY) override;

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
  bool MarkAddressAsUsed(const std::string& wallet_id,
                         const std::string& address) override;
  std::vector<UnspentOutput> GetUnspentOutputs(
      const std::string& wallet_id) override;
  std::vector<UnspentOutput> GetUnspentOutputsFromTxInputs(
      const std::string& wallet_id,
      const std::vector<TxInput>& inputs) override;
  std::vector<UnspentOutput> GetCoins(const std::string& wallet_id) override;
  std::vector<UnspentOutput> GetCoinsFromTxInputs(
      const std::string& wallet_id,
      const std::vector<TxInput>& inputs) override;
  bool ExportUnspentOutputs(const std::string& wallet_id,
                            const std::string& file_path,
                            ExportFormat format) override;
  Transaction CreateTransaction(const std::string& wallet_id,
                                const std::map<std::string, Amount>& outputs,
                                const std::string& memo = {},
                                const std::vector<UnspentOutput>& inputs = {},
                                Amount fee_rate = -1,
                                bool subtract_fee_from_amount = false,
                                const std::string& replace_txid = {}) override;
  bool ExportTransaction(const std::string& wallet_id, const std::string& tx_id,
                         const std::string& file_path) override;
  Transaction ImportTransaction(const std::string& wallet_id,
                                const std::string& file_path) override;
  Transaction ImportPsbt(const std::string& wallet_id, const std::string& psbt,
                         bool throw_if_unchanged = true) override;
  Transaction SignTransaction(const std::string& wallet_id,
                              const std::string& tx_id,
                              const Device& device) override;
  Transaction SignTransaction(const Wallet& wallet, const Transaction& tx,
                              const Device& device) override;
  void SetPreferScriptPath(const Wallet& wallet, const std::string& tx_id,
                           bool value) override;
  bool IsPreferScriptPath(const Wallet& wallet,
                          const std::string& tx_id) override;
  Transaction BroadcastTransaction(const std::string& wallet_id,
                                   const std::string& tx_id) override;
  Transaction GetTransaction(const std::string& wallet_id,
                             const std::string& tx_id) override;
  std::string GetRawTransaction(const std::string& wallet_id,
                                const std::string& tx_id) override;
  bool DeleteTransaction(const std::string& wallet_id,
                         const std::string& tx_id) override;

  Transaction DraftTransaction(const std::string& wallet_id,
                               const std::map<std::string, Amount>& outputs,
                               const std::vector<UnspentOutput>& inputs = {},
                               Amount fee_rate = -1,
                               bool subtract_fee_from_amount = false,
                               const std::string& replace_txid = {}) override;
  Transaction ReplaceTransaction(const std::string& wallet_id,
                                 const std::string& tx_id,
                                 Amount new_fee_rate) override;
  bool ReplaceTransactionId(const std::string& wallet_id,
                            const std::string& txid,
                            const std::string& replace_txid) override;
  Transaction UpdateTransaction(const std::string& wallet_id,
                                const std::string& tx_id,
                                const std::string& new_txid,
                                const std::string& raw_tx,
                                const std::string& reject_msg = {}) override;
  bool UpdateTransactionMemo(const std::string& wallet_id,
                             const std::string& tx_id,
                             const std::string& new_memo) override;
  bool UpdateTransactionSchedule(const std::string& wallet_id,
                                 const std::string& tx_id,
                                 time_t broadcast_ts) override;
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
  void SendPassphraseToDevice(const Device& device,
                              const std::string& passphrase) override;
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
      const std::string& wallet_id, int fragment_len = 200) override;
  std::vector<std::string> ExportKeystoneTransaction(
      const std::string& wallet_id, const std::string& tx_id,
      int fragment_len = 200) override;
  Transaction ImportKeystoneTransaction(
      const std::string& wallet_id,
      const std::vector<std::string>& qr_data) override;
  Wallet ImportKeystoneWallet(const std::vector<std::string>& qr_data,
                              const std::string& description = {}) override;

  std::vector<SingleSigner> ParsePassportSigners(
      const std::vector<std::string>& qr_data) override;
  std::vector<std::string> ExportPassportWallet(
      const std::string& wallet_id, int fragment_len = 200) override;
  std::vector<std::string> ExportPassportTransaction(
      const std::string& wallet_id, const std::string& tx_id,
      int fragment_len = 200) override;
  Transaction ImportPassportTransaction(
      const std::string& wallet_id,
      const std::vector<std::string>& qr_data) override;

  std::vector<SingleSigner> ParseSeedSigners(
      const std::vector<std::string>& qr_data) override;
  std::vector<SingleSigner> ParseQRSigners(
      const std::vector<std::string>& qr_data) override;

  std::vector<std::string> ExportBCR2020010Wallet(
      const std::string& wallet_id, int fragment_len = 200) override;

  // NFC
  std::unique_ptr<tap_protocol::CKTapCard> CreateCKTapCard(
      std::unique_ptr<tap_protocol::Transport> transport) override;
  void WaitCKTapCard(tap_protocol::CKTapCard* card,
                     std::function<bool(int)> progress) override;

  // TAPSIGNER
  MasterSigner ImportTapsignerMasterSigner(const std::string& file_path,
                                           const std::string& backup_key,
                                           const std::string& name,
                                           std::function<bool(int)> progress,
                                           bool is_primary = false) override;
  MasterSigner ImportTapsignerMasterSigner(
      const std::vector<unsigned char>& data, const std::string& backup_key,
      const std::string& name, std::function<bool(int)> progress,
      bool is_primary = false) override;
  void VerifyTapsignerBackup(const std::string& file_path,
                             const std::string& backup_key,
                             const std::string& master_signer_id = {}) override;
  void VerifyTapsignerBackup(const std::vector<unsigned char>& data,
                             const std::string& backup_key,
                             const std::string& master_signer_id = {}) override;
  std::unique_ptr<tap_protocol::Tapsigner> CreateTapsigner(
      std::unique_ptr<tap_protocol::Transport> transport) override;
  TapsignerStatus GetTapsignerStatus(
      tap_protocol::Tapsigner* tapsigner) override;
  void InitTapsigner(tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
                     const std::string& chain_code = {}) override;
  TapsignerStatus SetupTapsigner(tap_protocol::Tapsigner* tapsigner,
                                 const std::string& cvc,
                                 const std::string& new_cvc,
                                 const std::string& derivation_path = {},
                                 const std::string& chain_code = {}) override;
  MasterSigner CreateTapsignerMasterSigner(tap_protocol::Tapsigner* tapsigner,
                                           const std::string& cvc,
                                           const std::string& name,
                                           std::function<bool(int)> progress,
                                           bool is_primary = false,
                                           bool replace = true) override;
  Transaction SignTapsignerTransaction(tap_protocol::Tapsigner* tapsigner,
                                       const std::string& cvc,
                                       const std::string& wallet_id,
                                       const std::string& tx_id) override;
  bool ChangeTapsignerCVC(tap_protocol::Tapsigner* tapsigner,
                          const std::string& cvc, const std::string& new_cvc,
                          const std::string& master_signer_id = {}) override;
  TapsignerStatus BackupTapsigner(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& master_signer_id = {}) override;
  HealthStatus HealthCheckTapsignerMasterSigner(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& master_signer_id, std::string& message,
      std::string& signature, std::string& path) override;
  SingleSigner GetSignerFromTapsignerMasterSigner(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& mastersigner_id, const std::string& path) override;
  SingleSigner GetSignerFromTapsignerMasterSigner(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& master_signer_id, const WalletType& wallet_type,
      const AddressType& address_type, int index) override;
  std::string SignTapsignerMessage(tap_protocol::Tapsigner* tapsigner,
                                   const std::string& cvc,
                                   const SingleSigner& signer,
                                   const std::string& message) override;
  TapsignerStatus WaitTapsigner(tap_protocol::Tapsigner* tapsigner,
                                std::function<bool(int)> progress) override;
  void CacheTapsignerMasterSignerXPub(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& master_signer_id,
      std::function<bool /* stop */ (int /* percent */)> progress) override;
  void CacheDefaultTapsignerMasterSignerXPub(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& master_signer_id,
      std::function<bool /* stop */ (int /* percent */)> progress) override;
  TapsignerStatus GetTapsignerStatusFromMasterSigner(
      const std::string& master_signer_id) override;
  void AddTapsigner(const std::string& card_ident, const std::string& xfp,
                    const std::string& name, const std::string& version = {},
                    int birth_height = 0, bool is_testnet = false,
                    bool replace = false) override;

  // SATSCARD
  std::unique_ptr<tap_protocol::Satscard> CreateSatscard(
      std::unique_ptr<tap_protocol::Transport> transport) override;
  SatscardStatus GetSatscardStatus(tap_protocol::Satscard* satscard) override;
  SatscardStatus SetupSatscard(tap_protocol::Satscard* satscard,
                               const std::string& cvc,
                               const std::string& chain_code = {}) override;
  SatscardSlot UnsealSatscard(tap_protocol::Satscard* satscard,
                              const std::string& cvc,
                              const SatscardSlot& slot = {}) override;
  SatscardSlot FetchSatscardSlotUTXOs(const SatscardSlot& slot) override;
  SatscardSlot GetSatscardSlotKey(tap_protocol::Satscard* satscard,
                                  const std::string& cvc,
                                  const SatscardSlot& slot) override;
  Transaction CreateSatscardSlotsTransaction(
      const std::vector<SatscardSlot>& slots, const std::string& address,
      Amount fee_rate = -1) override;
  Transaction SweepSatscardSlot(const SatscardSlot& slot,
                                const std::string& address,
                                Amount fee_rate = -1) override;
  Transaction SweepSatscardSlots(const std::vector<SatscardSlot>& slots,
                                 const std::string& address,
                                 Amount fee_rate = -1) override;
  SatscardStatus WaitSatscard(tap_protocol::Satscard* satscard,
                              std::function<bool(int)> progress) override;
  Transaction FetchTransaction(const std::string& tx_id) override;

  // Coldcard mk4
  std::vector<SingleSigner> ParseJSONSigners(
      const std::string& json_str,
      SignerType signer_type = SignerType::COLDCARD_NFC) override;
  std::vector<Wallet> ParseJSONWallets(const std::string& json_str) override;
  Transaction ImportRawTransaction(const std::string& wallet_id,
                                   const std::string& raw_tx,
                                   const std::string& tx_id = {}) override;
  std::string GetWalletExportData(const std::string& wallet_id,
                                  ExportFormat format) override;
  std::string GetWalletExportData(const Wallet& wallet,
                                  ExportFormat format) override;
  void VerifyColdcardBackup(const std::vector<unsigned char>& data,
                            const std::string& backup_key,
                            const std::string& master_signer_id = {}) override;
  MasterSigner ImportColdcardBackup(const std::vector<unsigned char>& data,
                                    const std::string& backup_key,
                                    const std::string& name,
                                    std::function<bool(int)> progress,
                                    bool is_primary = false) override;
  MasterSigner ImportBackupKey(const std::vector<unsigned char>& data,
                               const std::string& backup_key,
                               const std::string& name,
                               std::function<bool(int)> progress,
                               bool is_primary = false) override;

  void RescanBlockchain(int start_height, int stop_height = -1) override;
  void ScanWalletAddress(const std::string& wallet_id,
                         bool force = false) override;

  void AddBalanceListener(
      std::function<void(std::string, Amount)> listener) override;
  void AddBalancesListener(
      std::function<void(std::string, Amount, Amount)> listener) override;
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

  std::string SignHealthCheckMessage(const SingleSigner& signer,
                                     const std::string& message) override;
  std::string SignHealthCheckMessage(tap_protocol::Tapsigner* tapsigner,
                                     const std::string& cvc,
                                     const SingleSigner& signer,
                                     const std::string& message) override;

  // Coin control
  bool UpdateCoinMemo(const std::string& wallet_id, const std::string& tx_id,
                      int vout, const std::string& memo) override;
  bool LockCoin(const std::string& wallet_id, const std::string& tx_id,
                int vout) override;
  bool UnlockCoin(const std::string& wallet_id, const std::string& tx_id,
                  int vout) override;

  CoinTag CreateCoinTag(const std::string& wallet_id, const std::string& name,
                        const std::string& color) override;
  std::vector<CoinTag> GetCoinTags(const std::string& wallet_id) override;
  bool UpdateCoinTag(const std::string& wallet_id, const CoinTag& tag) override;
  bool DeleteCoinTag(const std::string& wallet_id, int tag_id) override;
  bool AddToCoinTag(const std::string& wallet_id, int tag_id,
                    const std::string& tx_id, int vout) override;
  bool RemoveFromCoinTag(const std::string& wallet_id, int tag_id,
                         const std::string& tx_id, int vout) override;
  std::vector<UnspentOutput> GetCoinByTag(const std::string& wallet_id,
                                          int tag_id) override;

  CoinCollection CreateCoinCollection(const std::string& wallet_id,
                                      const std::string& name) override;
  std::vector<CoinCollection> GetCoinCollections(
      const std::string& wallet_id) override;
  bool UpdateCoinCollection(const std::string& wallet_id,
                            const CoinCollection& collection,
                            bool apply_to_existing_coins = false) override;
  bool DeleteCoinCollection(const std::string& wallet_id,
                            int collection_id) override;
  bool AddToCoinCollection(const std::string& wallet_id, int collection_id,
                           const std::string& tx_id, int vout) override;
  bool RemoveFromCoinCollection(const std::string& wallet_id, int collection_id,
                                const std::string& tx_id, int vout) override;
  std::vector<UnspentOutput> GetCoinInCollection(const std::string& wallet_id,
                                                 int collection_id) override;

  std::string ExportCoinControlData(const std::string& wallet_id) override;
  bool ImportCoinControlData(const std::string& wallet_id,
                             const std::string& data, bool force) override;
  std::string ExportBIP329(const std::string& wallet_id) override;
  void ImportBIP329(const std::string& wallet_id,
                    const std::string& data) override;

  bool IsMyAddress(const std::string& wallet_id,
                   const std::string& address) override;
  std::string GetAddressPath(const std::string& wallet_id,
                             const std::string& address) override;
  int GetAddressIndex(const std::string& wallet_id,
                      const std::string& address) override;

  std::vector<std::vector<UnspentOutput>> GetCoinAncestry(
      const std::string& wallet_id, const std::string& tx_id,
      int vout) override;

  bool IsCPFP(const std::string& wallet_id, const Transaction& tx,
              Amount& package_fee_rate) override;

  // Dummy transaction
  std::pair<std::string, Transaction> ImportDummyTx(
      const std::string& dummy_transaction) override;
  RequestTokens SaveDummyTxRequestToken(const std::string& wallet_id,
                                        const std::string& id,
                                        const std::string& token) override;
  bool DeleteDummyTx(const std::string& wallet_id,
                     const std::string& id) override;
  RequestTokens GetDummyTxRequestToken(const std::string& wallet_id,
                                       const std::string& id) override;
  std::map<std::string, Transaction> GetDummyTxs(
      const std::string& wallet_id) override;
  Transaction GetDummyTx(const std::string& wallet_id,
                         const std::string& id) override;

  int EstimateRollOverTransactionCount(
      const std::string& wallet_id, const std::set<int>& tags,
      const std::set<int>& collections) override;
  std::pair<Amount, Amount> EstimateRollOverAmount(
      const std::string& old_wallet_id, const std::string& new_wallet_id,
      const std::set<int>& tags, const std::set<int>& collections,
      Amount fee_rate = -1) override;
  std::map<std::pair<std::set<int>, std::set<int>>, Transaction>
  DraftRollOverTransactions(const std::string& old_wallet_id,
                            const std::string& new_wallet_id,
                            const std::set<int>& tags,
                            const std::set<int>& collections,
                            Amount fee_rate = -1) override;
  std::vector<Transaction> CreateRollOverTransactions(
      const std::string& old_wallet_id, const std::string& new_wallet_id,
      const std::set<int>& tags, const std::set<int>& collections,
      Amount fee_rate = -1) override;

  // Group Wallet
  void EnableGroupWallet(const std::string& osName,
                         const std::string& osVersion,
                         const std::string& appVersion,
                         const std::string& deviceClass,
                         const std::string& deviceId,
                         const std::string& accessToken) override;
  void StartConsumeGroupEvent() override;
  void StopConsumeGroupEvent() override;
  SandboxGroup CreateGroup(int m, int n, AddressType addressType,
                           const SingleSigner& signer = {}) override;
  SandboxGroup GetGroup(const std::string& groupId) override;
  std::vector<SandboxGroup> GetGroups() override;
  SandboxGroup JoinGroup(const std::string& groupId) override;
  SandboxGroup AddSignerToGroup(const std::string& groupId,
                                const SingleSigner& signer) override;
  SandboxGroup UpdateGroup(const std::string& groupId, int m, int n,
                           AddressType addressType,
                           const SingleSigner& signer = {}) override;
  SandboxGroup FinalizeGroup(const std::string& groupId) override;
  void SendGroupMessage(const std::string& walletId,
                        const std::string& msg) override;
  void AddGroupUpdateListener(
      std::function<void(const SandboxGroup& state)> listener) override;
  void AddGroupMessageListener(
      std::function<void(const GroupMessage& msg)> listener) override;

 private:
  std::string CreatePsbt(const std::string& wallet_id,
                         const std::map<std::string, Amount>& outputs,
                         const std::vector<UnspentOutput>& inputs,
                         Amount fee_rate, bool subtract_fee_from_amount,
                         bool utxo_update_psbt, Amount& fee, int& vsize,
                         int& change_pos);
  Wallet ImportWalletFromConfig(const std::string& config,
                                const std::string& description);
  void RunScanWalletAddress(const std::string& wallet_id);
  // Find the first unused address that the next 19 addresses are unused too
  std::string GetUnusedAddress(const Wallet& wallet, int& index, bool internal);

  AppSettings app_settings_;
  std::string account_;
  Chain chain_;
  HWIService hwi_;
  std::shared_ptr<NunchukStorage> storage_;
  std::unique_ptr<tap_protocol::HWITapsigner> hwi_tapsigner_;
  std::unique_ptr<Synchronizer> synchronizer_;
  boost::signals2::signal<void(std::string, bool)> device_listener_;
  boost::signals2::signal<void()> storage_listener_;
  std::vector<std::future<void>> scan_wallet_;

  // Cache
  time_t estimate_fee_cached_time_[ESTIMATE_FEE_CACHE_SIZE];
  Amount estimate_fee_cached_value_[ESTIMATE_FEE_CACHE_SIZE];
  static std::map<std::string, time_t> last_scan_;

  // Group wallet
  bool group_wallet_enable_{false};
  GroupService group_service_;
  boost::signals2::signal<void(const SandboxGroup&)> group_wallet_listener_;
  boost::signals2::signal<void(const GroupMessage&)> group_message_listener_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_NUNCHUKIMPL_H
