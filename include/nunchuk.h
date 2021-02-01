// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_INCLUDE_H
#define NUNCHUK_INCLUDE_H

#define NUNCHUK_EXPORT

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace nunchuk {

const int CONF_TARGET_PRIORITY = 2;
const int CONF_TARGET_STANDARD = 6;
const int CONF_TARGET_ECONOMICAL = 144;

typedef int64_t Amount;
typedef std::pair<std::string, int> TxInput;      // txid-vout pair
typedef std::pair<std::string, Amount> TxOutput;  // address-amount pair

enum class AddressType {
  ANY,
  LEGACY,
  NESTED_SEGWIT,
  NATIVE_SEGWIT,
};

enum class Chain {
  MAIN,
  TESTNET,
  REGTEST,
};

enum class BackendType {
  ELECTRUM,
  CORERPC,
};

enum class WalletType {
  SINGLE_SIG,
  MULTI_SIG,
  ESCROW,
};

enum class HealthStatus {
  SUCCESS,
  FINGERPRINT_NOT_MATCHED,
  NO_SIGNATURE,
  SIGNATURE_INVALID,
  KEY_NOT_MATCHED,
};

enum class TransactionStatus {
  PENDING_SIGNATURES,
  READY_TO_BROADCAST,
  NETWORK_REJECTED,
  PENDING_CONFIRMATION,
  REPLACED,
  CONFIRMED,
};

enum class ConnectionStatus {
  OFFLINE,
  SYNCING,
  ONLINE,
};

enum class ExportFormat {
  DB,
  DESCRIPTOR,
  COLDCARD,
  COBO,
  CSV,
};

enum class Unit {
  BTC,
  SATOSHI,
};

class NUNCHUK_EXPORT BaseException : public std::exception {
 public:
  explicit BaseException(int code, const char* message)
      : code_(code), message_(message) {}
  explicit BaseException(int code, const std::string& message)
      : code_(code), message_(message) {}
  int code() const noexcept { return code_; }
  const char* what() const noexcept { return message_.c_str(); }

 private:
  int code_;
  std::string message_;
};

class NUNCHUK_EXPORT NunchukException : public BaseException {
 public:
  // Nunchuk-defined error codes
  static const int INVALID_ADDRESS = -1001;
  static const int INVALID_AMOUNT = -1002;
  static const int INVALID_PSBT = -1003;
  static const int INVALID_RAW_TX = -1004;
  static const int INVALID_FEE_RATE = -1005;
  static const int INVALID_ADDRESS_TYPE = -1006;
  static const int INVALID_WALLET_TYPE = -1007;
  static const int AMOUNT_OUT_OF_RANGE = -1008;
  static const int RUN_OUT_OF_CACHED_XPUB = -1009;
  static const int MESSAGE_TOO_SHORT = -1010;
  static const int COIN_SELECTION_ERROR = -1011;
  static const int PSBT_INCOMPLETE = -1012;
  static const int SERVER_REQUEST_ERROR = -1013;
  static const int INVALID_PASSPHRASE = -1014;
  static const int PASSPHRASE_ALREADY_USED = -1015;
  static const int INVALID_CHAIN = -1016;
  static const int INVALID_PARAMETER = -1017;
  static const int CREATE_DUMMY_SIGNATURE_ERROR = -1018;
  static const int APP_RESTART_REQUIRED = -1019;
  static const int INVALID_FORMAT = -1020;
  using BaseException::BaseException;
};

class NUNCHUK_EXPORT StorageException : public BaseException {
 public:
  static const int WALLET_NOT_FOUND = -2001;
  static const int MASTERSIGNER_NOT_FOUND = -2002;
  static const int TX_NOT_FOUND = -2003;
  static const int SIGNER_USED = -2005;
  static const int INVALID_DATADIR = -2006;
  static const int SQL_ERROR = -2007;
  static const int WALLET_EXISTED = -2008;
  static const int SIGNER_EXISTS = -2009;
  static const int SIGNER_NOT_FOUND = -2010;
  static const int ADDRESS_NOT_FOUND = -2011;
  using BaseException::BaseException;
};

class NUNCHUK_EXPORT RPCException : public BaseException {
 public:
  // Error codes from contrib/bitcoin/src/rpc/protocol.h
  static const int RPC_MISC_ERROR = -3001;
  static const int RPC_TYPE_ERROR = -3003;
  static const int RPC_WALLET_EXISTS = -3004;
  static const int RPC_INVALID_ADDRESS_OR_KEY = -3005;
  static const int RPC_OUT_OF_MEMORY = -3007;
  static const int RPC_INVALID_PARAMETER = -3008;
  static const int RPC_WALLET_NOT_FOUND = -3018;
  static const int RPC_DATABASE_ERROR = -3020;
  static const int RPC_DESERIALIZATION_ERROR = -3022;
  static const int RPC_VERIFY_ERROR = -3025;
  static const int RPC_VERIFY_REJECTED = -3026;
  static const int RPC_VERIFY_ALREADY_IN_CHAIN = -3027;
  static const int RPC_IN_WARMUP = -3028;
  static const int RPC_METHOD_DEPRECATED = -3032;
  // Nunchuk-defined error codes
  static const int RPC_REQUEST_ERROR = -3099;
  using BaseException::BaseException;
};

class NUNCHUK_EXPORT HWIException : public BaseException {
 public:
  // Error codes from contrib/hwi/hwilib/errors.py
  static const int NO_DEVICE_TYPE = -4001;
  static const int MISSING_ARGUMENTS = -4002;
  static const int DEVICE_CONN_ERROR = -4003;
  static const int UNKNOWN_DEVICE_TYPE = -4004;
  static const int INVALID_TX = -4005;
  static const int NO_PASSWORD = -4006;
  static const int BAD_ARGUMENT = -4007;
  static const int NOT_IMPLEMENTED = -4008;
  static const int UNAVAILABLE_ACTION = -4009;
  static const int DEVICE_ALREADY_INIT = -4010;
  static const int DEVICE_ALREADY_UNLOCKED = -4011;
  static const int DEVICE_NOT_READY = -4012;
  static const int UNKNOWN_ERROR = -4013;
  static const int ACTION_CANCELED = -4014;
  static const int DEVICE_BUSY = -4015;
  static const int NEED_TO_BE_ROOT = -4016;
  static const int HELP_TEXT = -4017;
  static const int DEVICE_NOT_INITIALIZED = -4018;
  // Nunchuk-defined error codes
  static const int RUN_ERROR = -4099;
  static const int INVALID_RESULT = -4098;
  using BaseException::BaseException;
};

class NUNCHUK_EXPORT Device {
 public:
  Device(const std::string& fingerprint);
  Device(const std::string& type, const std::string& path,
         const std::string& model, const std::string& master_fingerprint,
         bool needs_pass_phrase_sent, bool needs_pin_sent,
         bool initialized = true);

  std::string get_type() const;
  std::string get_path() const;
  std::string get_model() const;
  std::string get_master_fingerprint() const;
  bool connected() const;
  bool needs_pass_phrase_sent() const;
  bool needs_pin_sent() const;
  bool initialized() const;

 private:
  std::string type_;
  std::string path_;
  std::string model_;
  std::string master_fingerprint_;
  bool connected_;
  bool needs_pass_phrase_sent_;
  bool needs_pin_sent_;
  bool initialized_;
};

class NUNCHUK_EXPORT SingleSigner {
 public:
  SingleSigner(const std::string& name, const std::string& xpub,
               const std::string& public_key,
               const std::string& derivation_path,
               const std::string& master_fingerprint, time_t last_health_check,
               const std::string& master_signer_id = {}, bool used = false);

  std::string get_name() const;
  std::string get_xpub() const;
  std::string get_public_key() const;
  std::string get_derivation_path() const;
  std::string get_master_fingerprint() const;
  std::string get_master_signer_id() const;
  bool is_used() const;
  bool has_master_signer() const;
  time_t get_last_health_check() const;
  void set_name(const std::string& value);
  void set_used(bool value);

 private:
  std::string name_;
  std::string xpub_;
  std::string public_key_;
  std::string derivation_path_;
  std::string master_fingerprint_;
  std::string master_signer_id_;
  time_t last_health_check_;
  bool used_;
};

class NUNCHUK_EXPORT MasterSigner {
 public:
  MasterSigner(const std::string& id, const Device& device,
               time_t last_health_check);

  std::string get_id() const;
  std::string get_name() const;
  Device get_device() const;
  time_t get_last_health_check() const;
  void set_name(const std::string& value);

 private:
  std::string id_;
  std::string name_;
  Device device_;
  time_t last_health_check_;
};

class NUNCHUK_EXPORT Wallet {
 public:
  Wallet(const std::string& id, int m, int n,
         const std::vector<SingleSigner>& signers, AddressType address_type,
         bool is_escrow, time_t create_date);

  std::string get_id() const;
  std::string get_name() const;
  int get_m() const;
  int get_n() const;
  std::vector<SingleSigner> get_signers() const;
  AddressType get_address_type() const;
  bool is_escrow() const;
  Amount get_balance() const;
  time_t get_create_date() const;
  std::string get_description() const;
  std::string get_descriptor(bool internal) const;
  void set_name(const std::string& value);
  void set_balance(const Amount& value);
  void set_description(const std::string& value);

 private:
  std::string id_;
  std::string name_;
  int m_;
  int n_;
  std::vector<SingleSigner> signers_;
  AddressType address_type_;
  bool escrow_;
  Amount balance_;
  time_t create_date_;
  std::string description_;
};

// Class that represents an Unspent Transaction Output (UTXO)
class NUNCHUK_EXPORT UnspentOutput {
 public:
  UnspentOutput();

  std::string get_txid() const;
  int get_vout() const;
  std::string get_address() const;
  Amount get_amount() const;
  int get_height() const;
  std::string get_memo() const;

  void set_txid(const std::string& value);
  void set_vout(int value);
  void set_address(const std::string& value);
  void set_amount(const Amount& value);
  void set_height(int value);
  void set_memo(const std::string& value);

 private:
  std::string txid_;
  int vout_;
  std::string address_;
  Amount amount_;
  int height_;
  std::string memo_;
};

// Class that represents a Transaction
class Transaction {
 public:
  Transaction();

  std::string get_txid() const;
  int get_height() const;
  std::vector<TxInput> const& get_inputs() const;
  std::vector<TxOutput> const& get_outputs() const;
  std::vector<TxOutput> const& get_user_outputs() const;
  std::vector<TxOutput> const& get_receive_outputs() const;
  int get_change_index() const;
  int get_m() const;
  std::map<std::string, bool> const& get_signers() const;
  std::string get_memo() const;
  TransactionStatus get_status() const;
  std::string get_replaced_by_txid() const;
  Amount get_fee() const;
  Amount get_fee_rate() const;
  time_t get_blocktime() const;
  bool subtract_fee_from_amount() const;
  bool is_receive() const;
  Amount get_sub_amount() const;

  void set_txid(const std::string& value);
  void set_height(int value);
  void add_input(const TxInput& value);
  void add_output(const TxOutput& value);
  void add_user_output(const TxOutput& value);
  void add_receive_output(const TxOutput& value);
  void set_change_index(int value);
  void set_m(int value);
  void set_signer(const std::string& signer_id, bool has_signature);
  void set_memo(const std::string& value);
  void set_status(TransactionStatus value);
  void set_replaced_by_txid(const std::string& value);
  void set_fee(const Amount& value);
  void set_fee_rate(const Amount& value);
  void set_blocktime(time_t value);
  void set_subtract_fee_from_amount(bool value);
  void set_receive(bool value);
  void set_sub_amount(const Amount& value);

 private:
  std::string txid_;
  int height_;
  std::vector<TxInput> inputs_;
  std::vector<TxOutput> outputs_;
  std::vector<TxOutput> user_outputs_;
  std::vector<TxOutput> receive_output_;
  int change_index_;
  int m_;
  std::map<std::string, bool> signers_;
  std::string memo_;
  TransactionStatus status_;
  std::string replaced_by_txid_;
  Amount fee_;
  Amount fee_rate_;
  time_t blocktime_;
  bool subtract_fee_from_amount_;
  bool is_receive_;
  Amount sub_amount_;
};

class NUNCHUK_EXPORT AppSettings {
 public:
  AppSettings();

  Chain get_chain() const;
  BackendType get_backend_type() const;
  std::vector<std::string> get_mainnet_servers() const;
  std::vector<std::string> get_testnet_servers() const;
  std::string get_hwi_path() const;
  std::string get_storage_path() const;
  bool use_proxy() const;
  std::string get_proxy_host() const;
  int get_proxy_port() const;
  std::string get_proxy_username() const;
  std::string get_proxy_password() const;
  std::string get_certificate_file() const;
  std::string get_corerpc_host() const;
  int get_corerpc_port() const;
  std::string get_corerpc_username() const;
  std::string get_corerpc_password() const;

  void set_chain(Chain value);
  void set_backend_type(BackendType value);
  void set_mainnet_servers(const std::vector<std::string>& value);
  void set_testnet_servers(const std::vector<std::string>& value);
  void set_hwi_path(const std::string& value);
  void set_storage_path(const std::string& value);
  void enable_proxy(bool value);
  void set_proxy_host(const std::string& value);
  void set_proxy_port(int value);
  void set_proxy_username(const std::string& value);
  void set_proxy_password(const std::string& value);
  void set_certificate_file(const std::string& value);
  void set_corerpc_host(const std::string& value);
  void set_corerpc_port(int value);
  void set_corerpc_username(const std::string& value);
  void set_corerpc_password(const std::string& value);

 private:
  Chain chain_;
  BackendType backend_type_;
  std::vector<std::string> mainnet_servers_;
  std::vector<std::string> testnet_servers_;
  std::string hwi_path_;
  std::string storage_path_;
  bool enable_proxy_;
  std::string proxy_host_;
  int proxy_port_;
  std::string proxy_username_;
  std::string proxy_password_;
  std::string certificate_file_;
  std::string corerpc_host_;
  int corerpc_port_;
  std::string corerpc_username_;
  std::string corerpc_password_;
};

class NUNCHUK_EXPORT Nunchuk {
 public:
  Nunchuk(const Nunchuk&) = delete;
  Nunchuk& operator=(const Nunchuk&) = delete;

  virtual ~Nunchuk();

  virtual void SetPassphrase(const std::string& passphrase) = 0;
  virtual Wallet CreateWallet(const std::string& name, int m, int n,
                              const std::vector<SingleSigner>& signers,
                              AddressType address_type, bool is_escrow,
                              const std::string& description = {}) = 0;
  virtual std::string DraftWallet(const std::string& name, int m, int n,
                                  const std::vector<SingleSigner>& signers,
                                  AddressType address_type, bool is_escrow,
                                  const std::string& description = {}) = 0;
  virtual std::vector<Wallet> GetWallets() = 0;
  virtual Wallet GetWallet(const std::string& wallet_id) = 0;
  virtual bool DeleteWallet(const std::string& wallet_id) = 0;
  virtual bool UpdateWallet(const Wallet& wallet) = 0;
  virtual bool ExportWallet(const std::string& wallet_id,
                            const std::string& file_path,
                            ExportFormat format) = 0;
  virtual Wallet ImportWalletDb(const std::string& file_path) = 0;
  virtual Wallet ImportWalletDescriptor(
      const std::string& file_path, const std::string& name,
      const std::string& description = {}) = 0;
  virtual Wallet ImportWalletConfigFile(
      const std::string& file_path, const std::string& description = {}) = 0;

  virtual SingleSigner GetSignerFromMasterSigner(
      const std::string& mastersigner_id, const WalletType& wallet_type,
      const AddressType& address_type, int index) = 0;
  virtual SingleSigner CreateSigner(const std::string& name,
                                    const std::string& xpub,
                                    const std::string& public_key,
                                    const std::string& derivation_path,
                                    const std::string& master_fingerprint) = 0;
  virtual int GetCurrentIndexFromMasterSigner(
      const std::string& mastersigner_id, const WalletType& wallet_type,
      const AddressType& address_type) = 0;
  virtual SingleSigner GetUnusedSignerFromMasterSigner(
      const std::string& mastersigner_id, const WalletType& wallet_type,
      const AddressType& address_type) = 0;
  virtual std::vector<SingleSigner> GetSignersFromMasterSigner(
      const std::string& mastersigner_id) = 0;
  virtual int GetNumberOfSignersFromMasterSigner(
      const std::string& mastersigner_id) = 0;
  virtual std::vector<MasterSigner> GetMasterSigners() = 0;
  virtual MasterSigner GetMasterSigner(const std::string& mastersigner_id) = 0;
  virtual bool DeleteMasterSigner(const std::string& mastersigner_id) = 0;
  virtual bool UpdateMasterSigner(const MasterSigner& mastersigner) = 0;
  virtual std::vector<SingleSigner> GetRemoteSigners() = 0;
  virtual bool DeleteRemoteSigner(const std::string& master_fingerprint,
                                  const std::string& derivation_path) = 0;
  virtual bool UpdateRemoteSigner(const SingleSigner& remotesigner) = 0;
  virtual std::string GetHealthCheckPath() = 0;
  virtual HealthStatus HealthCheckSingleSigner(
      const SingleSigner& signer, const std::string& message,
      const std::string& signature) = 0;

  virtual std::vector<Transaction> GetTransactionHistory(
      const std::string& wallet_id, int count, int skip) = 0;
  virtual bool ExportTransactionHistory(
      const std::string& wallet_id, const std::string& file_path,
      ExportFormat format = ExportFormat::CSV) = 0;
  virtual AppSettings GetAppSettings() = 0;
  virtual AppSettings UpdateAppSettings(const AppSettings& appSettings) = 0;

  virtual std::vector<std::string> GetAddresses(const std::string& wallet_id,
                                                bool used = false,
                                                bool internal = false) = 0;
  virtual std::string NewAddress(const std::string& wallet_id,
                                 bool internal = false) = 0;
  virtual Amount GetAddressBalance(const std::string& wallet_id,
                                   const std::string& address) = 0;
  virtual std::vector<UnspentOutput> GetUnspentOutputs(
      const std::string& wallet_id) = 0;
  virtual bool ExportUnspentOutputs(
      const std::string& wallet_id, const std::string& file_path,
      ExportFormat format = ExportFormat::CSV) = 0;
  virtual Transaction CreateTransaction(
      const std::string& wallet_id, const std::map<std::string, Amount> outputs,
      const std::string& memo = {},
      const std::vector<UnspentOutput> inputs = {}, Amount fee_rate = -1,
      bool subtract_fee_from_amount = false) = 0;
  virtual bool ExportTransaction(const std::string& wallet_id,
                                 const std::string& tx_id,
                                 const std::string& file_path) = 0;
  virtual Transaction ImportTransaction(const std::string& wallet_id,
                                        const std::string& file_path) = 0;
  virtual Transaction BroadcastTransaction(const std::string& wallet_id,
                                           const std::string& tx_id) = 0;
  virtual Transaction GetTransaction(const std::string& wallet_id,
                                     const std::string& tx_id) = 0;
  virtual bool DeleteTransaction(const std::string& wallet_id,
                                 const std::string& tx_id) = 0;

  virtual Transaction DraftTransaction(
      const std::string& wallet_id, const std::map<std::string, Amount> outputs,
      const std::vector<UnspentOutput> inputs = {}, Amount fee_rate = -1,
      bool subtract_fee_from_amount = false) = 0;
  virtual Transaction ReplaceTransaction(const std::string& wallet_id,
                                         const std::string& tx_id,
                                         Amount new_fee_rate) = 0;
  virtual bool UpdateTransactionMemo(const std::string& wallet_id,
                                     const std::string& tx_id,
                                     const std::string& new_memo) = 0;
  virtual bool ExportHealthCheckMessage(const std::string& message,
                                        const std::string& file_path) = 0;
  virtual std::string ImportHealthCheckSignature(
      const std::string& file_path) = 0;
  virtual Amount EstimateFee(int conf_target = 6) = 0;
  virtual int GetChainTip() = 0;
  virtual Amount GetTotalAmount(const std::string& wallet_id,
                                const std::vector<TxInput>& inputs) = 0;
  virtual std::string GetSelectedWallet() = 0;
  virtual bool SetSelectedWallet(const std::string& wallet_id) = 0;

  virtual SingleSigner CreateCoboSigner(const std::string& name,
                                        const std::string& json_info) = 0;
  virtual std::vector<std::string> ExportCoboWallet(
      const std::string& wallet_id) = 0;
  virtual std::vector<std::string> ExportCoboTransaction(
      const std::string& wallet_id, const std::string& tx_id) = 0;
  virtual Transaction ImportCoboTransaction(
      const std::string& wallet_id,
      const std::vector<std::string>& qr_data) = 0;
  virtual Wallet ImportCoboWallet(const std::vector<std::string>& qr_data,
                                  const std::string& description = {}) = 0;

  // Add listener methods
  virtual void AddBalanceListener(
      std::function<void(std::string /* wallet_id */, Amount /* new_balance */)>
          listener) = 0;
  virtual void AddBlockListener(
      std::function<void(int /* height */, std::string /* hex_header */)>
          listener) = 0;
  virtual void AddTransactionListener(
      std::function<void(std::string /* tx_id */, TransactionStatus)>
          listener) = 0;
  virtual void AddDeviceListener(
      std::function<void(std::string /* fingerprint */, bool /* connected */)>
          listener) = 0;
  virtual void AddBlockchainConnectionListener(
      std::function<void(ConnectionStatus)> listener) = 0;

  // The following methods use HWI to interact with the devices. They might take
  // a long time or require user inputs on device. Depending on the platform,
  // client should handle them accordingly (perhaps in a background thread if
  // necessary).
  virtual std::vector<Device> GetDevices() = 0;
  virtual MasterSigner CreateMasterSigner(
      const std::string& name, const Device& device,
      std::function<bool /* stop */ (int /* percent */)> progress) = 0;
  virtual HealthStatus HealthCheckMasterSigner(const std::string& fingerprint,
                                               std::string& message,
                                               std::string& signature,
                                               std::string& path) = 0;
  virtual Transaction SignTransaction(const std::string& wallet_id,
                                      const std::string& tx_id,
                                      const Device& device) = 0;
  virtual void CacheMasterSignerXPub(
      const std::string& mastersigner_id,
      std::function<bool /* stop */ (int /* percent */)> progress) = 0;
  virtual void DisplayAddressOnDevice(
      const std::string& wallet_id, const std::string& address,
      const std::string& device_fingerprint = {}) = 0;
  virtual void PromtPinOnDevice(const Device& device) = 0;
  virtual void SendPinToDevice(const Device& device,
                               const std::string& pin) = 0;

 protected:
  Nunchuk() = default;
};

class NUNCHUK_EXPORT Utils {
 public:
  static void SetChain(Chain chain);
  static std::string GenerateRandomMessage(int message_length = 20);
  static bool IsValidXPub(const std::string& value);
  static bool IsValidPublicKey(const std::string& value);
  static bool IsValidDerivationPath(const std::string& value);
  static bool IsValidFingerPrint(const std::string& value);
  static Amount AmountFromValue(const std::string& value,
                                const bool allow_negative = false);
  static std::string ValueFromAmount(const Amount& amount);
  static bool MoneyRange(const Amount& nValue);
  static std::string AddressToScriptPubKey(const std::string& address);
  static std::string SanitizeBIP32Input(
      const std::string& slip132_input,
      const std::string& target_format = "xpub");

 private:
  Utils() {}
};

std::unique_ptr<Nunchuk> MakeNunchuk(const AppSettings& appsettings,
                                     const std::string& passphrase = "");

}  // namespace nunchuk

#endif  // NUNCHUK_INCLUDE_H