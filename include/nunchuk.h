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

#ifndef NUNCHUK_INCLUDE_H
#define NUNCHUK_INCLUDE_H

#include <optional>
#include <set>
#include "utils/errorutils.hpp"
#define NUNCHUK_EXPORT

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <tap_protocol/transport.h>
#include <tap_protocol/tap_protocol.h>
#include <tap_protocol/cktapcard.h>

namespace nunchuk {

const int CONF_TARGET_PRIORITY = 2;
const int CONF_TARGET_STANDARD = 6;
const int CONF_TARGET_ECONOMICAL = 144;

const int LOW_DENSITY = 50;
const int MEDIUM_DENSITY = 100;
const int HIGH_DENSITY = 200;
const int ULTRA_HIGH_DENSITY = 1000;

const int LOW_DENSITY_BBQR = 3;
const int MEDIUM_DENSITY_BBQR = 10;
const int HIGH_DENSITY_BBQR = 27;
const int ULTRA_HIGH_DENSITY_BBQR = 40;

typedef int64_t Amount;
typedef std::pair<std::string, int> TxInput;        // txid-vout pair
typedef std::pair<std::string, Amount> TxOutput;    // address-amount pair
typedef std::map<std::string, bool> RequestTokens;  // token-sent map

enum class AddressType {
  ANY,
  LEGACY,
  NESTED_SEGWIT,
  NATIVE_SEGWIT,
  TAPROOT,
};

enum class Chain {
  MAIN,
  TESTNET,
  SIGNET,
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

enum class WalletTemplate {
  DEFAULT,
  DISABLE_KEY_PATH,  // Taproot wallet only
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
  PENDING_NONCE,  // Musig wallet only
  DELETED,        // Group wallet only
};

enum class CoinStatus {
  INCOMING_PENDING_CONFIRMATION,
  CONFIRMED,
  OUTGOING_PENDING_SIGNATURES,
  OUTGOING_PENDING_BROADCAST,
  OUTGOING_PENDING_CONFIRMATION,
  SPENT,
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
  BSMS,
};

enum class Unit {
  BTC,
  SATOSHI,
};

enum class DescriptorPath {
  ANY,
  INTERNAL_ALL,
  INTERNAL_PUBKEY,
  INTERNAL_XPUB,
  EXTERNAL_ALL,
  EXTERNAL_PUBKEY,
  EXTERNAL_XPUB,
  TEMPLATE,
};

enum class SignerType {
  UNKNOWN = -1,
  HARDWARE,
  AIRGAP,
  SOFTWARE,
  FOREIGN_SOFTWARE,
  NFC,
  COLDCARD_NFC,
  SERVER,
  PORTAL_NFC,
};

enum class OrderBy {
  NAME_ASC,
  NAME_DESC,
  NEWEST_FIRST,
  OLDEST_FIRST,
  MOST_RECENTLY_USED,
  LEAST_RECENTLY_USED,
};

enum class SignerTag {
  INHERITANCE,
  KEYSTONE,
  JADE,
  PASSPORT,
  SEEDSIGNER,
  COLDCARD,
  TREZOR,
  LEDGER,
  BITBOX,
  KEEPKEY,
};

class NUNCHUK_EXPORT BaseException : public std::exception {
 public:
  explicit BaseException(int code, const char* message)
      : code_(code), message_(message) {}
  explicit BaseException(int code, const std::string& message)
      : code_(code), message_(message) {}
  explicit BaseException(int code, std::string&& message)
      : code_(code), message_(std::move(message)) {}
  int code() const noexcept { return code_; }
  const char* what() const noexcept override { return message_.c_str(); }

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
  static const int INVALID_SIGNER_PASSPHRASE = -1021;
  static const int INVALID_SIGNER_TYPE = -1022;
  static const int VERSION_NOT_SUPPORTED = -1023;
  static const int INVALID_BIP32_PATH = -1024;
  static const int DECRYPT_FAIL = -1025;
  static const int NETWORK_REJECTED = -1026;
  static const int INVALID_SIGNATURE = -1027;
  static const int INVALID_RBF = -1028;
  static const int INSUFFICIENT_FEE = -1029;
  static const int INVALID_STATE = -1030;
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
  static const int TAG_EXISTS = -2012;
  static const int COLLECTION_EXISTS = -2013;
  static const int NONCE_NOT_FOUND = -2014;
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
  static const int VERSION_NOT_SUPPORTED = -4097;
  using BaseException::BaseException;
};

class TapProtocolException : public BaseException {
 public:
  using BaseException::BaseException;
  static const int TAP_PROTOCOL_ERROR = -6000;
  static const int INVALID_DEVICE = TAP_PROTOCOL_ERROR - 100;
  static const int INVALID_DEVICE_TYPE = TAP_PROTOCOL_ERROR - 101;
  static const int UNLUCKY_NUMBER = TAP_PROTOCOL_ERROR - 205;
  static const int BAD_ARGUMENT = TAP_PROTOCOL_ERROR - 400;
  static const int BAD_AUTH = TAP_PROTOCOL_ERROR - 401;
  static const int NEED_AUTH = TAP_PROTOCOL_ERROR - 403;
  static const int UNKNOW_COMMAND = TAP_PROTOCOL_ERROR - 404;
  static const int INVALID_COMMAND = TAP_PROTOCOL_ERROR - 405;
  static const int INVALID_STATE = TAP_PROTOCOL_ERROR - 406;
  static const int WEAK_NONCE = TAP_PROTOCOL_ERROR - 417;
  static const int BAD_CBOR = TAP_PROTOCOL_ERROR - 422;
  static const int BACKUP_FIRST = TAP_PROTOCOL_ERROR - 425;
  static const int RATE_LIMIT = TAP_PROTOCOL_ERROR - 429;
  static const int TAG_LOST = TAP_PROTOCOL_ERROR - 499;

  explicit TapProtocolException(const tap_protocol::TapProtoException& te)
      : BaseException(TAP_PROTOCOL_ERROR - te.code(),
                      NormalizeErrorMessage(te.what())) {}
};

class NUNCHUK_EXPORT GroupException : public BaseException {
 public:
  static const int NOT_ENABLED = -7000;
  static const int SERVER_REQUEST_ERROR = -7001;
  static const int WALLET_NOT_FOUND = -7002;
  static const int SIGNER_NOT_FOUND = -7003;
  static const int TOO_MANY_SIGNER = -7004;
  static const int SIGNER_EXISTS = -7005;
  static const int INVALID_PARAMETER = -7006;
  static const int INVALID_SIGNATURE = -7007;
  static const int GROUP_NOT_FOUND = -7008;
  static const int VERSION_MISMATCH = -7009;
  static const int SANDBOX_FINALIZED = -7010;
  static const int GROUP_NOT_JOINED = -7011;
  static const int GROUP_JOINED = -7012;
  using BaseException::BaseException;
};

class NUNCHUK_EXPORT Device {
 public:
  Device();
  Device(const std::string& fingerprint);
  Device(const std::string& type, const std::string& model,
         const std::string& master_fingerprint);
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
  bool is_tapsigner() const;
  void set_needs_pass_phrase_sent(const bool value);

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
  SingleSigner();
  SingleSigner(const std::string& name, const std::string& xpub,
               const std::string& public_key,
               const std::string& derivation_path,
               const std::string& master_fingerprint, time_t last_health_check,
               const std::string& master_signer_id = {}, bool used = false,
               SignerType signer_type = SignerType::AIRGAP,
               std::vector<SignerTag> tags = {}, bool visible = true);

  std::string get_name() const;
  std::string get_xpub() const;
  std::string get_public_key() const;
  std::string get_derivation_path() const;
  std::string get_master_fingerprint() const;
  std::string get_master_signer_id() const;
  SignerType get_type() const;
  const std::vector<SignerTag>& get_tags() const;
  bool is_visible() const;
  bool is_used() const;
  bool has_master_signer() const;
  time_t get_last_health_check() const;
  std::string get_descriptor() const;
  bool is_taproot() const;
  void set_name(const std::string& value);
  void set_used(bool value);
  void set_type(SignerType value);
  void set_tags(std::vector<SignerTag> tags);
  void set_visible(bool value);

 private:
  std::string name_;
  std::string xpub_;
  std::string public_key_;
  std::string derivation_path_;
  std::string master_fingerprint_;
  std::string master_signer_id_;
  time_t last_health_check_;
  bool used_;
  bool visible_{true};
  SignerType type_;
  std::vector<SignerTag> tags_;
};

class NUNCHUK_EXPORT MasterSigner {
 public:
  MasterSigner();
  MasterSigner(const std::string& id, const Device& device,
               time_t last_health_check,
               SignerType signer_type = SignerType::HARDWARE);

  std::string get_id() const;
  std::string get_name() const;
  Device get_device() const;
  time_t get_last_health_check() const;
  const std::vector<SignerTag>& get_tags() const;
  bool is_software() const;
  bool is_nfc() const;
  bool is_visible() const;
  SignerType get_type() const;
  bool is_support_taproot() const;
  bool need_backup() const;

  void set_name(const std::string& value);
  void set_tags(std::vector<SignerTag> tags);
  void set_visible(bool value);
  void set_need_backup(bool value);

 private:
  std::string id_;
  std::string name_;
  Device device_;
  time_t last_health_check_;
  SignerType type_;
  std::vector<SignerTag> tags_;
  bool visible_{true};
  bool need_backup_{false};
};

class NUNCHUK_EXPORT PrimaryKey {
 public:
  PrimaryKey();
  PrimaryKey(const std::string& name, const std::string& master_fingerprint,
             const std::string& account, const std::string& address);

  std::string get_name() const;
  std::string get_master_fingerprint() const;
  std::string get_account() const;
  std::string get_address() const;
  void set_name(const std::string& value);

 private:
  std::string name_;
  std::string master_fingerprint_;
  std::string account_;
  std::string address_;
};

class NUNCHUK_EXPORT Wallet {
 public:
  Wallet(bool strict = true) noexcept;
  Wallet(const std::string& id, int m, int n,
         const std::vector<SingleSigner>& signers, AddressType address_type,
         bool is_escrow, time_t create_date, bool strict = true);
  Wallet(const std::string& id, const std::string& name, int m, int n,
         const std::vector<SingleSigner>& signers, AddressType address_type,
         bool is_escrow, time_t create_date, bool strict = true);
  Wallet(const std::string& id, const std::string& name, int m, int n,
         const std::vector<SingleSigner>& signers, AddressType address_type,
         WalletType wallet_type, time_t create_date, bool strict = true);

  std::string get_id() const;
  std::string get_name() const;
  int get_m() const;
  int get_n() const;
  const std::vector<SingleSigner>& get_signers() const;
  AddressType get_address_type() const;
  WalletType get_wallet_type() const;
  WalletTemplate get_wallet_template() const;
  bool is_escrow() const;
  Amount get_balance() const;
  Amount get_unconfirmed_balance() const;
  time_t get_create_date() const;
  std::string get_description() const;
  std::string get_descriptor(DescriptorPath key_path, int index = -1,
                             bool sorted = true) const;
  time_t get_last_used() const;
  int get_gap_limit() const;
  void check_valid() const;
  bool need_backup() const;

  void set_name(const std::string& value);
  void set_n(int n);
  void set_m(int m);
  void set_signers(std::vector<SingleSigner> signers);
  void set_address_type(AddressType value);
  void set_wallet_type(WalletType value);
  void set_wallet_template(WalletTemplate value);
  void set_balance(const Amount& value);
  void set_unconfirmed_balance(const Amount& value);
  void set_description(const std::string& value);
  void set_create_date(const time_t value);
  void set_last_used(const time_t value);
  void set_gap_limit(int value);
  void set_need_backup(bool value);

 private:
  void post_update();
  std::string id_;
  std::string name_;
  int m_{0};
  int n_{0};
  std::vector<SingleSigner> signers_;
  AddressType address_type_;
  WalletType wallet_type_;
  WalletTemplate wallet_template_{WalletTemplate::DEFAULT};
  Amount balance_{0};
  Amount unconfirmed_balance_{0};
  time_t create_date_{std::time(0)};
  std::string description_;
  bool strict_{true};
  time_t last_used_{0};
  int gap_limit_{20};
  bool need_backup_{false};
};

class NUNCHUK_EXPORT CoinTag {
 public:
  CoinTag(int id, const std::string& name, const std::string& color);

  int get_id() const;
  std::string get_name() const;
  std::string get_color() const;

 private:
  int id_;
  std::string name_;
  std::string color_;
};

class NUNCHUK_EXPORT CoinCollection {
 public:
  static const int COINS_WITHOUT_TAGS = -1;
  CoinCollection(int id, const std::string& name);

  int get_id() const;
  std::string get_name() const;
  bool is_add_new_coin() const;
  bool is_auto_lock() const;
  std::vector<int> const& get_add_coins_with_tag() const;

  void set_add_new_coin(bool value);
  void set_auto_lock(bool value);
  void set_add_coins_with_tag(std::vector<int> value);

 private:
  int id_;
  std::string name_;
  bool add_new_coin_;
  bool auto_lock_;
  std::vector<int> add_tags_;
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
  bool is_change() const;
  bool is_locked() const;
  std::vector<int> const& get_tags() const;
  std::vector<int> const& get_collections() const;
  time_t get_blocktime() const;
  time_t get_schedule_time() const;
  CoinStatus get_status() const;

  void set_txid(const std::string& value);
  void set_vout(int value);
  void set_address(const std::string& value);
  void set_amount(const Amount& value);
  void set_height(int value);
  void set_memo(const std::string& value);
  void set_change(bool value);
  void set_locked(bool value);
  void set_tags(std::vector<int> value);
  void set_collections(std::vector<int> value);
  void set_blocktime(time_t value);
  void set_schedule_time(time_t value);
  void set_status(CoinStatus value);

 private:
  std::string txid_;
  int vout_;
  std::string address_;
  Amount amount_;
  int height_;
  std::string memo_;
  bool change_;
  bool locked_;
  std::vector<int> tags_;
  std::vector<int> collections_;
  time_t blocktime_;
  time_t schedule_time_;
  CoinStatus status_;
};

class NUNCHUK_EXPORT GroupSandbox {
 public:
  GroupSandbox(const std::string& id);

  std::string get_id() const;
  std::string get_name() const;
  std::string get_url() const;
  int get_m() const;
  int get_n() const;
  AddressType get_address_type() const;
  WalletTemplate get_wallet_template() const;
  const std::vector<SingleSigner>& get_signers() const;
  bool is_finalized() const;
  const std::vector<std::string>& get_ephemeral_keys() const;
  int get_state_id() const;
  std::string get_wallet_id() const;
  std::string get_pubkey() const;
  const std::map<int, std::pair<time_t, std::string>>& get_occupied() const;
  std::string get_replace_wallet_id() const;

  void set_name(const std::string& value);
  void set_url(const std::string& value);
  void set_n(int n);
  void set_m(int m);
  void set_address_type(AddressType value);
  void set_wallet_template(WalletTemplate value);
  void set_signers(std::vector<SingleSigner> signers);
  void set_finalized(bool value);
  void set_ephemeral_keys(std::vector<std::string> keys);
  void set_state_id(int id);
  void set_wallet_id(const std::string& value);
  void set_pubkey(const std::string& value);
  void add_occupied(int index, time_t ts, const std::string& uid);
  void remove_occupied(int index);
  void set_replace_wallet_id(const std::string& value);

 private:
  std::string id_;
  std::string name_;
  std::string url_;
  int m_{0};
  int n_{0};
  AddressType address_type_;
  WalletTemplate wallet_template_{WalletTemplate::DEFAULT};
  std::vector<SingleSigner> signers_;
  bool finalized_{false};
  std::vector<std::string> keys_;
  int state_id_{0};
  std::string wallet_id_{};
  std::string pubkey_{};
  std::map<int, std::pair<time_t, std::string>> occupied_{};
  std::string replace_wallet_id_{};
};

class NUNCHUK_EXPORT GroupMessage {
 public:
  GroupMessage(const std::string& id, const std::string& wallet_id);

  std::string get_id() const;
  std::string get_wallet_id() const;
  std::string get_sender() const;
  std::string get_content() const;
  std::string get_signer() const;
  time_t get_ts() const;

  void set_wallet_id(const std::string& value);
  void set_sender(const std::string& value);
  void set_content(const std::string& value);
  void set_signer(const std::string& value);
  void set_ts(time_t value);

 private:
  std::string id_;
  std::string wallet_id_;
  std::string sender_;
  std::string content_;
  std::string signer_;
  time_t ts_;
};

class NUNCHUK_EXPORT GroupConfig {
 public:
  GroupConfig();

  int get_total() const;
  int get_remain() const;
  int get_max_keys(AddressType address_type) const;
  const std::vector<int>& get_retention_days_options() const;

  void set_total(int value);
  void set_remain(int value);
  void set_max_keys(AddressType address_type, int value);
  void set_retention_days_options(std::vector<int> values);

 private:
  int total_;
  int remain_;
  std::map<AddressType, int> address_key_limits_{};
  std::vector<int> retention_days_options_{};
};

class NUNCHUK_EXPORT GroupWalletConfig {
 public:
  GroupWalletConfig();

  int get_chat_retention_days() const;
  void set_chat_retention_days(int value);

 private:
  int chat_retention_days_{1};
};

typedef std::map<std::string, bool> KeyStatus;  // xfp-signed map
typedef std::pair<TransactionStatus, KeyStatus> KeysetStatus;

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
  std::vector<KeysetStatus> const& get_keyset_status() const;
  std::string get_replaced_by_txid() const;
  std::string get_replace_txid() const;
  Amount get_fee() const;
  Amount get_fee_rate() const;
  time_t get_blocktime() const;
  bool subtract_fee_from_amount() const;
  bool is_receive() const;
  Amount get_sub_amount() const;
  std::string get_psbt() const;
  std::string get_raw() const;
  std::string get_reject_msg() const;
  time_t get_schedule_time() const;
  int get_vsize() const;

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
  void set_keyset_status(const std::vector<KeysetStatus>& value);
  void set_replaced_by_txid(const std::string& value);
  void set_replace_txid(const std::string& value);
  void set_fee(const Amount& value);
  void set_fee_rate(const Amount& value);
  void set_blocktime(time_t value);
  void set_subtract_fee_from_amount(bool value);
  void set_receive(bool value);
  void set_sub_amount(const Amount& value);
  void set_psbt(const std::string& value);
  void set_raw(const std::string& value);
  void set_reject_msg(const std::string& value);
  void set_schedule_time(time_t value);
  void set_vsize(int value);

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
  std::vector<KeysetStatus> keyset_status_;
  std::string replaced_by_txid_;
  std::string replace_txid_;
  Amount fee_;
  Amount fee_rate_;
  time_t blocktime_;
  bool subtract_fee_from_amount_;
  bool is_receive_;
  Amount sub_amount_;
  std::string psbt_;
  std::string raw_;
  std::string reject_msg_;
  time_t schedule_time_;
  int vsize_;
};

class TapsignerStatus {
 public:
  TapsignerStatus();
  TapsignerStatus(
      const std::string& card_ident, int birth_height, int number_of_backup,
      const std::string& version,
      const std::optional<std::string>& current_derivation = std::nullopt,
      bool is_testnet = false, int auth_delay = 0,
      const std::string& master_signer_id = {},
      const std::vector<unsigned char>& backup_data = {});

  const std::string& get_card_ident() const;
  std::string get_current_derivation() const;
  const std::string& get_version() const;
  const std::string& get_master_signer_id() const;
  const std::vector<unsigned char>& get_backup_data() const;
  int get_birth_height() const;
  int get_number_of_backup() const;
  int get_auth_delay() const;
  bool is_testnet() const;
  bool is_master_signer() const;
  bool need_setup() const;

  void set_card_ident(const std::string& card_ident);
  void set_birth_height(int birth_height);
  void set_number_of_backup(int number_of_backup);
  void set_current_derivation(const std::string& current_derivation);
  void set_version(const std::string& version);
  void set_testnet(bool is_testnet);
  void set_auth_delay(int auth_delay);
  void set_backup_data(const std::vector<unsigned char>& backup_data);
  void set_master_signer_id(const std::string& master_signer_id);

 private:
  std::string card_ident_;
  int birth_height_{};
  int number_of_backup_{};
  std::optional<std::string> current_derivation_;
  std::string version_;
  bool is_testnet_{};
  int auth_delay_{};
  std::vector<unsigned char> backup_data_;
  std::string master_signer_id_;
};

class SatscardSlot {
 public:
  enum class Status {
    UNUSED,
    SEALED,
    UNSEALED,
  };

  SatscardSlot();
  SatscardSlot(int index, Status status, const std::string& address);
  SatscardSlot(int index, Status status, const std::string& address,
               std::vector<unsigned char> privkey,
               std::vector<unsigned char> pubkey,
               std::vector<unsigned char> chain_code,
               std::vector<unsigned char> master_privkey);

  int get_index() const;
  Status get_status() const;
  const std::string& get_address() const;
  Amount get_balance() const;
  bool is_confirmed() const;
  const std::vector<UnspentOutput>& get_utxos() const;
  const std::vector<unsigned char>& get_privkey() const;
  const std::vector<unsigned char>& get_pubkey() const;
  const std::vector<unsigned char>& get_chain_code() const;
  const std::vector<unsigned char>& get_master_privkey() const;

  void set_index(int index);
  void set_status(Status status);
  void set_address(const std::string& address);
  void set_balance(const Amount& value);
  void set_confirmed(bool confirmed);
  void set_utxos(std::vector<UnspentOutput> utxos);
  void set_privkey(std::vector<unsigned char> privkey);
  void set_pubkey(std::vector<unsigned char> pubkey);
  void set_chain_code(std::vector<unsigned char> chain_code);
  void set_master_privkey(std::vector<unsigned char> master_privkey);

 private:
  int index_{};
  Status status_;
  std::string address_;
  Amount balance_{};
  bool confirmed_{};
  std::vector<UnspentOutput> utxos_;
  std::vector<unsigned char> privkey_;
  std::vector<unsigned char> pubkey_;
  std::vector<unsigned char> chain_code_;
  std::vector<unsigned char> master_privkey_;
};

class SatscardStatus {
 public:
  SatscardStatus();
  SatscardStatus(const std::string& card_ident, int birth_height,
                 const std::string& version, bool is_testnet, int auth_delay,
                 int active_slot_index, int num_slot,
                 std::vector<SatscardSlot> slots);

  const std::string& get_card_ident() const;
  const std::string& get_version() const;
  int get_birth_height() const;
  int get_auth_delay() const;
  int get_active_slot_index() const;
  int get_number_of_slots() const;
  bool is_testnet() const;
  bool need_setup() const;
  bool is_used_up() const;
  const std::vector<SatscardSlot>& get_slots() const;
  const SatscardSlot& get_active_slot() const;

  void set_card_ident(const std::string& card_ident);
  void set_birth_height(int birth_height);
  void set_version(const std::string& version);
  void set_testnet(bool is_testnet);
  void set_auth_delay(int auth_delay);
  void set_active_slot_index(int index);
  void set_number_of_slots(int number_of_slots);
  void set_slots(std::vector<SatscardSlot> slots);

 private:
  std::string card_ident_;
  int birth_height_{};
  std::string version_;
  bool is_testnet_{};
  int auth_delay_{};
  int active_slot_index_{};
  int num_slot_{};
  std::vector<SatscardSlot> slots_;
};

class NUNCHUK_EXPORT AppSettings {
 public:
  AppSettings();

  Chain get_chain() const;
  BackendType get_backend_type() const;
  std::vector<std::string> get_mainnet_servers() const;
  std::vector<std::string> get_signet_servers() const;
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
  std::string get_group_server() const;

  void set_chain(Chain value);
  void set_backend_type(BackendType value);
  void set_mainnet_servers(const std::vector<std::string>& value);
  void set_signet_servers(const std::vector<std::string>& value);
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
  void set_group_server(const std::string& value);

 private:
  Chain chain_;
  BackendType backend_type_;
  std::vector<std::string> mainnet_servers_;
  std::vector<std::string> signet_servers_;
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
  std::string group_server_;
};

class NUNCHUK_EXPORT Nunchuk {
 public:
  Nunchuk(const Nunchuk&) = delete;
  Nunchuk& operator=(const Nunchuk&) = delete;

  virtual ~Nunchuk();

  virtual void SetPassphrase(const std::string& passphrase) = 0;
  virtual Wallet CreateWallet(
      const std::string& name, int m, int n,
      const std::vector<SingleSigner>& signers, AddressType address_type,
      bool is_escrow, const std::string& description = {},
      bool allow_used_signer = false, const std::string& decoy_pin = {},
      WalletTemplate wallet_template = WalletTemplate::DEFAULT) = 0;
  virtual Wallet CreateWallet(
      const std::string& name, int m, int n,
      const std::vector<SingleSigner>& signers, AddressType address_type,
      WalletType wallet_type, const std::string& description = {},
      bool allow_used_signer = false, const std::string& decoy_pin = {},
      WalletTemplate wallet_template = WalletTemplate::DEFAULT) = 0;
  virtual Wallet CreateWallet(const Wallet& wallet,
                              bool allow_used_signer = false,
                              const std::string& decoy_pin = {}) = 0;
  virtual Wallet CloneWallet(const std::string& wallet_id,
                             const std::string& decoy_pin) = 0;
  virtual Wallet CreateHotWallet(const std::string& mnemonic = {},
                                 const std::string& passphrase = {},
                                 bool need_backup = true,
                                 bool replace = true) = 0;
  virtual std::string GetHotWalletMnemonic(
      const std::string& wallet_id, const std::string& passphrase = {}) = 0;
  virtual std::string GetHotKeyMnemonic(const std::string& signer_id,
                                        const std::string& passphrase = {}) = 0;
  virtual std::string DraftWallet(
      const std::string& name, int m, int n,
      const std::vector<SingleSigner>& signers, AddressType address_type,
      bool is_escrow, const std::string& description = {},
      WalletTemplate wallet_template = WalletTemplate::DEFAULT) = 0;
  virtual std::string DraftWallet(
      const std::string& name, int m, int n,
      const std::vector<SingleSigner>& signers, AddressType address_type,
      WalletType wallet_type, const std::string& description = {},
      WalletTemplate wallet_template = WalletTemplate::DEFAULT) = 0;
  virtual std::vector<Wallet> GetWallets(const std::vector<OrderBy>& orders = {
                                             OrderBy::OLDEST_FIRST}) = 0;
  virtual Wallet GetWallet(const std::string& wallet_id) = 0;
  virtual bool HasWallet(const std::string& wallet_id) = 0;
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
  virtual void ForceRefreshWallet(const std::string& wallet_id) = 0;

  virtual SingleSigner GetSigner(const std::string& xfp,
                                 const WalletType& wallet_type,
                                 const AddressType& address_type,
                                 int index) = 0;
  virtual int GetLastUsedSignerIndex(const std::string& xfp,
                                     const WalletType& wallet_type,
                                     const AddressType& address_type) = 0;
  virtual SingleSigner GetSignerFromMasterSigner(
      const std::string& mastersigner_id, const WalletType& wallet_type,
      const AddressType& address_type, int index) = 0;
  virtual SingleSigner CreateSigner(const std::string& name,
                                    const std::string& xpub,
                                    const std::string& public_key,
                                    const std::string& derivation_path,
                                    const std::string& master_fingerprint,
                                    SignerType signer_type = SignerType::AIRGAP,
                                    std::vector<SignerTag> tags = {},
                                    bool replace = false) = 0;
  virtual bool HasSigner(const SingleSigner& signer) = 0;
  virtual SingleSigner GetSigner(const SingleSigner& signer) = 0;
  virtual int GetCurrentIndexFromMasterSigner(
      const std::string& mastersigner_id, const WalletType& wallet_type,
      const AddressType& address_type) = 0;
  virtual SingleSigner GetUnusedSignerFromMasterSigner(
      const std::string& mastersigner_id, const WalletType& wallet_type,
      const AddressType& address_type) = 0;
  virtual SingleSigner GetDefaultSignerFromMasterSigner(
      const std::string& mastersigner_id, const WalletType& wallet_type,
      const AddressType& address_type) = 0;
  virtual SingleSigner GetSignerFromMasterSigner(
      const std::string& mastersigner_id, const std::string& path) = 0;
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
  virtual bool MarkAddressAsUsed(const std::string& wallet_id,
                                 const std::string& address) = 0;
  virtual std::vector<UnspentOutput> GetUnspentOutputs(
      const std::string& wallet_id) = 0;
  virtual std::vector<UnspentOutput> GetUnspentOutputsFromTxInputs(
      const std::string& wallet_id, const std::vector<TxInput>& inputs) = 0;
  virtual std::vector<UnspentOutput> GetCoins(const std::string& wallet_id) = 0;
  virtual std::vector<UnspentOutput> GetCoinsFromTxInputs(
      const std::string& wallet_id, const std::vector<TxInput>& inputs) = 0;
  virtual bool ExportUnspentOutputs(
      const std::string& wallet_id, const std::string& file_path,
      ExportFormat format = ExportFormat::CSV) = 0;
  virtual Transaction CreateTransaction(
      const std::string& wallet_id,
      const std::map<std::string, Amount>& outputs,
      const std::string& memo = {},
      const std::vector<UnspentOutput>& inputs = {}, Amount fee_rate = -1,
      bool subtract_fee_from_amount = false,
      const std::string& replace_txid = {}) = 0;
  virtual bool ExportTransaction(const std::string& wallet_id,
                                 const std::string& tx_id,
                                 const std::string& file_path) = 0;
  virtual Transaction ImportTransaction(const std::string& wallet_id,
                                        const std::string& file_path) = 0;
  virtual Transaction ImportPsbt(const std::string& wallet_id,
                                 const std::string& psbt,
                                 bool throw_if_unchanged = true,
                                 bool send_group_event = true) = 0;
  virtual Transaction BroadcastTransaction(const std::string& wallet_id,
                                           const std::string& tx_id) = 0;
  virtual Transaction GetTransaction(const std::string& wallet_id,
                                     const std::string& tx_id) = 0;
  virtual std::string GetRawTransaction(const std::string& wallet_id,
                                        const std::string& tx_id) = 0;
  virtual bool DeleteTransaction(const std::string& wallet_id,
                                 const std::string& tx_id,
                                 bool send_group_event = true) = 0;

  virtual Transaction DraftTransaction(
      const std::string& wallet_id,
      const std::map<std::string, Amount>& outputs,
      const std::vector<UnspentOutput>& inputs = {}, Amount fee_rate = -1,
      bool subtract_fee_from_amount = false,
      const std::string& replace_txid = {}) = 0;
  virtual Transaction ReplaceTransaction(const std::string& wallet_id,
                                         const std::string& tx_id,
                                         Amount new_fee_rate) = 0;
  virtual bool ReplaceTransactionId(const std::string& wallet_id,
                                    const std::string& txid,
                                    const std::string& replace_txid) = 0;
  virtual Transaction UpdateTransaction(const std::string& wallet_id,
                                        const std::string& tx_id,
                                        const std::string& new_txid,
                                        const std::string& raw_tx,
                                        const std::string& reject_msg = {}) = 0;
  virtual bool UpdateTransactionMemo(const std::string& wallet_id,
                                     const std::string& tx_id,
                                     const std::string& new_memo) = 0;
  virtual bool UpdateTransactionSchedule(const std::string& wallet_id,
                                         const std::string& tx_id,
                                         time_t broadcast_ts) = 0;
  virtual bool ExportHealthCheckMessage(const std::string& message,
                                        const std::string& file_path) = 0;
  virtual std::string ImportHealthCheckSignature(
      const std::string& file_path) = 0;
  virtual Amount EstimateFee(int conf_target = 6, bool use_mempool = true) = 0;
  virtual int GetChainTip() = 0;
  virtual Amount GetTotalAmount(const std::string& wallet_id,
                                const std::vector<TxInput>& inputs) = 0;
  virtual std::string GetSelectedWallet() = 0;
  virtual bool SetSelectedWallet(const std::string& wallet_id) = 0;
  virtual bool DeletePrimaryKey() = 0;

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

  virtual SingleSigner ParseKeystoneSigner(const std::string& qr_data) = 0;
  virtual std::vector<std::string> ExportKeystoneWallet(
      const std::string& wallet_id, int fragment_len = 200) = 0;
  virtual std::vector<std::string> ExportKeystoneTransaction(
      const std::string& wallet_id, const std::string& tx_id,
      int fragment_len = 200) = 0;
  virtual Transaction ImportKeystoneTransaction(
      const std::string& wallet_id,
      const std::vector<std::string>& qr_data) = 0;
  virtual Wallet ImportKeystoneWallet(const std::vector<std::string>& qr_data,
                                      const std::string& description = {}) = 0;

  virtual std::vector<SingleSigner> ParsePassportSigners(
      const std::vector<std::string>& qr_data) = 0;
  virtual std::vector<std::string> ExportPassportWallet(
      const std::string& wallet_id, int fragment_len = 200) = 0;
  virtual std::vector<std::string> ExportPassportTransaction(
      const std::string& wallet_id, const std::string& tx_id,
      int fragment_len = 200) = 0;
  virtual Transaction ImportPassportTransaction(
      const std::string& wallet_id,
      const std::vector<std::string>& qr_data) = 0;

  virtual std::vector<SingleSigner> ParseSeedSigners(
      const std::vector<std::string>& qr_data) = 0;
  virtual std::vector<SingleSigner> ParseQRSigners(
      const std::vector<std::string>& qr_data) = 0;

  virtual std::vector<std::string> ExportBCR2020010Wallet(
      const std::string& wallet_id, int fragment_len = 200) = 0;

  // NFC
  virtual std::unique_ptr<tap_protocol::CKTapCard> CreateCKTapCard(
      std::unique_ptr<tap_protocol::Transport> transport) = 0;
  virtual void WaitCKTapCard(tap_protocol::CKTapCard* card,
                             std::function<bool(int)> progress) = 0;

  // TAPSIGNER
  virtual MasterSigner ImportTapsignerMasterSigner(
      const std::string& file_path, const std::string& backup_key,
      const std::string& name, std::function<bool(int)> progress,
      bool is_primary = false) = 0;
  virtual MasterSigner ImportTapsignerMasterSigner(
      const std::vector<unsigned char>& data, const std::string& backup_key,
      const std::string& name, std::function<bool(int)> progress,
      bool is_primary = false) = 0;
  virtual void VerifyTapsignerBackup(
      const std::string& file_path, const std::string& backup_key,
      const std::string& master_signer_id = {}) = 0;
  virtual void VerifyTapsignerBackup(
      const std::vector<unsigned char>& data, const std::string& backup_key,
      const std::string& master_signer_id = {}) = 0;
  virtual std::unique_ptr<tap_protocol::Tapsigner> CreateTapsigner(
      std::unique_ptr<tap_protocol::Transport> transport) = 0;
  virtual TapsignerStatus GetTapsignerStatus(
      tap_protocol::Tapsigner* tapsigner) = 0;
  // setup only
  virtual void InitTapsigner(tap_protocol::Tapsigner* tapsigner,
                             const std::string& cvc,
                             const std::string& chain_code = {}) = 0;
  // setup - backup - change CVC
  virtual TapsignerStatus SetupTapsigner(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& new_cvc, const std::string& derivation_path = {},
      const std::string& chain_code = {}) = 0;
  virtual MasterSigner CreateTapsignerMasterSigner(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& name, std::function<bool(int)> progress,
      bool is_primary = false, bool replace = true) = 0;
  virtual Transaction SignTapsignerTransaction(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& wallet_id, const std::string& tx_id) = 0;
  virtual bool ChangeTapsignerCVC(tap_protocol::Tapsigner* tapsigner,
                                  const std::string& cvc,
                                  const std::string& new_cvc,
                                  const std::string& master_signer_id = {}) = 0;
  virtual TapsignerStatus BackupTapsigner(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& master_signer_id = {}) = 0;
  virtual HealthStatus HealthCheckTapsignerMasterSigner(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& master_signer_id, std::string& message,
      std::string& signature, std::string& path) = 0;
  virtual SingleSigner GetSignerFromTapsignerMasterSigner(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& mastersigner_id, const std::string& path) = 0;
  virtual SingleSigner GetSignerFromTapsignerMasterSigner(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& master_signer_id, const WalletType& wallet_type,
      const AddressType& address_type, int index) = 0;

  virtual std::string SignTapsignerMessage(tap_protocol::Tapsigner* tapsigner,
                                           const std::string& cvc,
                                           const SingleSigner& signer,
                                           const std::string& message) = 0;
  virtual TapsignerStatus WaitTapsigner(tap_protocol::Tapsigner* tapsigner,
                                        std::function<bool(int)> progress) = 0;
  virtual void CacheTapsignerMasterSignerXPub(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& master_signer_id,
      std::function<bool /* stop */ (int /* percent */)> progress) = 0;
  virtual void CacheDefaultTapsignerMasterSignerXPub(
      tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
      const std::string& master_signer_id,
      std::function<bool /* stop */ (int /* percent */)> progress) = 0;
  virtual TapsignerStatus GetTapsignerStatusFromMasterSigner(
      const std::string& master_signer_id) = 0;
  virtual void AddTapsigner(const std::string& card_ident,
                            const std::string& xfp, const std::string& name,
                            const std::string& version = {},
                            int birth_height = 0, bool is_testnet = false,
                            bool replace = false) = 0;

  // SATSCARD
  virtual std::unique_ptr<tap_protocol::Satscard> CreateSatscard(
      std::unique_ptr<tap_protocol::Transport> transport) = 0;
  virtual SatscardStatus GetSatscardStatus(
      tap_protocol::Satscard* satscard) = 0;
  virtual SatscardStatus SetupSatscard(tap_protocol::Satscard* satscard,
                                       const std::string& cvc,
                                       const std::string& chain_code = {}) = 0;
  virtual SatscardSlot UnsealSatscard(tap_protocol::Satscard* satscard,
                                      const std::string& cvc,
                                      const SatscardSlot& slot = {}) = 0;
  virtual SatscardSlot FetchSatscardSlotUTXOs(const SatscardSlot& slot) = 0;
  virtual SatscardSlot GetSatscardSlotKey(tap_protocol::Satscard* satscard,
                                          const std::string& cvc,
                                          const SatscardSlot& slot) = 0;
  virtual Transaction CreateSatscardSlotsTransaction(
      const std::vector<SatscardSlot>& slots, const std::string& address,
      Amount fee_rate = -1) = 0;
  virtual Transaction SweepSatscardSlot(const SatscardSlot& slot,
                                        const std::string& address,
                                        Amount fee_rate = -1) = 0;
  virtual Transaction SweepSatscardSlots(const std::vector<SatscardSlot>& slots,
                                         const std::string& address,
                                         Amount fee_rate = -1) = 0;
  virtual SatscardStatus WaitSatscard(tap_protocol::Satscard* satscard,
                                      std::function<bool(int)> progress) = 0;
  virtual Transaction FetchTransaction(const std::string& tx_id) = 0;

  // Coldcard mk4
  virtual std::vector<SingleSigner> ParseJSONSigners(
      const std::string& json_str,
      SignerType signer_type = SignerType::COLDCARD_NFC) = 0;
  virtual std::vector<Wallet> ParseJSONWallets(const std::string& json_str) = 0;
  virtual Transaction ImportRawTransaction(const std::string& wallet_id,
                                           const std::string& raw_tx,
                                           const std::string& tx_id = {}) = 0;
  virtual std::string GetWalletExportData(const std::string& wallet_id,
                                          ExportFormat format) = 0;
  virtual std::string GetWalletExportData(const Wallet& wallet,
                                          ExportFormat format) = 0;
  virtual void VerifyColdcardBackup(const std::vector<unsigned char>& data,
                                    const std::string& backup_key,
                                    const std::string& xfp = {}) = 0;
  virtual MasterSigner ImportColdcardBackup(
      const std::vector<unsigned char>& data, const std::string& backup_key,
      const std::string& name, std::function<bool(int)> progress,
      bool is_primary = false) = 0;
  virtual MasterSigner ImportBackupKey(const std::vector<unsigned char>& data,
                                       const std::string& backup_key,
                                       const std::string& name,
                                       std::function<bool(int)> progress,
                                       bool is_primary = false) = 0;

  virtual void RescanBlockchain(int start_height, int stop_height = -1) = 0;
  virtual void ScanWalletAddress(const std::string& wallet_id,
                                 bool force = false) = 0;
  virtual MasterSigner CreateSoftwareSigner(
      const std::string& name, const std::string& mnemonic,
      const std::string& passphrase,
      std::function<bool /* stop */ (int /* percent */)> progress,
      bool is_primary = false, bool replace = true) = 0;
  virtual MasterSigner CreateSoftwareSignerFromMasterXprv(
      const std::string& name, const std::string& master_xprv,
      std::function<bool /* stop */ (int /* percent */)> progress,
      bool is_primary = false, bool replace = true) = 0;
  virtual std::string SignLoginMessage(const std::string& mastersigner_id,
                                       const std::string& message) = 0;
  virtual void SendSignerPassphrase(const std::string& mastersigner_id,
                                    const std::string& passphrase) = 0;
  virtual void ClearSignerPassphrase(const std::string& mastersigner_id) = 0;
  virtual std::string ExportBackup() = 0;
  virtual bool SyncWithBackup(
      const std::string& data,
      std::function<bool /* stop */ (int /* percent */)> progress) = 0;

  // Coin control
  virtual bool UpdateCoinMemo(const std::string& wallet_id,
                              const std::string& tx_id, int vout,
                              const std::string& memo) = 0;
  virtual bool LockCoin(const std::string& wallet_id, const std::string& tx_id,
                        int vout) = 0;
  virtual bool UnlockCoin(const std::string& wallet_id,
                          const std::string& tx_id, int vout) = 0;

  virtual CoinTag CreateCoinTag(const std::string& wallet_id,
                                const std::string& name,
                                const std::string& color) = 0;
  virtual std::vector<CoinTag> GetCoinTags(const std::string& wallet_id) = 0;
  virtual bool UpdateCoinTag(const std::string& wallet_id,
                             const CoinTag& tag) = 0;
  virtual bool DeleteCoinTag(const std::string& wallet_id, int tag_id) = 0;
  virtual bool AddToCoinTag(const std::string& wallet_id, int tag_id,
                            const std::string& tx_id, int vout) = 0;
  virtual bool RemoveFromCoinTag(const std::string& wallet_id, int tag_id,
                                 const std::string& tx_id, int vout) = 0;
  virtual std::vector<UnspentOutput> GetCoinByTag(const std::string& wallet_id,
                                                  int tag_id) = 0;

  virtual CoinCollection CreateCoinCollection(const std::string& wallet_id,
                                              const std::string& name) = 0;
  virtual std::vector<CoinCollection> GetCoinCollections(
      const std::string& wallet_id) = 0;
  virtual bool UpdateCoinCollection(const std::string& wallet_id,
                                    const CoinCollection& collection,
                                    bool apply_to_existing_coins = false) = 0;
  virtual bool DeleteCoinCollection(const std::string& wallet_id,
                                    int collection_id) = 0;
  virtual bool AddToCoinCollection(const std::string& wallet_id,
                                   int collection_id, const std::string& tx_id,
                                   int vout) = 0;
  virtual bool RemoveFromCoinCollection(const std::string& wallet_id,
                                        int collection_id,
                                        const std::string& tx_id, int vout) = 0;
  virtual std::vector<UnspentOutput> GetCoinInCollection(
      const std::string& wallet_id, int collection_id) = 0;

  virtual std::string ExportCoinControlData(const std::string& wallet_id) = 0;
  virtual bool ImportCoinControlData(const std::string& wallet_id,
                                     const std::string& data, bool force) = 0;
  virtual std::string ExportBIP329(const std::string& wallet_id) = 0;
  virtual void ImportBIP329(const std::string& wallet_id,
                            const std::string& data) = 0;

  virtual bool IsMyAddress(const std::string& wallet_id,
                           const std::string& address) = 0;
  virtual std::string GetAddressPath(const std::string& wallet_id,
                                     const std::string& address) = 0;
  virtual int GetAddressIndex(const std::string& wallet_id,
                              const std::string& address) = 0;
  virtual std::vector<std::vector<UnspentOutput>> GetCoinAncestry(
      const std::string& wallet_id, const std::string& tx_id, int vout) = 0;

  virtual bool IsCPFP(const std::string& wallet_id, const Transaction& tx,
                      Amount& package_fee_rate) = 0;
  virtual Amount GetScriptPathFeeRate(const std::string& wallet_id,
                                      const Transaction& tx) = 0;

  virtual int EstimateRollOverTransactionCount(
      const std::string& wallet_id, const std::set<int>& tags,
      const std::set<int>& collections) = 0;
  virtual std::pair<Amount /* sub total */, Amount /* fee */>
  EstimateRollOverAmount(const std::string& old_wallet_id,
                         const std::string& new_wallet_id,
                         const std::set<int>& tags,
                         const std::set<int>& collections,
                         Amount fee_rate = -1) = 0;
  virtual std::map<
      std::pair<std::set<int> /* tags */, std::set<int> /* collections */>,
      Transaction>
  DraftRollOverTransactions(const std::string& old_wallet_id,
                            const std::string& new_wallet_id,
                            const std::set<int>& tags,
                            const std::set<int>& collections,
                            Amount fee_rate = -1) = 0;
  virtual std::vector<Transaction> CreateRollOverTransactions(
      const std::string& old_wallet_id, const std::string& new_wallet_id,
      const std::set<int>& tags, const std::set<int>& collections,
      Amount fee_rate = -1) = 0;

  // Dummy transaction
  virtual std::pair<std::string /* id */, Transaction> ImportDummyTx(
      const std::string& dummy_transaction) = 0;
  virtual RequestTokens SaveDummyTxRequestToken(const std::string& wallet_id,
                                                const std::string& id,
                                                const std::string& token) = 0;
  virtual bool DeleteDummyTx(const std::string& wallet_id,
                             const std::string& id) = 0;
  virtual RequestTokens GetDummyTxRequestToken(const std::string& wallet_id,
                                               const std::string& id) = 0;
  virtual std::map<std::string /* id */, Transaction> GetDummyTxs(
      const std::string& wallet_id) = 0;
  virtual Transaction GetDummyTx(const std::string& wallet_id,
                                 const std::string& id) = 0;

  // Add listener methods
  virtual void AddBalanceListener(
      std::function<void(std::string /* wallet_id */, Amount /* new_balance */)>
          listener) = 0;
  virtual void AddBalancesListener(
      std::function<void(std::string /* wallet_id */, Amount /* balance */,
                         Amount /* unconfirmed_balance */)>
          listener) = 0;
  virtual void AddBlockListener(
      std::function<void(int /* height */, std::string /* hex_header */)>
          listener) = 0;
  virtual void AddTransactionListener(
      std::function<void(std::string /* tx_id */, TransactionStatus,
                         std::string /* wallet_id */)>
          listener) = 0;
  virtual void AddDeviceListener(
      std::function<void(std::string /* fingerprint */, bool /* connected */)>
          listener) = 0;
  virtual void AddBlockchainConnectionListener(
      std::function<void(ConnectionStatus, int /* percent */)> listener) = 0;
  virtual void AddStorageUpdateListener(std::function<void()> listener) = 0;

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
  virtual std::string SignMessage(const SingleSigner& signer,
                                  const std::string& message) = 0;
  virtual std::string GetSignerAddress(
      const SingleSigner& signer,
      AddressType address_type = AddressType::LEGACY) = 0;
  virtual Transaction SignTransaction(const std::string& wallet_id,
                                      const std::string& tx_id,
                                      const Device& device) = 0;
  virtual Transaction SignTransaction(const Wallet& wallet,
                                      const Transaction& tx,
                                      const Device& device) = 0;
  virtual void SetPreferScriptPath(const Wallet& wallet,
                                   const std::string& tx_id, bool value) = 0;
  virtual bool IsPreferScriptPath(const Wallet& wallet,
                                  const std::string& tx_id) = 0;
  virtual void CacheMasterSignerXPub(
      const std::string& mastersigner_id,
      std::function<bool /* stop */ (int /* percent */)> progress) = 0;
  virtual void DisplayAddressOnDevice(
      const std::string& wallet_id, const std::string& address,
      const std::string& device_fingerprint = {}) = 0;
  virtual void PromtPinOnDevice(const Device& device) = 0;
  virtual void SendPinToDevice(const Device& device,
                               const std::string& pin) = 0;
  virtual void SendPassphraseToDevice(const Device& device,
                                      const std::string& passphrase) = 0;

  // The following methods is for signing server requests
  virtual std::string SignHealthCheckMessage(const SingleSigner& signer,
                                             const std::string& message) = 0;
  virtual std::string SignHealthCheckMessage(tap_protocol::Tapsigner* tapsigner,
                                             const std::string& cvc,
                                             const SingleSigner& signer,
                                             const std::string& message) = 0;

  // Group Wallet
  virtual void EnableGroupWallet(const std::string& osName,
                                 const std::string& osVersion,
                                 const std::string& appVersion,
                                 const std::string& deviceClass,
                                 const std::string& deviceId,
                                 const std::string& accessToken) = 0;
  virtual std::pair<std::string, std::string> ParseGroupUrl(
      const std::string& url) = 0;
  virtual GroupConfig GetGroupConfig() = 0;
  virtual std::string GetGroupDeviceUID() = 0;
  virtual void StartConsumeGroupEvent() = 0;
  virtual void StopConsumeGroupEvent() = 0;
  virtual GroupSandbox CreateGroup(const std::string& name, int m, int n,
                                   AddressType addressType) = 0;
  virtual GroupSandbox GetGroup(const std::string& groupId) = 0;
  virtual int GetGroupOnline(const std::string& groupId) = 0;
  virtual std::vector<GroupSandbox> GetGroups() = 0;
  virtual GroupSandbox JoinGroup(const std::string& groupId) = 0;
  virtual GroupSandbox CreateReplaceGroup(const std::string& walletId) = 0;
  virtual std::map<std::string, bool> GetReplaceGroups(
      const std::string& walletId) = 0;
  virtual GroupSandbox AcceptReplaceGroup(const std::string& walletId,
                                          const std::string& groupId) = 0;
  virtual void DeclineReplaceGroup(const std::string& walletId,
                                   const std::string& groupId) = 0;
  virtual GroupSandbox SetSlotOccupied(const std::string& groupId, int index,
                                       bool value) = 0;
  virtual GroupSandbox AddSignerToGroup(const std::string& groupId,
                                        const SingleSigner& signer,
                                        int index) = 0;
  virtual GroupSandbox RemoveSignerFromGroup(const std::string& groupId,
                                             int index) = 0;
  virtual GroupSandbox UpdateGroup(const std::string& groupId,
                                   const std::string& name, int m, int n,
                                   AddressType addressType) = 0;
  virtual GroupSandbox FinalizeGroup(
      const std::string& groupId, const std::set<size_t>& valueKeyset = {}) = 0;
  virtual void DeleteGroup(const std::string& groupId) = 0;
  virtual std::vector<Wallet> GetGroupWallets() = 0;
  virtual std::vector<std::string> GetDeprecatedGroupWallets() = 0;
  virtual GroupWalletConfig GetGroupWalletConfig(
      const std::string& walletId) = 0;
  virtual void SetGroupWalletConfig(const std::string& walletId,
                                    const GroupWalletConfig& config) = 0;
  virtual bool CheckGroupWalletExists(const Wallet& wallet) = 0;
  virtual void RecoverGroupWallet(const std::string& walletId) = 0;
  virtual void SendGroupMessage(const std::string& walletId,
                                const std::string& msg,
                                const SingleSigner& signer = {}) = 0;
  virtual void SetLastReadMessage(const std::string& walletId,
                                  const std::string& messageId) = 0;
  virtual int GetUnreadMessagesCount(const std::string& walletId) = 0;
  virtual std::vector<GroupMessage> GetGroupMessages(
      const std::string& walletId, int page, int pageSize, bool latest) = 0;
  virtual std::string DecryptGroupWalletId(const std::string& walletGid) = 0;
  virtual std::string DecryptGroupTxId(const std::string& walletId,
                                       const std::string& txGid) = 0;
  virtual void AddGroupUpdateListener(
      std::function<void(const GroupSandbox& state)> listener) = 0;
  virtual void AddGroupMessageListener(
      std::function<void(const GroupMessage& msg)> listener) = 0;
  virtual void AddGroupOnlineListener(
      std::function<void(const std::string& groupId, int online)> listener) = 0;
  virtual void AddGroupDeleteListener(
      std::function<void(const std::string& groupId)> listener) = 0;
  virtual void AddReplaceRequestListener(
      std::function<void(const std::string& walletId,
                         const std::string& replaceGroupId)>
          listener) = 0;

 protected:
  Nunchuk() = default;
};

struct BtcUri {
  std::string address;
  Amount amount{};
  std::string label;
  std::string message;
  std::map<std::string, std::string> others;
};

struct AnalyzeQRResult {
  bool is_success;
  bool is_failure;
  bool is_complete;
  size_t expected_part_count;
  std::set<size_t> received_part_indexes;
  std::set<size_t> last_part_indexes;
  size_t processed_parts_count;
  double estimated_percent_complete;
};

struct BSMSData {
  std::string version;
  std::string descriptor;
  std::string path_restrictions;
  std::string first_address;
};

class NUNCHUK_EXPORT Utils {
 public:
  static void SetChain(Chain chain);
  static Chain GetChain();
  static std::string GenerateRandomMessage(int message_length = 20);
  static std::string GenerateRandomChainCode();
  static std::string GenerateHealthCheckMessage();
  static bool IsValidXPub(const std::string& value);
  static bool IsValidXPrv(const std::string& value);
  static bool IsValidPublicKey(const std::string& value);
  static bool IsValidDerivationPath(const std::string& value);
  static bool IsValidFingerPrint(const std::string& value);
  static bool IsDustOutput(const TxOutput& txout);
  static bool IsValidAddress(const std::string& address);
  static Amount AmountFromValue(const std::string& value,
                                const bool allow_negative = false);
  static std::string ValueFromAmount(const Amount& amount);
  static bool MoneyRange(const Amount& nValue);
  static std::string AddressToScriptPubKey(const std::string& address);
  static std::string SanitizeBIP32Input(
      const std::string& slip132_input,
      const std::string& target_format = "xpub");
  static std::string GenerateMnemonic(int words = 24);
  static std::string GenerateMnemonic12Words();
  static bool CheckMnemonic(const std::string& mnemonic);
  static std::vector<std::string> GetBIP39WordList();
  static std::string SHA256(const std::string& data);
  static void SetPassPhrase(const std::string& storage_path,
                            const std::string& account, Chain chain,
                            const std::string& old_passphrase,
                            const std::string& new_passphrase);
  static std::vector<PrimaryKey> GetPrimaryKeys(const std::string& storage_path,
                                                Chain chain);
  static std::string GetPrimaryKeyAddress(const std::string& mnemonic,
                                          const std::string& passphrase);
  static std::string GetPrimaryKeyAddress(tap_protocol::Tapsigner* tapsigner,
                                          const std::string& cvc);

  static std::string GetMasterFingerprint(const std::string& mnemonic,
                                          const std::string& passphrase);
  static std::string GetMasterFingerprint(tap_protocol::Tapsigner* tapsigner,
                                          const std::string& cvc);

  static std::string SignLoginMessage(const std::string& mnemonic,
                                      const std::string& passphrase,
                                      const std::string& message);
  static std::string SignLoginMessage(tap_protocol::Tapsigner* tapsigner,
                                      const std::string& cvc,
                                      const std::string& message);

  static std::vector<Device> GetDevices(const std::string& hwi_path);

  static std::string SignPsbt(const std::string& mnemonic,
                              const std::string& passphrase,
                              const std::string& psbt);
  static std::string SignPsbt(tap_protocol::Tapsigner* tapsigner,
                              const std::string& cvc, const std::string& psbt);
  static std::string SignPsbt(const std::string& hwi_path, const Device& device,
                              const std::string& psbt);

  static Wallet ParseWalletDescriptor(const std::string& descs);
  static Wallet ParseKeystoneWallet(Chain chain,
                                    const std::vector<std::string>& qr_data);
  static BtcUri ParseBtcUri(const std::string& value);
  static Wallet ParseWalletConfig(Chain chain, const std::string& config);
  static BSMSData ParseBSMSData(const std::string& bsms);
  static SingleSigner ParseSignerString(const std::string& signer_str);
  static std::vector<Wallet> ParseJSONWallets(
      const std::string& json_str, SignerType signer_type = SignerType::AIRGAP);
  static std::vector<Wallet> ParseBBQRWallets(
      const std::vector<std::string>& qr_data);
  static std::vector<SingleSigner> ParsePassportSigners(
      Chain chain, const std::vector<std::string>& qr_data);
  static SingleSigner SanitizeSingleSigner(const SingleSigner& signer);
  static std::vector<SingleSigner> SanitizeSingleSigners(
      const std::vector<SingleSigner>& signers);
  static std::string GetHealthCheckMessage(const std::string& body);
  static std::string GetHealthCheckDummyTx(const Wallet& wallet,
                                           const std::string& body);
  static Transaction DecodeDummyTx(const Wallet& wallet,
                                   const std::string& psbt);
  static Transaction DecodeTx(const Wallet& wallet, const std::string& psbt,
                              const Amount& sub_amount, const Amount& fee,
                              const Amount& fee_rate);
  static std::string CreateRequestToken(const std::string& signature,
                                        const std::string& fingerprint);
  static std::string GetPartialSignature(const SingleSigner& signer,
                                         const std::string& signed_psbt);

  static std::vector<std::string> ExportKeystoneTransaction(
      const std::string& psbt, int fragment_len = 200);
  static std::vector<std::string> ExportPassportTransaction(
      const std::string& psbt, int fragment_len = 200);
  static std::string ParseKeystoneTransaction(
      const std::vector<std::string>& qr_data);
  static std::string ParsePassportTransaction(
      const std::vector<std::string>& qr_data);
  static std::vector<std::string> ExportBBQRTransaction(
      const std::string& psbt, int min_version = 1 /*1-40*/,
      int max_version = 40 /*1-40*/);
  static std::vector<std::string> ExportBBQRWallet(
      const Wallet& wallet, ExportFormat = ExportFormat::COLDCARD,
      int min_version = 1 /*1-40*/, int max_version = 1 /*1-40*/);
  static std::vector<std::string> ExportKeystoneWallet(const Wallet& wallet,
                                                       int fragment_len = 200);
  static std::vector<std::string> ExportBCR2020010Wallet(
      const Wallet& wallet, int fragment_len = 200);
  static AnalyzeQRResult AnalyzeQR(const std::vector<std::string>& qr_data);
  static int GetIndexFromPath(const std::string& path);
  static std::string GetBip32Path(WalletType wallet_type,
                                  AddressType address_type, int index);
  static std::vector<std::string> DeriveAddresses(const Wallet& wallet,
                                                  int from_index, int to_index);
  static bool NewDecoyPin(const std::string& storage_path,
                          const std::string& pin);
  static bool IsExistingDecoyPin(const std::string& storage_path,
                                 const std::string& pin);
  static bool ChangeDecoyPin(const std::string& storage_path,
                             const std::string& old_pin,
                             const std::string& new_pin);
  static std::vector<std::string> ListDecoyPin(const std::string& storage_path);
  static bool CheckElectrumServer(const std::string& server, int timeout = 1);

 private:
  Utils() {}
};

std::unique_ptr<Nunchuk> MakeNunchuk(const AppSettings& appsettings,
                                     const std::string& passphrase = "");

std::unique_ptr<Nunchuk> MakeNunchukForAccount(const AppSettings& appsettings,
                                               const std::string& passphrase,
                                               const std::string& account);

std::unique_ptr<Nunchuk> MakeNunchukForDecoyPin(const AppSettings& appsettings,
                                                const std::string& pin);

}  // namespace nunchuk

#endif  // NUNCHUK_INCLUDE_H
