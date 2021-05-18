// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nunchukimpl.h"

#include <coinselector.h>
#include <softwaresigner.h>
#include <key_io.h>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <utils/httplib.h>
#include <utils/bip32.hpp>
#include <utils/txutils.hpp>
#include <utils/addressutils.hpp>
#include <utils/json.hpp>
#include <utils/loguru.hpp>
#include <utils/quote.hpp>
#include <utils/multisigconfig.hpp>
#include <boost/algorithm/string.hpp>
#include <ur.h>

using json = nlohmann::json;
using namespace boost::algorithm;

namespace nunchuk {

static int MESSAGE_MIN_LEN = 8;
static int CACHE_SECOND = 600;  // 10 minutes

// Nunchuk implement
NunchukImpl::NunchukImpl(const AppSettings& appsettings,
                         const std::string& passphrase)
    : app_settings_(appsettings),
      storage_(app_settings_.get_storage_path(), passphrase),
      chain_(app_settings_.get_chain()),
      hwi_(app_settings_.get_hwi_path(), chain_) {
  CoreUtils::getInstance().SetChain(chain_);
  storage_.MaybeMigrate(chain_);
  std::fill(estimate_fee_cached_time_,
            estimate_fee_cached_time_ + ESTIMATE_FEE_CACHE_SIZE, 0);
  std::fill(estimate_fee_cached_value_,
            estimate_fee_cached_value_ + ESTIMATE_FEE_CACHE_SIZE, 0);
  synchronizer_ = MakeSynchronizer(app_settings_, &storage_);
  synchronizer_->Run();
}
Nunchuk::~Nunchuk() = default;
NunchukImpl::~NunchukImpl() {}

void NunchukImpl::SetPassphrase(const std::string& passphrase) {
  storage_.SetPassphrase(chain_, passphrase);
}

Wallet NunchukImpl::CreateWallet(const std::string& name, int m, int n,
                                 const std::vector<SingleSigner>& signers,
                                 AddressType address_type, bool is_escrow,
                                 const std::string& description) {
  Wallet wallet = storage_.CreateWallet(chain_, name, m, n, signers,
                                        address_type, is_escrow, description);
  ScanNewWallet(wallet.get_id(), wallet.is_escrow());
  return storage_.GetWallet(chain_, wallet.get_id(), true);
}

std::string NunchukImpl::DraftWallet(const std::string& name, int m, int n,
                                     const std::vector<SingleSigner>& signers,
                                     AddressType address_type, bool is_escrow,
                                     const std::string& description) {
  return GetDescriptorForSigners(
      signers, m, DescriptorPath::ANY, address_type,
      n == 1 ? WalletType::SINGLE_SIG
             : (is_escrow ? WalletType::ESCROW : WalletType::MULTI_SIG));
}

std::vector<Wallet> NunchukImpl::GetWallets() {
  auto wallet_ids = storage_.ListWallets(chain_);
  std::vector<Wallet> wallets;
  std::string selected_wallet = GetSelectedWallet();
  for (auto&& id : wallet_ids) {
    if (id == selected_wallet) continue;
    try {
      wallets.push_back(GetWallet(id));
    } catch (StorageException& se) {
      if (se.code() != StorageException::SIGNER_NOT_FOUND) {
        throw;
      }
    }
  }
  // Move selected_wallet to back so it will be scanned first when opening app
  if (!selected_wallet.empty()) try {
      wallets.push_back(GetWallet(selected_wallet));
    } catch (...) {
    }
  return wallets;
}

Wallet NunchukImpl::GetWallet(const std::string& wallet_id) {
  return storage_.GetWallet(chain_, wallet_id);
}

bool NunchukImpl::DeleteWallet(const std::string& wallet_id) {
  return storage_.DeleteWallet(chain_, wallet_id);
}

bool NunchukImpl::UpdateWallet(const Wallet& wallet) {
  return storage_.UpdateWallet(chain_, wallet);
}

bool NunchukImpl::ExportWallet(const std::string& wallet_id,
                               const std::string& file_path,
                               ExportFormat format) {
  return storage_.ExportWallet(chain_, wallet_id, file_path, format);
}

Wallet NunchukImpl::ImportWalletDb(const std::string& file_path) {
  std::string id = storage_.ImportWalletDb(chain_, file_path);
  return storage_.GetWallet(chain_, id, true);
}

Wallet NunchukImpl::ImportWalletDescriptor(const std::string& file_path,
                                           const std::string& name,
                                           const std::string& description) {
  std::string descs = trim_copy(storage_.LoadFile(file_path));
  AddressType address_type;
  WalletType wallet_type;
  int m;
  int n;
  std::vector<SingleSigner> signers;
  if (!ParseDescriptors(descs, address_type, wallet_type, m, n, signers)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Could not parse descriptor");
  }
  return CreateWallet(name, m, n, signers, address_type,
                      wallet_type == WalletType::ESCROW, description);
}

Wallet NunchukImpl::ImportWalletConfigFile(const std::string& file_path,
                                           const std::string& description) {
  std::string config = storage_.LoadFile(file_path);
  return ImportWalletFromConfig(config, description);
}

Wallet NunchukImpl::ImportWalletFromConfig(const std::string& config,
                                           const std::string& description) {
  std::string name;
  AddressType address_type;
  WalletType wallet_type;
  int m;
  int n;
  std::vector<SingleSigner> signers;
  if (!ParseConfig(chain_, config, name, address_type, wallet_type, m, n,
                   signers)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Could not parse multisig config");
  }
  return CreateWallet(name, m, n, signers, address_type, false, description);
}

void NunchukImpl::ScanNewWallet(const std::string wallet_id, bool is_escrow) {
  int index = is_escrow ? -1 : 0;
  std::string address;
  if (is_escrow) {
    synchronizer_->LookAhead(chain_, wallet_id, address, index, false);
    auto descriptor =
        GetWallet(wallet_id).get_descriptor(DescriptorPath::EXTERNAL_ALL);
    address = CoreUtils::getInstance().DeriveAddresses(descriptor, index);
  } else {
    int change_index = 0;
    GetUnusedAddress(wallet_id, change_index, true);  // scan change address
    address = GetUnusedAddress(wallet_id, index, false);
  }

  // auto create an unused external address
  storage_.AddAddress(chain_, wallet_id, address, index, false);
}

std::string NunchukImpl::GetUnusedAddress(const std::string wallet_id,
                                          int& index, bool internal) {
  auto descriptor = GetWallet(wallet_id).get_descriptor(
      internal ? DescriptorPath::INTERNAL_ALL : DescriptorPath::EXTERNAL_ALL);
  int consecutive_unused = 0;
  std::vector<std::string> unused_addresses;
  while (true) {
    auto address = CoreUtils::getInstance().DeriveAddresses(descriptor, index);
    bool used =
        synchronizer_->LookAhead(chain_, wallet_id, address, index, internal);
    if (used) {
      for (auto&& a : unused_addresses) {
        storage_.AddAddress(chain_, wallet_id, a, index, internal);
      }
      unused_addresses.clear();
      consecutive_unused = 0;
    } else {
      unused_addresses.push_back(address);
      consecutive_unused++;
    }
    index++;
    if (consecutive_unused == 20) {
      index = index - 20;
      return unused_addresses[0];
    }
  }
}

std::vector<Device> NunchukImpl::GetDevices() { return hwi_.Enumerate(); }

void NunchukImpl::PromtPinOnDevice(const Device& device) {
  hwi_.PromptPin(device);
}

void NunchukImpl::SendPinToDevice(const Device& device,
                                  const std::string& pin) {
  hwi_.SendPin(device, pin);
}

MasterSigner NunchukImpl::CreateMasterSigner(
    const std::string& raw_name, const Device& device,
    std::function<bool(int)> progress) {
  std::string name = trim_copy(raw_name);
  std::string id = storage_.CreateMasterSigner(chain_, name, device);

  storage_.CacheMasterSignerXPub(
      chain_, id,
      [&](std::string path) { return hwi_.GetXpubAtPath(device, path); },
      progress, true);

  MasterSigner mastersigner{id, device, std::time(0)};
  mastersigner.set_name(name);
  return mastersigner;
}

MasterSigner NunchukImpl::CreateSoftwareSigner(
    const std::string& raw_name, const std::string& mnemonic,
    const std::string& passphrase, std::function<bool(int)> progress) {
  std::string name = trim_copy(raw_name);
  SoftwareSigner signer{mnemonic, passphrase};
  Device device{"software", "nunchuk", signer.GetMasterFingerprint()};
  std::string id = storage_.CreateMasterSigner(chain_, name, device, mnemonic);
  storage_.SendSignerPassphrase(chain_, id, passphrase);

  storage_.CacheMasterSignerXPub(
      chain_, id, [&](std::string path) { return signer.GetXpubAtPath(path); },
      progress, true);

  MasterSigner mastersigner{id, device, std::time(0), true};
  mastersigner.set_name(name);
  return mastersigner;
}

void NunchukImpl::SendSignerPassphrase(const std::string& mastersigner_id,
                                       const std::string& passphrase) {
  storage_.SendSignerPassphrase(chain_, mastersigner_id, passphrase);
}

SingleSigner NunchukImpl::GetSignerFromMasterSigner(
    const std::string& mastersigner_id, const WalletType& wallet_type,
    const AddressType& address_type, int index) {
  return storage_.GetSignerFromMasterSigner(chain_, mastersigner_id,
                                            wallet_type, address_type, index);
}

SingleSigner NunchukImpl::CreateSigner(const std::string& raw_name,
                                       const std::string& xpub,
                                       const std::string& public_key,
                                       const std::string& derivation_path,
                                       const std::string& master_fingerprint) {
  std::string target_format = chain_ == Chain::MAIN ? "xpub" : "tpub";
  std::string sanitized_xpub = Utils::SanitizeBIP32Input(xpub, target_format);
  if (!Utils::IsValidXPub(sanitized_xpub) &&
      !Utils::IsValidPublicKey(public_key)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "invalid xpub and public_key");
  }
  if (!Utils::IsValidDerivationPath(derivation_path)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "invalid derivation path");
  }
  if (!Utils::IsValidFingerPrint(master_fingerprint)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "invalid master fingerprint");
  }
  std::string name = trim_copy(raw_name);
  return storage_.CreateSingleSigner(chain_, name, sanitized_xpub, public_key,
                                     derivation_path, master_fingerprint);
}

int NunchukImpl::GetCurrentIndexFromMasterSigner(
    const std::string& mastersigner_id, const WalletType& wallet_type,
    const AddressType& address_type) {
  return storage_.GetCurrentIndexFromMasterSigner(chain_, mastersigner_id,
                                                  wallet_type, address_type);
}

SingleSigner NunchukImpl::GetUnusedSignerFromMasterSigner(
    const std::string& mastersigner_id, const WalletType& wallet_type,
    const AddressType& address_type) {
  int index = GetCurrentIndexFromMasterSigner(mastersigner_id, wallet_type,
                                              address_type);
  if (index < 0) {
    throw NunchukException(NunchukException::RUN_OUT_OF_CACHED_XPUB,
                           "run out of cached xpub!");
  }
  return GetSignerFromMasterSigner(mastersigner_id, wallet_type, address_type,
                                   index);
}

std::vector<SingleSigner> NunchukImpl::GetSignersFromMasterSigner(
    const std::string& mastersigner_id) {
  return storage_.GetSignersFromMasterSigner(chain_, mastersigner_id);
}

int NunchukImpl::GetNumberOfSignersFromMasterSigner(
    const std::string& mastersigner_id) {
  return GetSignersFromMasterSigner(mastersigner_id).size();
}

std::vector<MasterSigner> NunchukImpl::GetMasterSigners() {
  auto mastersigner_ids = storage_.ListMasterSigners(chain_);
  std::vector<MasterSigner> mastersigners;
  for (auto&& id : mastersigner_ids) {
    if (storage_.IsMasterSigner(chain_, id)) {
      mastersigners.push_back(GetMasterSigner(id));
    }
  }
  return mastersigners;
}

MasterSigner NunchukImpl::GetMasterSigner(const std::string& mastersigner_id) {
  return storage_.GetMasterSigner(chain_, mastersigner_id);
}

bool NunchukImpl::DeleteMasterSigner(const std::string& mastersigner_id) {
  return storage_.DeleteMasterSigner(chain_, mastersigner_id);
}

bool NunchukImpl::UpdateMasterSigner(const MasterSigner& mastersigner) {
  return storage_.UpdateMasterSigner(chain_, mastersigner);
}

std::vector<SingleSigner> NunchukImpl::GetRemoteSigners() {
  return storage_.GetRemoteSigners(chain_);
}

bool NunchukImpl::DeleteRemoteSigner(const std::string& master_fingerprint,
                                     const std::string& derivation_path) {
  return storage_.DeleteRemoteSigner(chain_, master_fingerprint,
                                     derivation_path);
}

bool NunchukImpl::UpdateRemoteSigner(const SingleSigner& remotesigner) {
  return storage_.UpdateRemoteSigner(chain_, remotesigner);
}

std::string NunchukImpl::GetHealthCheckPath() {
  return (chain_ == Chain::MAIN ? MAINNET_HEALTH_CHECK_PATH
                                : TESTNET_HEALTH_CHECK_PATH);
}

HealthStatus NunchukImpl::HealthCheckMasterSigner(
    const std::string& fingerprint, std::string& message,
    std::string& signature, std::string& path) {
  message = message.empty() ? Utils::GenerateRandomMessage() : message;
  if (message.size() < MESSAGE_MIN_LEN) {
    throw std::runtime_error("message too short!");
  }

  bool existed = true;
  std::string id = fingerprint;
  try {
    if (GetMasterSigner(id).is_software()) {
      return HealthStatus::SUCCESS;
    }
  } catch (StorageException& se) {
    if (se.code() == StorageException::MASTERSIGNER_NOT_FOUND) {
      existed = false;
    } else {
      throw;
    }
  }

  Device device{fingerprint};
  path = chain_ == Chain::MAIN ? MAINNET_HEALTH_CHECK_PATH
                               : TESTNET_HEALTH_CHECK_PATH;
  std::string xpub = hwi_.GetXpubAtPath(device, path);
  if (existed) {
    std::string master_xpub = hwi_.GetXpubAtPath(device, "m");
    if (master_xpub != storage_.GetMasterSignerXPub(chain_, id, "m")) {
      return HealthStatus::KEY_NOT_MATCHED;
    }

    if (xpub != storage_.GetMasterSignerXPub(chain_, id, path)) {
      return HealthStatus::KEY_NOT_MATCHED;
    }
  }

  std::string descriptor = GetPkhDescriptor(xpub);
  std::string address = CoreUtils::getInstance().DeriveAddresses(descriptor);
  signature = hwi_.SignMessage(device, message, path);

  if (CoreUtils::getInstance().VerifyMessage(address, signature, message)) {
    if (existed) storage_.SetHealthCheckSuccess(chain_, id);
    return HealthStatus::SUCCESS;
  } else {
    return HealthStatus::SIGNATURE_INVALID;
  }
}

HealthStatus NunchukImpl::HealthCheckSingleSigner(
    const SingleSigner& signer, const std::string& message,
    const std::string& signature) {
  if (message.size() < MESSAGE_MIN_LEN) {
    throw NunchukException(NunchukException::MESSAGE_TOO_SHORT,
                           "message too short!");
  }

  std::string address;
  if (signer.get_public_key().empty()) {
    std::string descriptor = GetPkhDescriptor(signer.get_xpub());
    address = CoreUtils::getInstance().DeriveAddresses(descriptor);
  } else {
    CPubKey pubkey(ParseHex(signer.get_public_key()));
    address = EncodeDestination(PKHash(pubkey.GetID()));
  }

  if (CoreUtils::getInstance().VerifyMessage(address, signature, message)) {
    storage_.SetHealthCheckSuccess(chain_, signer);
    return HealthStatus::SUCCESS;
  } else {
    return HealthStatus::SIGNATURE_INVALID;
  }
}

std::vector<Transaction> NunchukImpl::GetTransactionHistory(
    const std::string& wallet_id, int count, int skip) {
  return storage_.GetTransactions(chain_, wallet_id, count, skip);
}

bool NunchukImpl::ExportTransactionHistory(const std::string& wallet_id,
                                           const std::string& file_path,
                                           ExportFormat format) {
  if (format != ExportFormat::CSV) return false;
  std::stringstream value;
  auto txs = GetTransactionHistory(wallet_id, 10000, 0);
  value << "txid,fee,amount,height,memo" << std::endl;
  for (auto tx : txs) {
    value << tx.get_txid() << "," << tx.get_fee() << ","
          << ((tx.is_receive() ? 1 : -1) * tx.get_sub_amount()) << ","
          << tx.get_height() << "," << quoted(tx.get_memo()) << std::endl;
  }
  return storage_.WriteFile(file_path, value.str());
}

std::vector<std::string> NunchukImpl::GetAddresses(const std::string& wallet_id,
                                                   bool used, bool internal) {
  return storage_.GetAddresses(chain_, wallet_id, used, internal);
}

std::string NunchukImpl::NewAddress(const std::string& wallet_id,
                                    bool internal) {
  std::string descriptor = GetWallet(wallet_id).get_descriptor(
      internal ? DescriptorPath::INTERNAL_ALL : DescriptorPath::EXTERNAL_ALL);
  int index = storage_.GetCurrentAddressIndex(chain_, wallet_id, internal) + 1;
  while (true) {
    auto address = CoreUtils::getInstance().DeriveAddresses(descriptor, index);
    if (!synchronizer_->LookAhead(chain_, wallet_id, address, index,
                                  internal)) {
      storage_.AddAddress(chain_, wallet_id, address, index, internal);
      return address;
    }
    index++;
  }
}

Amount NunchukImpl::GetAddressBalance(const std::string& wallet_id,
                                      const std::string& address) {
  return storage_.GetAddressBalance(chain_, wallet_id, address);
}

std::vector<UnspentOutput> NunchukImpl::GetUnspentOutputs(
    const std::string& wallet_id) {
  return storage_.GetUnspentOutputs(chain_, wallet_id);
}

bool NunchukImpl::ExportUnspentOutputs(const std::string& wallet_id,
                                       const std::string& file_path,
                                       ExportFormat format) {
  if (format != ExportFormat::CSV) return false;
  std::stringstream value;
  auto utxos = GetUnspentOutputs(wallet_id);
  value << "txid,vout,amount,height,memo" << std::endl;
  for (auto utxo : utxos) {
    value << utxo.get_txid() << "," << utxo.get_vout() << ","
          << utxo.get_amount() << "," << utxo.get_height() << ","
          << quoted(utxo.get_memo()) << std::endl;
  }
  return storage_.WriteFile(file_path, value.str());
}

Transaction NunchukImpl::CreateTransaction(
    const std::string& wallet_id, const std::map<std::string, Amount> outputs,
    const std::string& memo, const std::vector<UnspentOutput> inputs,
    Amount fee_rate, bool subtract_fee_from_amount) {
  Amount fee = 0;
  int change_pos = 0;
  if (fee_rate <= 0) fee_rate = EstimateFee();
  auto psbt = CreatePsbt(wallet_id, outputs, inputs, fee_rate,
                         subtract_fee_from_amount, true, fee, change_pos);
  return storage_.CreatePsbt(chain_, wallet_id, psbt, fee, memo, change_pos,
                             outputs, fee_rate, subtract_fee_from_amount);
}

bool NunchukImpl::ExportTransaction(const std::string& wallet_id,
                                    const std::string& tx_id,
                                    const std::string& file_path) {
  std::string psbt = storage_.GetPsbt(chain_, wallet_id, tx_id);
  return storage_.WriteFile(file_path, psbt);
}

Transaction NunchukImpl::ImportPsbt(const std::string& wallet_id,
                                    const std::string& base64_psbt) {
  std::string psbt = boost::trim_copy(base64_psbt);
  std::string tx_id = GetTxIdFromPsbt(psbt);
  std::string existed_psbt = storage_.GetPsbt(chain_, wallet_id, tx_id);
  if (!existed_psbt.empty()) {
    std::string combined_psbt =
        CoreUtils::getInstance().CombinePsbt({psbt, existed_psbt});
    storage_.UpdatePsbt(chain_, wallet_id, combined_psbt);
    return GetTransaction(wallet_id, tx_id);
  }
  return storage_.CreatePsbt(chain_, wallet_id, psbt);
}

Transaction NunchukImpl::ImportTransaction(const std::string& wallet_id,
                                           const std::string& file_path) {
  std::string psbt = storage_.LoadFile(file_path);
  if (boost::starts_with(psbt, "psbt")) {
    psbt = EncodeBase64(MakeUCharSpan(psbt));
  }
  return ImportPsbt(wallet_id, psbt);
}

Transaction NunchukImpl::SignTransaction(const std::string& wallet_id,
                                         const std::string& tx_id,
                                         const Device& device) {
  std::string psbt = storage_.GetPsbt(chain_, wallet_id, tx_id);
  DLOG_F(INFO, "NunchukImpl::SignTransaction(), psbt='%s'", psbt.c_str());
  auto mastersigner_id = device.get_master_fingerprint();
  std::string signed_psbt;
  if (GetMasterSigner(mastersigner_id).is_software()) {
    auto software_signer = storage_.GetSoftwareSigner(chain_, mastersigner_id);
    signed_psbt = software_signer.SignTx(psbt);
  } else {
    signed_psbt = hwi_.SignTx(device, psbt);
  }
  DLOG_F(INFO, "NunchukImpl::SignTransaction(), signed_psbt='%s'",
         signed_psbt.c_str());
  storage_.UpdatePsbt(chain_, wallet_id, signed_psbt);
  return GetTransaction(wallet_id, tx_id);
}

Transaction NunchukImpl::BroadcastTransaction(const std::string& wallet_id,
                                              const std::string& tx_id) {
  std::string psbt = storage_.GetPsbt(chain_, wallet_id, tx_id);
  std::string raw_tx = CoreUtils::getInstance().FinalizePsbt(psbt);
  // finalizepsbt will change the txid for legacy and nested-segwit
  // transactions. We need to update our PSBT record in the DB
  std::string new_txid = DecodeRawTransaction(raw_tx).GetHash().GetHex();
  if (tx_id != new_txid) {
    storage_.UpdatePsbtTxId(chain_, wallet_id, tx_id, new_txid);
  }
  try {
    synchronizer_->Broadcast(raw_tx);
  } catch (NunchukException& ne) {
    if (ne.code() == NunchukException::SERVER_REQUEST_ERROR &&
        boost::starts_with(ne.what(),
                           "the transaction was rejected by network rules.")) {
      storage_.UpdateTransaction(chain_, wallet_id, raw_tx, -2, 0, ne.what());
      throw;
    }
  }
  storage_.UpdateTransaction(chain_, wallet_id, raw_tx, 0, 0);
  return GetTransaction(wallet_id, new_txid);
}

Transaction NunchukImpl::GetTransaction(const std::string& wallet_id,
                                        const std::string& tx_id) {
  return storage_.GetTransaction(chain_, wallet_id, tx_id);
}

bool NunchukImpl::DeleteTransaction(const std::string& wallet_id,
                                    const std::string& tx_id) {
  return storage_.DeleteTransaction(chain_, wallet_id, tx_id);
}

AppSettings NunchukImpl::GetAppSettings() { return app_settings_; }

AppSettings NunchukImpl::UpdateAppSettings(const AppSettings& settings) {
  app_settings_ = settings;
  chain_ = app_settings_.get_chain();
  hwi_.SetPath(app_settings_.get_hwi_path());
  hwi_.SetChain(chain_);
  CoreUtils::getInstance().SetChain(chain_);
  if (synchronizer_->NeedRecreate(settings)) {
    std::fill(estimate_fee_cached_time_,
              estimate_fee_cached_time_ + ESTIMATE_FEE_CACHE_SIZE, 0);
    std::fill(estimate_fee_cached_value_,
              estimate_fee_cached_value_ + ESTIMATE_FEE_CACHE_SIZE, 0);
    synchronizer_ = MakeSynchronizer(app_settings_, &storage_);
    synchronizer_->Run();
  }
  return settings;
}

Transaction NunchukImpl::DraftTransaction(
    const std::string& wallet_id, const std::map<std::string, Amount> outputs,
    const std::vector<UnspentOutput> inputs, Amount fee_rate,
    bool subtract_fee_from_amount) {
  Amount fee = 0;
  int change_pos = 0;
  if (fee_rate <= 0) fee_rate = EstimateFee();
  auto psbt = CreatePsbt(wallet_id, outputs, inputs, fee_rate,
                         subtract_fee_from_amount, false, fee, change_pos);
  Wallet wallet = GetWallet(wallet_id);
  int m = wallet.get_m();
  auto tx = GetTransactionFromPartiallySignedTransaction(
      DecodePsbt(psbt), wallet.get_signers(), m);
  tx.set_m(m);
  tx.set_fee(fee);
  tx.set_change_index(change_pos);
  tx.set_receive(false);
  tx.set_sub_amount(0);
  tx.set_fee_rate(fee_rate);
  tx.set_subtract_fee_from_amount(subtract_fee_from_amount);
  return tx;
}

Transaction NunchukImpl::ReplaceTransaction(const std::string& wallet_id,
                                            const std::string& tx_id,
                                            Amount new_fee_rate) {
  auto tx = storage_.GetTransaction(chain_, wallet_id, tx_id);
  if (new_fee_rate < tx.get_fee_rate()) {
    throw NunchukException(NunchukException::INVALID_FEE_RATE,
                           "invalid new fee rate");
  }

  std::map<std::string, Amount> outputs;
  for (auto&& output : tx.get_user_outputs()) {
    outputs[output.first] = output.second;
  }
  std::vector<UnspentOutput> inputs;
  for (auto&& input : tx.get_inputs()) {
    auto tx = storage_.GetTransaction(chain_, wallet_id, input.first);
    auto output = tx.get_outputs()[input.second];
    UnspentOutput utxo;
    utxo.set_txid(input.first);
    utxo.set_vout(input.second);
    utxo.set_address(output.first);
    utxo.set_amount(output.second);
    utxo.set_height(tx.get_height());
    inputs.push_back(utxo);
  }

  Amount fee = 0;
  int change_pos = 0;
  auto psbt = CreatePsbt(wallet_id, outputs, inputs, new_fee_rate,
                         tx.subtract_fee_from_amount(), true, fee, change_pos);
  return storage_.CreatePsbt(chain_, wallet_id, psbt, fee, tx.get_memo(),
                             change_pos, outputs, new_fee_rate,
                             tx.subtract_fee_from_amount(), tx.get_txid());
}

bool NunchukImpl::UpdateTransactionMemo(const std::string& wallet_id,
                                        const std::string& tx_id,
                                        const std::string& new_memo) {
  return storage_.UpdateTransactionMemo(chain_, wallet_id, tx_id, new_memo);
}

void NunchukImpl::CacheMasterSignerXPub(const std::string& mastersigner_id,
                                        std::function<bool(int)> progress) {
  if (GetMasterSigner(mastersigner_id).is_software()) {
    auto software_signer = storage_.GetSoftwareSigner(chain_, mastersigner_id);
    storage_.CacheMasterSignerXPub(
        chain_, mastersigner_id,
        [&](const std::string& path) {
          return software_signer.GetXpubAtPath(path);
        },
        progress, false);
  } else {
    Device device{mastersigner_id};
    storage_.CacheMasterSignerXPub(
        chain_, mastersigner_id,
        [&](const std::string& path) {
          return hwi_.GetXpubAtPath(device, path);
        },
        progress, false);
  }
}

bool NunchukImpl::ExportHealthCheckMessage(const std::string& message,
                                           const std::string& file_path) {
  return storage_.WriteFile(file_path, message);
}

std::string NunchukImpl::ImportHealthCheckSignature(
    const std::string& file_path) {
  return boost::trim_copy(storage_.LoadFile(file_path));
}

Amount NunchukImpl::EstimateFee(int conf_target, bool use_mempool) {
  auto current_time = std::time(0);
  int cached_index = -1;
  if (use_mempool && chain_ == Chain::MAIN) {
    if (conf_target <= CONF_TARGET_PRIORITY)
      cached_index = 3;
    else if (conf_target <= CONF_TARGET_STANDARD)
      cached_index = 4;
    else
      cached_index = 5;
  } else {
    if (conf_target == CONF_TARGET_PRIORITY)
      cached_index = 0;
    else if (conf_target == CONF_TARGET_STANDARD)
      cached_index = 1;
    else if (conf_target == CONF_TARGET_ECONOMICAL)
      cached_index = 2;
  }
  if (cached_index >= 0 && cached_index < ESTIMATE_FEE_CACHE_SIZE &&
      current_time - estimate_fee_cached_time_[cached_index] <= CACHE_SECOND) {
    return estimate_fee_cached_value_[cached_index];
  } else if (use_mempool && chain_ == Chain::MAIN) {
    httplib::Client cli("https://mempool.space");
    auto res = cli.Get("/api/v1/fees/recommended");
    if (!res) {
      throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                             "Send request error");
    }
    json recommended = json::parse(res->body);
    estimate_fee_cached_time_[3] = current_time;
    estimate_fee_cached_time_[4] = current_time;
    estimate_fee_cached_time_[5] = current_time;
    estimate_fee_cached_value_[3] = recommended["fastestFee"];
    estimate_fee_cached_value_[4] = recommended["hourFee"];
    estimate_fee_cached_value_[5] = recommended["minimumFee"];
    return estimate_fee_cached_value_[cached_index];
  }
  Amount rs = synchronizer_->EstimateFee(conf_target);
  if (cached_index >= 0) {
    estimate_fee_cached_value_[cached_index] = rs;
    estimate_fee_cached_time_[cached_index] = current_time;
  }
  return rs;
}

int NunchukImpl::GetChainTip() { return synchronizer_->GetChainTip(); }

Amount NunchukImpl::GetTotalAmount(const std::string& wallet_id,
                                   const std::vector<TxInput>& inputs) {
  Amount total = 0;
  for (auto&& input : inputs) {
    auto tx = GetTransaction(wallet_id, input.first);
    total += tx.get_outputs()[input.second].second;
  }
  return total;
}

std::string NunchukImpl::GetSelectedWallet() {
  return storage_.GetSelectedWallet(chain_);
}

bool NunchukImpl::SetSelectedWallet(const std::string& wallet_id) {
  return storage_.SetSelectedWallet(chain_, wallet_id);
}

void NunchukImpl::DisplayAddressOnDevice(
    const std::string& wallet_id, const std::string& address,
    const std::string& device_fingerprint) {
  Wallet wallet = GetWallet(wallet_id);
  std::string desc = wallet.get_descriptor(
      DescriptorPath::EXTERNAL,
      wallet.is_escrow()
          ? -1
          : storage_.GetAddressIndex(chain_, wallet_id, address));

  if (device_fingerprint.empty()) {
    auto devices = GetDevices();
    for (auto&& device : devices) {
      for (auto&& signer : wallet.get_signers()) {
        if (signer.get_master_fingerprint() ==
            device.get_master_fingerprint()) {
          hwi_.DisplayAddress(device, desc);
        }
      }
    }
  } else {
    hwi_.DisplayAddress(Device{device_fingerprint}, desc);
  }
}
SingleSigner NunchukImpl::CreateCoboSigner(const std::string& name,
                                           const std::string& json_info) {
  json info = json::parse(json_info);
  std::string xfp, xpub, path;
  if (info["xfp"] == nullptr) {
    xfp = info["MasterFingerprint"];
    xpub = info["ExtPubKey"];
    path = "m/" + info["AccountKeyPath"].get<std::string>();
  } else {
    xfp = info["xfp"];
    xpub = info["xpub"];
    path = info["path"];
  }
  return CreateSigner(name, xpub, {}, path, xfp);
}

std::vector<std::string> NunchukImpl::ExportCoboWallet(
    const std::string& wallet_id) {
  auto content = storage_.GetMultisigConfig(chain_, wallet_id, true);
  std::vector<uint8_t> data(content.begin(), content.end());
  return nunchuk::bcr::EncodeUniformResource(data);
}

std::vector<std::string> NunchukImpl::ExportCoboTransaction(
    const std::string& wallet_id, const std::string& tx_id) {
  std::string base64_psbt = storage_.GetPsbt(chain_, wallet_id, tx_id);
  bool invalid;
  auto psbt = DecodeBase64(base64_psbt.c_str(), &invalid);
  if (invalid) {
    throw NunchukException(NunchukException::INVALID_PSBT, "Invalid base64");
  }
  return nunchuk::bcr::EncodeUniformResource(psbt);
}

Transaction NunchukImpl::ImportCoboTransaction(
    const std::string& wallet_id, const std::vector<std::string>& qr_data) {
  auto psbt = nunchuk::bcr::DecodeUniformResource(qr_data);
  return ImportPsbt(wallet_id, EncodeBase64(MakeUCharSpan(psbt)));
}

Wallet NunchukImpl::ImportCoboWallet(const std::vector<std::string>& qr_data,
                                     const std::string& description) {
  auto config = nunchuk::bcr::DecodeUniformResource(qr_data);
  std::string config_str(config.begin(), config.end());
  return ImportWalletFromConfig(config_str, description);
}

void NunchukImpl::RescanBlockchain(int start_height, int stop_height) {
  synchronizer_->RescanBlockchain(start_height, stop_height);
}

void NunchukImpl::AddBalanceListener(
    std::function<void(std::string, Amount)> listener) {
  synchronizer_->AddBalanceListener(listener);
}

void NunchukImpl::AddBlockListener(
    std::function<void(int, std::string)> listener) {
  synchronizer_->AddBlockListener(listener);
}

void NunchukImpl::AddTransactionListener(
    std::function<void(std::string, TransactionStatus)> listener) {
  synchronizer_->AddTransactionListener(listener);
}

void NunchukImpl::AddDeviceListener(
    std::function<void(std::string, bool)> listener) {
  device_listener_.connect(listener);
}

void NunchukImpl::AddBlockchainConnectionListener(
    std::function<void(ConnectionStatus, int)> listener) {
  synchronizer_->AddBlockchainConnectionListener(listener);
}

std::string NunchukImpl::CreatePsbt(const std::string& wallet_id,
                                    const std::map<std::string, Amount> outputs,
                                    const std::vector<UnspentOutput> inputs,
                                    Amount fee_rate,
                                    bool subtract_fee_from_amount,
                                    bool utxo_update_psbt, Amount& fee,
                                    int& change_pos) {
  Wallet wallet = GetWallet(wallet_id);
  std::vector<UnspentOutput> utxos =
      inputs.empty() ? GetUnspentOutputs(wallet_id) : inputs;

  std::vector<TxInput> selector_inputs;
  std::vector<TxOutput> selector_outputs;
  for (const auto& output : outputs) {
    selector_outputs.push_back(TxOutput(output.first, output.second));
  }

  std::string change_address;
  if (wallet.is_escrow()) {
    // Use the only address as change_address to pass in selector
    change_address = storage_.GetAllAddresses(chain_, wallet_id)[0];
  } else {
    auto unused = GetAddresses(wallet_id, false, true);
    change_address = unused.empty() ? NewAddress(wallet_id, true) : unused[0];
  }
  std::string error;
  std::string internal_desc =
      wallet.get_descriptor(DescriptorPath::INTERNAL_ALL);
  std::string external_desc =
      wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL);
  std::string desc = GetDescriptorsImportString(external_desc, internal_desc);
  CoinSelector selector{desc, change_address};
  selector.set_fee_rate(CFeeRate(fee_rate));
  selector.set_discard_rate(CFeeRate(synchronizer_->RelayFee()));

  // For escrow use all utxos as inputs
  if (!selector.Select(utxos, wallet.is_escrow() ? utxos : inputs,
                       change_address, subtract_fee_from_amount,
                       selector_outputs, selector_inputs, fee, error,
                       change_pos)) {
    throw NunchukException(NunchukException::COIN_SELECTION_ERROR, error);
  }

  std::string psbt =
      CoreUtils::getInstance().CreatePsbt(selector_inputs, selector_outputs);
  if (!utxo_update_psbt) return psbt;
  return storage_.FillPsbt(chain_, wallet_id, psbt);
}

std::unique_ptr<Nunchuk> MakeNunchuk(const AppSettings& appsettings,
                                     const std::string& passphrase) {
  return std::unique_ptr<NunchukImpl>(new NunchukImpl(appsettings, passphrase));
}

}  // namespace nunchuk