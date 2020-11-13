// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nunchukimpl.h"

#include <coinselector.h>
#include <key_io.h>
#include <utils/bip32.hpp>
#include <utils/txutils.hpp>
#include <utils/addressutils.hpp>
#include <utils/json.hpp>
#include <utils/loguru.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

using json = nlohmann::json;
using namespace boost::algorithm;

namespace nunchuk {

static int MESSAGE_MIN_LEN = 8;

// Nunchuk implement
NunchukImpl::NunchukImpl(const AppSettings& appsettings,
                         const std::string& passphrase)
    : app_settings_(appsettings),
      storage_(app_settings_.get_storage_path(), passphrase),
      chain_(app_settings_.get_chain()),
      hwi_(app_settings_.get_hwi_path(), chain_),
      synchronizer_(&storage_) {
  CoreUtils::getInstance().SetChain(chain_);
  storage_.MaybeMigrate(chain_);
  synchronizer_.Run(app_settings_);
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
  std::string descriptor =
      storage_.GetDescriptor(chain_, wallet.get_id(), false);
  int index = is_escrow ? -1 : 0;
  auto address = CoreUtils::getInstance().DeriveAddresses(descriptor, index);
  storage_.AddAddress(chain_, wallet.get_id(), address, index, false);
  synchronizer_.SubscribeAddress(wallet.get_id(), address);
  return wallet;
}

std::string NunchukImpl::DraftWallet(const std::string& name, int m, int n,
                                     const std::vector<SingleSigner>& signers,
                                     AddressType address_type, bool is_escrow,
                                     const std::string& description) {
  WalletType wallet_type =
      n == 1 ? WalletType::SINGLE_SIG
             : (is_escrow ? WalletType::ESCROW : WalletType::MULTI_SIG);
  std::stringstream descs;
  descs << GetDescriptorForSigners(signers, m, false, address_type,
                                   wallet_type);
  if (!is_escrow) {
    descs << "\n" + GetDescriptorForSigners(signers, m, true, address_type,
                                            wallet_type);
  }
  return descs.str();
}

std::vector<Wallet> NunchukImpl::GetWallets() {
  auto wallet_ids = storage_.ListWallets(chain_);
  std::vector<Wallet> wallets;
  std::string selected_wallet = GetSelectedWallet();
  for (auto&& id : wallet_ids) {
    if (id == selected_wallet) continue;
    wallets.push_back(GetWallet(id));
  }
  // Move selected_wallet to back so it will be scanned first when opening app
  if (!selected_wallet.empty()) wallets.push_back(GetWallet(selected_wallet));
  return wallets;
}

Wallet NunchukImpl::GetWallet(const std::string& wallet_id) {
  return storage_.GetWallet(chain_, wallet_id);
}

bool NunchukImpl::DeleteWallet(const std::string& wallet_id) {
  return storage_.DeleteWallet(chain_, wallet_id);
}

bool NunchukImpl::UpdateWallet(Wallet& wallet) {
  return storage_.UpdateWallet(chain_, wallet);
}

bool NunchukImpl::ExportWallet(const std::string& wallet_id,
                               const std::string& file_path,
                               ExportFormat format) {
  return storage_.ExportWallet(chain_, wallet_id, file_path, format);
}

Wallet NunchukImpl::ImportWalletDb(const std::string& file_path) {
  std::string id = storage_.ImportWalletDb(chain_, file_path);
  return GetWallet(id);
}

Wallet NunchukImpl::ImportWalletDescriptor(const std::string& file_path) {
  std::string descs = trim_copy(storage_.LoadFile(file_path));
  AddressType address_type;
  WalletType wallet_type;
  int m;
  int n;
  std::vector<SingleSigner> signers;
  if (ParseDescriptors(descs, address_type, wallet_type, m, n, signers)) {
    boost::filesystem::path path(file_path);
    std::string name = path.stem().string();
    if (name.find("-") > 0) name = name.substr(0, name.find("-"));
    return CreateWallet(name, m, n, signers, address_type,
                        wallet_type == WalletType::ESCROW);
  }
  throw NunchukException(NunchukException::INVALID_PARAMETER,
                         "Could not parse descriptor");
}

std::vector<Device> NunchukImpl::GetDevices() { return hwi_.Enumerate(); }

MasterSigner NunchukImpl::CreateMasterSigner(
    const std::string& raw_name, const Device& device,
    std::function<bool(int)> progress) {
  std::string name = trim_copy(raw_name);
  std::string id = storage_.CreateMasterSigner(chain_, name,
                                               device.get_master_fingerprint());

  // Retrieve standard BIP32 paths when connected to a device for the first time
  int count = 0;
  auto cachePath = [&](const std::string& path) {
    storage_.CacheMasterSignerXPub(chain_, id, path,
                                   hwi_.GetXpubAtPath(device, path));
    progress(count++ * 100 / 7);
  };
  auto cacheIndex = [&](WalletType w, AddressType a) {
    int index = w == WalletType::MULTI_SIG ? 1 : 0;
    storage_.CacheMasterSignerXPub(
        chain_, id, w, a, index,
        hwi_.GetXpubAtPath(device, GetBip32Path(chain_, w, a, index)));
    progress(count++ * 100 / 7);
  };
  cachePath("m");
  cachePath(chain_ == Chain::MAIN ? MAINNET_HEALTH_CHECK_PATH
                                  : TESTNET_HEALTH_CHECK_PATH);
  cacheIndex(WalletType::MULTI_SIG, AddressType::ANY);
  cacheIndex(WalletType::SINGLE_SIG, AddressType::NATIVE_SEGWIT);
  cacheIndex(WalletType::SINGLE_SIG, AddressType::NESTED_SEGWIT);
  cacheIndex(WalletType::SINGLE_SIG, AddressType::LEGACY);
  cacheIndex(WalletType::ESCROW, AddressType::ANY);

  MasterSigner mastersigner{id, device, std::time(0)};
  mastersigner.set_name(name);
  return mastersigner;
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
  return SingleSigner(name, sanitized_xpub, public_key, derivation_path,
                      master_fingerprint, 0);
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
    mastersigners.push_back(GetMasterSigner(id));
  }
  return mastersigners;
}

MasterSigner NunchukImpl::GetMasterSigner(const std::string& mastersigner_id) {
  return storage_.GetMasterSigner(chain_, mastersigner_id);
}

bool NunchukImpl::DeleteMasterSigner(const std::string& mastersigner_id) {
  return storage_.DeleteMasterSigner(chain_, mastersigner_id);
}

bool NunchukImpl::UpdateMasterSigner(MasterSigner& mastersigner) {
  return storage_.UpdateMasterSigner(chain_, mastersigner);
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
    GetMasterSigner(id);
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

std::vector<std::string> NunchukImpl::GetAddresses(const std::string& wallet_id,
                                                   bool used, bool internal) {
  return storage_.GetAddresses(chain_, wallet_id, used, internal);
}

std::string NunchukImpl::NewAddress(const std::string& wallet_id,
                                    bool internal) {
  std::string descriptor = storage_.GetDescriptor(chain_, wallet_id, internal);
  int index = storage_.GetCurrentAddressIndex(chain_, wallet_id, internal) + 1;
  auto address = CoreUtils::getInstance().DeriveAddresses(descriptor, index);
  storage_.AddAddress(chain_, wallet_id, address, index, internal);
  synchronizer_.SubscribeAddress(wallet_id, address);
  return address;
}

std::vector<UnspentOutput> NunchukImpl::GetUnspentOutputs(
    const std::string& wallet_id) {
  return storage_.GetUnspentOutputs(chain_, wallet_id);
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

Transaction NunchukImpl::ImportTransaction(const std::string& wallet_id,
                                           const std::string& file_path) {
  std::string psbt = storage_.LoadFile(file_path);
  boost::trim(psbt);
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

Transaction NunchukImpl::SignTransaction(const std::string& wallet_id,
                                         const std::string& tx_id,
                                         const Device& device) {
  std::string psbt = storage_.GetPsbt(chain_, wallet_id, tx_id);
  DLOG_F(INFO, "NunchukImpl::SignTransaction(), psbt='%s'", psbt.c_str());
  std::string signed_psbt = hwi_.SignTx(device, psbt);
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
    synchronizer_.Broadcast(raw_tx);
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
  synchronizer_.Run(settings);
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
  auto tx = GetTransactionFromPartiallySignedTransaction(DecodePsbt(psbt), m);
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
  std::string id = mastersigner_id;
  Device device{id};
  int count = 0;
  auto cacheIndex = [&](WalletType w, AddressType a, int n) {
    int index = storage_.GetCachedIndexFromMasterSigner(chain_, id, w, a);
    if (index < 0 && w == WalletType::MULTI_SIG) index = 0;
    for (int i = index + 1; i <= index + n; i++) {
      storage_.CacheMasterSignerXPub(
          chain_, id, w, a, i,
          hwi_.GetXpubAtPath(device, GetBip32Path(chain_, w, a, i)));
      progress(count++ * 100 / TOTAL_CACHE_NUMBER);
    }
  };
  cacheIndex(WalletType::MULTI_SIG, AddressType::ANY, MULTISIG_CACHE_NUMBER);
  cacheIndex(WalletType::SINGLE_SIG, AddressType::NATIVE_SEGWIT,
             SINGLESIG_BIP84_CACHE_NUMBER);
  cacheIndex(WalletType::SINGLE_SIG, AddressType::NESTED_SEGWIT,
             SINGLESIG_BIP49_CACHE_NUMBER);
  cacheIndex(WalletType::SINGLE_SIG, AddressType::LEGACY,
             SINGLESIG_BIP48_CACHE_NUMBER);
  cacheIndex(WalletType::ESCROW, AddressType::ANY, ESCROW_CACHE_NUMBER);
}

bool NunchukImpl::ExportHealthCheckMessage(const std::string& message,
                                           const std::string& file_path) {
  return storage_.WriteFile(file_path, message);
}

std::string NunchukImpl::ImportHealthCheckSignature(
    const std::string& file_path) {
  return boost::trim_copy(storage_.LoadFile(file_path));
}

Amount NunchukImpl::EstimateFee(int conf_target) {
  return synchronizer_.EstimateFee(conf_target);
}

int NunchukImpl::GetChainTip() { return synchronizer_.GetChainTip(); }

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

void NunchukImpl::AddBalanceListener(
    std::function<void(std::string, Amount)> listener) {
  synchronizer_.AddBalanceListener(listener);
}

void NunchukImpl::AddBlockListener(
    std::function<void(int, std::string)> listener) {
  synchronizer_.AddBlockListener(listener);
}

void NunchukImpl::AddTransactionListener(
    std::function<void(std::string, TransactionStatus)> listener) {
  synchronizer_.AddTransactionListener(listener);
}

void NunchukImpl::AddDeviceListener(
    std::function<void(std::string, bool)> listener) {
  device_listener_.connect(listener);
}

void NunchukImpl::AddBlockchainConnectionListener(
    std::function<void(ConnectionStatus)> listener) {
  synchronizer_.AddBlockchainConnectionListener(listener);
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
  std::string internal_desc = storage_.GetDescriptor(chain_, wallet_id, true);
  std::string external_desc = storage_.GetDescriptor(chain_, wallet_id, false);
  std::string desc = GetDescriptorsImportString(external_desc, internal_desc);
  CoinSelector selector{desc, change_address};
  selector.set_fee_rate(CFeeRate(fee_rate));
  selector.set_discard_rate(CFeeRate(synchronizer_.RelayFee()));

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