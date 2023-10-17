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

#include "nunchukimpl.h"

#include <coinselector.h>
#include <softwaresigner.h>
#include <key_io.h>
#include <validation.h>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include "descriptor.h"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <utils/httplib.h>
#include <utils/bip32.hpp>
#include <utils/txutils.hpp>
#include <utils/addressutils.hpp>
#include <utils/json.hpp>
#include <utils/loguru.hpp>
#include <utils/quote.hpp>
#include <utils/multisigconfig.hpp>
#include <utils/bsms.hpp>
#include <utils/bcr2.hpp>
#include <utils/passport.hpp>
#include <ur.h>
#include <ur-encoder.hpp>
#include <ur-decoder.hpp>
#include <cbor-lite.hpp>
#include <util/bip32.h>
#include <regex>
#include <charconv>
#include <base58.h>

using json = nlohmann::json;
using namespace boost::algorithm;
using namespace nunchuk::bcr2;
using namespace tap_protocol;

namespace nunchuk {

static int MESSAGE_MIN_LEN = 8;
static int CACHE_SECOND = 600;  // 10 minutes
static std::regex BC_UR_REGEX("UR:BYTES/[0-9]+OF[0-9]+/(.+)");

std::map<std::string, time_t> NunchukImpl::last_scan_;

static HWITapsigner::Chain NunchukChain2TapsignerChain(Chain chain) {
  switch (chain) {
    case Chain::MAIN:
      return HWITapsigner::Chain::MAIN;
    case Chain::TESTNET:
    case Chain::SIGNET:
    case Chain::REGTEST:
      return HWITapsigner::Chain::TESTNET;
  }
  throw NunchukException(NunchukException::INVALID_CHAIN, "Invalid chain");
}

// Nunchuk implement
NunchukImpl::NunchukImpl(const AppSettings& appsettings,
                         const std::string& passphrase,
                         const std::string& account)
    : app_settings_(appsettings),
      account_(account),
      chain_(app_settings_.get_chain()),
      hwi_(app_settings_.get_hwi_path(), chain_),
      storage_(NunchukStorage::get(account_)),
      hwi_tapsigner_(MakeHWITapsigner(NunchukChain2TapsignerChain(chain_))) {
  CoreUtils::getInstance().SetChain(chain_);
  storage_->Init(app_settings_.get_storage_path(), passphrase);
  storage_->MaybeMigrate(chain_);
  std::fill(estimate_fee_cached_time_,
            estimate_fee_cached_time_ + ESTIMATE_FEE_CACHE_SIZE, 0);
  std::fill(estimate_fee_cached_value_,
            estimate_fee_cached_value_ + ESTIMATE_FEE_CACHE_SIZE, 0);
  synchronizer_ = MakeSynchronizer(app_settings_, account_);
  synchronizer_->Run();
}
Nunchuk::~Nunchuk() = default;
NunchukImpl::~NunchukImpl() {}

void NunchukImpl::SetPassphrase(const std::string& passphrase) {
  storage_->SetPassphrase(chain_, passphrase);
}

Wallet NunchukImpl::CreateWallet(const std::string& name, int m, int n,
                                 const std::vector<SingleSigner>& signers,
                                 AddressType address_type, bool is_escrow,
                                 const std::string& description,
                                 bool allow_used_signer) {
  Wallet wallet("", m, n, signers, address_type, is_escrow, 0);
  wallet.set_name(name);
  wallet.set_description(description);
  wallet.set_create_date(std::time(0));
  return CreateWallet(wallet, allow_used_signer);
}

Wallet NunchukImpl::CreateWallet(const Wallet& w, bool allow_used_signer) {
  Wallet sanitized_wallet = w;
  sanitized_wallet.set_signers(
      Utils::SanitizeSingleSigners(sanitized_wallet.get_signers()));
  sanitized_wallet.check_valid();

  Wallet wallet = storage_->CreateWallet(chain_, sanitized_wallet);
  ScanWalletAddress(wallet.get_id(), true);
  storage_listener_();
  return storage_->GetWallet(chain_, wallet.get_id(), true);
}

std::string NunchukImpl::DraftWallet(const std::string& name, int m, int n,
                                     const std::vector<SingleSigner>& signers,
                                     AddressType address_type, bool is_escrow,
                                     const std::string& description) {
  Wallet wallet("", m, n, Utils::SanitizeSingleSigners(signers), address_type,
                is_escrow, 0);
  return wallet.get_descriptor(DescriptorPath::ANY);
}

std::vector<Wallet> NunchukImpl::GetWallets(
    const std::vector<OrderBy>& orders) {
  static constexpr auto order_func = [](const Wallet& lhs, const Wallet& rhs,
                                        OrderBy order) -> int {
    switch (order) {
      case OrderBy::NAME_ASC:
        return lhs.get_name().compare(rhs.get_name());
      case OrderBy::NAME_DESC:
        return rhs.get_name().compare(lhs.get_name());
      case OrderBy::OLDEST_FIRST:
        return lhs.get_create_date() - rhs.get_create_date();
      case OrderBy::NEWEST_FIRST:
        return rhs.get_create_date() - lhs.get_create_date();
      case OrderBy::MOST_RECENTLY_USED:
        return rhs.get_last_used() - lhs.get_last_used();
      case OrderBy::LEAST_RECENTLY_USED:
        return lhs.get_last_used() - rhs.get_last_used();
        break;
    }
    throw NunchukException(NunchukException::VERSION_NOT_SUPPORTED,
                           "Version not supported");
  };

  static constexpr auto less_func =
      [](const Wallet& lhs, const Wallet& rhs,
         const std::vector<OrderBy>& orders) -> bool {
    for (auto&& order : orders) {
      int order_result = order_func(lhs, rhs, order);
      if (order_result == 0) {
        continue;
      }
      if (order_result < 0) {
        return true;
      }
      if (order_result > 0) {
        return false;
      }
    }
    return lhs.get_id() < rhs.get_id();
  };

  const auto wallet_ids = storage_->ListWallets(chain_);
  std::vector<Wallet> wallets(wallet_ids.size());

  std::transform(
      wallet_ids.begin(), wallet_ids.end(), wallets.begin(),
      [&](const std::string& wallet_id) { return GetWallet(wallet_id); });

  std::sort(wallets.begin(), wallets.end(),
            [&](const Wallet& lhs, const Wallet& rhs) {
              return less_func(lhs, rhs, orders);
            });

  return wallets;
}

Wallet NunchukImpl::GetWallet(const std::string& wallet_id) {
  return storage_->GetWallet(chain_, wallet_id);
}

bool NunchukImpl::HasWallet(const std::string& wallet_id) {
  return storage_->HasWallet(chain_, wallet_id);
}

bool NunchukImpl::DeleteWallet(const std::string& wallet_id) {
  bool rs = storage_->DeleteWallet(chain_, wallet_id);
  storage_listener_();
  return rs;
}

bool NunchukImpl::UpdateWallet(const Wallet& wallet) {
  wallet.check_valid();

  bool rs = storage_->UpdateWallet(chain_, wallet);
  ScanWalletAddress(wallet.get_id(), true);
  storage_listener_();
  return rs;
}

bool NunchukImpl::ExportWallet(const std::string& wallet_id,
                               const std::string& file_path,
                               ExportFormat format) {
  return storage_->ExportWallet(chain_, wallet_id, file_path, format);
}

Wallet NunchukImpl::ImportWalletDb(const std::string& file_path) {
  std::string id = storage_->ImportWalletDb(chain_, file_path);
  storage_listener_();
  return storage_->GetWallet(chain_, id, true);
}

Wallet NunchukImpl::ImportWalletDescriptor(const std::string& file_path,
                                           const std::string& name,
                                           const std::string& description) {
  std::string descs = trim_copy(storage_->LoadFile(file_path));
  Wallet wallet = Utils::ParseWalletDescriptor(descs);
  wallet.set_name(name);
  wallet.set_description(description);
  return CreateWallet(wallet, true);
}

Wallet NunchukImpl::ImportWalletConfigFile(const std::string& file_path,
                                           const std::string& description) {
  std::string config = storage_->LoadFile(file_path);
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
  return CreateWallet(name, m, n, signers, address_type, false, description,
                      true);
}

void NunchukImpl::ForceRefreshWallet(const std::string& wallet_id) {
  storage_->ForceRefresh(chain_, wallet_id);
  ScanWalletAddress(wallet_id, true);
}

void NunchukImpl::ScanWalletAddress(const std::string& wallet_id, bool force) {
  if (wallet_id.empty()) return;
  time_t current = std::time(0);
  if (!force && current - last_scan_[wallet_id] < 600) return;
  last_scan_[wallet_id] = current;
  scan_wallet_.push_back(std::async(std::launch::async, [this, wallet_id] {
    RunScanWalletAddress(wallet_id);
  }));
}

void NunchukImpl::RunScanWalletAddress(const std::string& wallet_id) {
  auto wallet = GetWallet(wallet_id);
  int index = -1;
  std::string address;
  if (wallet.is_escrow()) {
    auto descriptor = wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL);
    address = CoreUtils::getInstance().DeriveAddress(descriptor, index);
    synchronizer_->LookAhead(chain_, wallet_id, address, index, false);
  } else {
    // scan internal address
    index = storage_->GetCurrentAddressIndex(chain_, wallet_id, true) + 1;
    address = GetUnusedAddress(wallet, index, true);
    storage_->AddAddress(chain_, wallet_id, address, index, true);
    // scan external address
    index = storage_->GetCurrentAddressIndex(chain_, wallet_id, false) + 1;
    address = GetUnusedAddress(wallet, index, false);
  }

  // auto create an unused external address
  storage_->AddAddress(chain_, wallet_id, address, index, false);
}

std::string NunchukImpl::GetUnusedAddress(const Wallet& wallet, int& index,
                                          bool internal) {
  auto descriptor = wallet.get_descriptor(
      internal ? DescriptorPath::INTERNAL_ALL : DescriptorPath::EXTERNAL_ALL);
  int consecutive_unused = 0;
  std::vector<std::string> unused_addresses;
  std::map<std::string, int> addresses_index;
  std::string wallet_id = wallet.get_id();
  while (true) {
    auto address = CoreUtils::getInstance().DeriveAddress(descriptor, index);
    addresses_index[address] = index;
    if (synchronizer_->LookAhead(chain_, wallet_id, address, index, internal)) {
      for (auto&& a : unused_addresses) {
        storage_->AddAddress(chain_, wallet_id, a, addresses_index[a],
                             internal);
      }
      unused_addresses.clear();
      consecutive_unused = 0;
    } else {
      unused_addresses.push_back(address);
      consecutive_unused++;
    }
    index++;
    if (consecutive_unused == wallet.get_gap_limit()) {
      index = index - wallet.get_gap_limit();
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

void NunchukImpl::SendPassphraseToDevice(const Device& device,
                                         const std::string& passphrase) {
  hwi_.SendPassphrase(device, passphrase);
}

MasterSigner NunchukImpl::CreateMasterSigner(
    const std::string& raw_name, const Device& device,
    std::function<bool(int)> progress) {
  std::string name = trim_copy(raw_name);
  std::string id = storage_->CreateMasterSigner(chain_, name, device);
  const std::string deviceType = device.get_type();
  std::vector<SignerTag> tags;
  if (deviceType == "ledger") {
    tags.push_back(SignerTag::LEDGER);
  } else if (deviceType == "trezor") {
    tags.push_back(SignerTag::TREZOR);
  } else if (deviceType == "bitbox02") {
    tags.push_back(SignerTag::BITBOX);
  } else if (deviceType == "coldcard") {
    tags.push_back(SignerTag::COLDCARD);
  } else if (deviceType == "jade") {
    tags.push_back(SignerTag::JADE);
  }

  storage_->CacheMasterSignerXPub(
      chain_, id,
      [&](std::string path) { return hwi_.GetXpubAtPath(device, path); },
      progress, true);
  storage_listener_();

  MasterSigner mastersigner{id, device, std::time(0)};
  mastersigner.set_name(name);
  mastersigner.set_tags(tags);
  storage_->UpdateMasterSigner(chain_, mastersigner);
  return mastersigner;
}

MasterSigner NunchukImpl::CreateSoftwareSigner(
    const std::string& raw_name, const std::string& mnemonic,
    const std::string& passphrase, std::function<bool(int)> progress,
    bool is_primary) {
  if (!Utils::CheckMnemonic(mnemonic)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid mnemonic");
  }
  SoftwareSigner signer{mnemonic, passphrase};
  std::string name = trim_copy(raw_name);
  std::string id = to_lower_copy(signer.GetMasterFingerprint());

  if (is_primary) {
    std::string address = signer.GetAddressAtPath(LOGIN_SIGNING_PATH);
    PrimaryKey key{name, id, account_, address};
    if (!storage_->AddPrimaryKey(chain_, key)) {
      throw StorageException(StorageException::SQL_ERROR,
                             "Create primary key failed");
    }
  }

  Device device{"software", "nunchuk", id};
  storage_->CreateMasterSigner(chain_, name, device, mnemonic);
  storage_->CacheMasterSignerXPub(
      chain_, id, [&](std::string path) { return signer.GetXpubAtPath(path); },
      progress, true);
  storage_listener_();

  MasterSigner mastersigner{id, device, std::time(0), SignerType::SOFTWARE};
  mastersigner.set_name(name);
  return mastersigner;
}

bool NunchukImpl::DeletePrimaryKey() {
  return storage_->RemovePrimaryKey(chain_, account_);
}

std::string NunchukImpl::SignLoginMessage(const std::string& mastersigner_id,
                                          const std::string& message) {
  auto signer = storage_->GetSoftwareSigner(chain_, mastersigner_id);
  return signer.SignMessage(message, LOGIN_SIGNING_PATH);
}

void NunchukImpl::SendSignerPassphrase(const std::string& mastersigner_id,
                                       const std::string& passphrase) {
  storage_->SendSignerPassphrase(chain_, mastersigner_id, passphrase);
}

void NunchukImpl::ClearSignerPassphrase(const std::string& mastersigner_id) {
  storage_->ClearSignerPassphrase(chain_, mastersigner_id);
}

SingleSigner NunchukImpl::GetSignerFromMasterSigner(
    const std::string& mastersigner_id, const WalletType& wallet_type,
    const AddressType& address_type, int index) {
  try {
    return storage_->GetSignerFromMasterSigner(
        chain_, mastersigner_id, wallet_type, address_type, index);
  } catch (NunchukException& ne) {
    if (ne.code() == NunchukException::RUN_OUT_OF_CACHED_XPUB) {
      auto master = GetMasterSigner(mastersigner_id);
      if (master.get_type() == SignerType::HARDWARE) {
        Device device{mastersigner_id};
        auto path = GetBip32Path(chain_, wallet_type, address_type, index);
        auto xpub = hwi_.GetXpubAtPath(device, path);
        auto signer = SingleSigner(
            master.get_name(), xpub, "", path, mastersigner_id,
            master.get_last_health_check(), mastersigner_id, false,
            master.get_type(), master.get_tags(), master.is_visible());
        return signer;
      }
    }
    throw;
  }
}

SingleSigner NunchukImpl::CreateSigner(const std::string& raw_name,
                                       const std::string& xpub,
                                       const std::string& public_key,
                                       const std::string& derivation_path,
                                       const std::string& master_fingerprint,
                                       SignerType signer_type,
                                       std::vector<SignerTag> tags) {
  const SingleSigner signer = Utils::SanitizeSingleSigner(SingleSigner(
      raw_name, xpub, public_key, derivation_path, master_fingerprint,
      std::time(nullptr), {}, false, signer_type, tags));
  auto rs = storage_->CreateSingleSigner(
      chain_, signer.get_name(), signer.get_xpub(), signer.get_public_key(),
      signer.get_derivation_path(), signer.get_master_fingerprint(),
      signer.get_type(), signer.get_tags());
  storage_listener_();
  return rs;
}

bool NunchukImpl::HasSigner(const SingleSigner& signer) {
  return storage_->HasSigner(chain_, signer);
}

int NunchukImpl::GetCurrentIndexFromMasterSigner(
    const std::string& mastersigner_id, const WalletType& wallet_type,
    const AddressType& address_type) {
  return storage_->GetCurrentIndexFromMasterSigner(chain_, mastersigner_id,
                                                   wallet_type, address_type);
}

SingleSigner NunchukImpl::GetUnusedSignerFromMasterSigner(
    const std::string& mastersigner_id, const WalletType& wallet_type,
    const AddressType& address_type) {
  int index = GetCurrentIndexFromMasterSigner(mastersigner_id, wallet_type,
                                              address_type);
  auto mastersigner = GetMasterSigner(mastersigner_id);
  if (index < 0) {
    // Auto top up XPUBs for SOFTWARE signer
    if (mastersigner.get_type() == SignerType::SOFTWARE) {
      auto ss = storage_->GetSoftwareSigner(chain_, mastersigner_id);
      storage_->CacheMasterSignerXPub(
          chain_, mastersigner_id,
          [&](const std::string& path) { return ss.GetXpubAtPath(path); },
          [](int) { return true; }, false);
      index = GetCurrentIndexFromMasterSigner(mastersigner_id, wallet_type,
                                              address_type);
    }
  }
  if (index < 0) {
    throw NunchukException(
        NunchukException::RUN_OUT_OF_CACHED_XPUB,
        strprintf("[%s] has run out of XPUBs. Please top up.",
                  mastersigner.get_name()));
  }
  return GetSignerFromMasterSigner(mastersigner_id, wallet_type, address_type,
                                   index);
}

SingleSigner NunchukImpl::GetDefaultSignerFromMasterSigner(
    const std::string& mastersigner_id, const WalletType& wallet_type,
    const AddressType& address_type) {
  return GetSignerFromMasterSigner(mastersigner_id, wallet_type, address_type,
                                   0);
}

SingleSigner NunchukImpl::GetSigner(const std::string& xfp,
                                    const WalletType& wallet_type,
                                    const AddressType& address_type,
                                    int index) {
  auto path = GetBip32Path(chain_, wallet_type, address_type, index);
  try {
    return storage_->GetSignerFromMasterSigner(chain_, xfp, path);
  } catch (NunchukException& ne) {
    return storage_->GetRemoteSigner(chain_, xfp, path);
  }
}

int NunchukImpl::GetCurrentSignerIndex(const std::string& xfp,
                                       const WalletType& wt,
                                       const AddressType& at) {
  int cur = storage_->GetCurrentIndexFromMasterSigner(chain_, xfp, wt, at);
  auto remote = storage_->GetRemoteSigners(chain_, xfp);
  for (auto&& signer : remote) {
    int index = GetIndexFromPath(wt, at, signer.get_derivation_path());
    if (index > cur && FormalizePath(GetBip32Path(chain_, wt, at, index)) ==
                           FormalizePath(signer.get_derivation_path())) {
      cur = index;
    }
  }
  return cur;
}

SingleSigner NunchukImpl::GetSignerFromMasterSigner(
    const std::string& mastersigner_id, const std::string& path) {
  if (!Utils::IsValidDerivationPath(path)) {
    throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                           strprintf("Invalid derivation path [%s].", path));
  }
  try {
    return storage_->GetSignerFromMasterSigner(chain_, mastersigner_id, path);
  } catch (NunchukException& ne) {
    if (ne.code() == NunchukException::RUN_OUT_OF_CACHED_XPUB) {
      auto master = GetMasterSigner(mastersigner_id);
      if (master.get_type() == SignerType::HARDWARE) {
        Device device{mastersigner_id};
        auto xpub = hwi_.GetXpubAtPath(device, path);
        auto signer = SingleSigner(
            master.get_name(), xpub, "", path, mastersigner_id,
            master.get_last_health_check(), mastersigner_id, false,
            master.get_type(), master.get_tags(), master.is_visible());
        return signer;
      }
    }
    throw;
  }
}

std::vector<SingleSigner> NunchukImpl::GetSignersFromMasterSigner(
    const std::string& mastersigner_id) {
  return storage_->GetSignersFromMasterSigner(chain_, mastersigner_id);
}

int NunchukImpl::GetNumberOfSignersFromMasterSigner(
    const std::string& mastersigner_id) {
  return GetSignersFromMasterSigner(mastersigner_id).size();
}

std::vector<MasterSigner> NunchukImpl::GetMasterSigners() {
  auto mastersigner_ids = storage_->ListMasterSigners(chain_);
  std::vector<MasterSigner> mastersigners;
  for (auto&& id : mastersigner_ids) {
    if (storage_->IsMasterSigner(chain_, id)) {
      mastersigners.push_back(GetMasterSigner(id));
    }
  }
  return mastersigners;
}

MasterSigner NunchukImpl::GetMasterSigner(const std::string& mastersigner_id) {
  return storage_->GetMasterSigner(chain_, mastersigner_id);
}

bool NunchukImpl::DeleteMasterSigner(const std::string& mastersigner_id) {
  bool rs = storage_->DeleteMasterSigner(chain_, mastersigner_id);
  storage_listener_();
  return rs;
}

bool NunchukImpl::UpdateMasterSigner(const MasterSigner& mastersigner) {
  bool rs = storage_->UpdateMasterSigner(chain_, mastersigner);
  storage_listener_();
  return rs;
}

std::vector<SingleSigner> NunchukImpl::GetRemoteSigners() {
  return storage_->GetRemoteSigners(chain_);
}

bool NunchukImpl::DeleteRemoteSigner(const std::string& master_fingerprint,
                                     const std::string& derivation_path) {
  bool rs =
      storage_->DeleteRemoteSigner(chain_, master_fingerprint, derivation_path);
  storage_listener_();
  return rs;
}

bool NunchukImpl::UpdateRemoteSigner(const SingleSigner& remotesigner) {
  bool rs = storage_->UpdateRemoteSigner(chain_, remotesigner);
  storage_listener_();
  return rs;
}

std::string NunchukImpl::GetHealthCheckPath() {
  return (chain_ == Chain::MAIN
              ? GetDerivationPathView(MAINNET_HEALTH_CHECK_PATH)
              : GetDerivationPathView(TESTNET_HEALTH_CHECK_PATH));
}

HealthStatus NunchukImpl::HealthCheckMasterSigner(
    const std::string& fingerprint, std::string& message,
    std::string& signature, std::string& path) {
  message = message.empty() ? Utils::GenerateHealthCheckMessage() : message;
  if (message.size() < MESSAGE_MIN_LEN) {
    throw NunchukException(NunchukException::MESSAGE_TOO_SHORT,
                           "Message too short!");
  }

  bool existed = true;
  SignerType signerType = SignerType::HARDWARE;
  std::string deviceType = "";
  std::string id = fingerprint;
  try {
    auto signer = GetMasterSigner(id);
    signerType = signer.get_type();
    deviceType = signer.get_device().get_type();
  } catch (StorageException& se) {
    if (se.code() == StorageException::MASTERSIGNER_NOT_FOUND) {
      existed = false;
    } else {
      throw;
    }
  }
  path = chain_ == Chain::MAIN ? MAINNET_HEALTH_CHECK_PATH
                               : TESTNET_HEALTH_CHECK_PATH;
  if (signerType == SignerType::SOFTWARE) {
    auto ss = storage_->GetSoftwareSigner(chain_, id);
    signature = ss.SignMessage(message, path);
    return HealthStatus::SUCCESS;
  } else if (signerType == SignerType::FOREIGN_SOFTWARE) {
    throw NunchukException(
        NunchukException::INVALID_SIGNER_TYPE,
        strprintf("Can not healthcheck foreign software id = '%s'", id));
  } else if (signerType == SignerType::NFC) {
    throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                           strprintf("Must be healthcheck with NFC "
                                     "id = '%s'",
                                     id));
  }

  if (deviceType == "ledger") std::replace(path.begin(), path.end(), '\'', 'h');
  Device device{fingerprint};
  std::string xpub;
  try {
    xpub = hwi_.GetXpubAtPath(device, path);
  } catch (HWIException& he) {
    path = "m/84'/0'/0'/1/0";
    xpub = hwi_.GetXpubAtPath(device, "m/84'/0'/0'");
    CExtPubKey xkey = DecodeExtPubKey(xpub);
    xkey.Derive(xkey, 1);
    xkey.Derive(xkey, 0);
    xpub = EncodeExtPubKey(xkey);
  }

  if (existed && signerType == SignerType::HARDWARE &&
      deviceType != "bitbox02" && deviceType != "ledger" &&
      deviceType != "trezor") {
    std::string master_xpub = hwi_.GetXpubAtPath(device, "m");
    std::string stored_master_xpub =
        storage_->GetMasterSignerXPub(chain_, id, "m");
    if (!stored_master_xpub.empty() && master_xpub != stored_master_xpub) {
      return HealthStatus::KEY_NOT_MATCHED;
    }

    std::string stored_xpub = storage_->GetMasterSignerXPub(chain_, id, path);
    if (!stored_xpub.empty() && xpub != stored_xpub) {
      return HealthStatus::KEY_NOT_MATCHED;
    }
  }

  std::string descriptor = GetPkhDescriptor(xpub);
  std::string address = CoreUtils::getInstance().DeriveAddress(descriptor);
  signature = hwi_.SignMessage(device, message, path);

  if (CoreUtils::getInstance().VerifyMessage(address, signature, message)) {
    if (existed && signerType == SignerType::HARDWARE) {
      storage_->SetHealthCheckSuccess(chain_, id);
    }
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
                           "Message too short!");
  }

  std::string address;
  if (signer.get_public_key().empty()) {
    std::string descriptor = GetPkhDescriptor(signer.get_xpub());
    address = CoreUtils::getInstance().DeriveAddress(descriptor);
  } else {
    CPubKey pubkey(ParseHex(signer.get_public_key()));
    address = EncodeDestination(PKHash(pubkey.GetID()));
  }

  if (CoreUtils::getInstance().VerifyMessage(address, signature, message)) {
    storage_->SetHealthCheckSuccess(chain_, signer);
    return HealthStatus::SUCCESS;
  } else {
    return HealthStatus::SIGNATURE_INVALID;
  }
}

std::vector<Transaction> NunchukImpl::GetTransactionHistory(
    const std::string& wallet_id, int count, int skip) {
  auto txs = storage_->GetTransactions(chain_, wallet_id, count, skip);
  auto removed_iter =
      std::remove_if(txs.begin(), txs.end(), [](const Transaction& tx) -> bool {
        return tx.get_status() == TransactionStatus::REPLACED;
      });
  txs.erase(removed_iter, txs.end());
  return txs;
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
  return storage_->WriteFile(file_path, value.str());
}

std::vector<std::string> NunchukImpl::GetAddresses(const std::string& wallet_id,
                                                   bool used, bool internal) {
  return storage_->GetAddresses(chain_, wallet_id, used, internal);
}

std::string NunchukImpl::NewAddress(const std::string& wallet_id,
                                    bool internal) {
  auto wallet = GetWallet(wallet_id);
  std::string descriptor = wallet.get_descriptor(
      internal ? DescriptorPath::INTERNAL_ALL : DescriptorPath::EXTERNAL_ALL);
  int index =
      wallet.is_escrow()
          ? -1
          : storage_->GetCurrentAddressIndex(chain_, wallet_id, internal) + 1;
  while (true) {
    auto address = CoreUtils::getInstance().DeriveAddress(descriptor, index);
    if (!synchronizer_->LookAhead(chain_, wallet_id, address, index,
                                  internal)) {
      storage_->AddAddress(chain_, wallet_id, address, index, internal);
      return address;
    }
    index++;
  }
}

Amount NunchukImpl::GetAddressBalance(const std::string& wallet_id,
                                      const std::string& address) {
  return storage_->GetAddressBalance(chain_, wallet_id, address);
}

std::vector<UnspentOutput> NunchukImpl::GetUnspentOutputs(
    const std::string& wallet_id) {
  return storage_->GetUtxos(chain_, wallet_id);
}

std::vector<UnspentOutput> NunchukImpl::GetUnspentOutputsFromTxInputs(
    const std::string& wallet_id, const std::vector<TxInput>& txInputs) {
  auto utxos = storage_->GetUtxos(chain_, wallet_id);
  auto check = [&](const UnspentOutput& coin) {
    for (auto&& input : txInputs) {
      if (input.first == coin.get_txid() && input.second == coin.get_vout())
        return false;
    }
    return true;
  };
  utxos.erase(std::remove_if(utxos.begin(), utxos.end(), check), utxos.end());
  return utxos;
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
  return storage_->WriteFile(file_path, value.str());
}

Transaction NunchukImpl::CreateTransaction(
    const std::string& wallet_id, const std::map<std::string, Amount>& outputs,
    const std::string& memo, const std::vector<UnspentOutput>& inputs,
    Amount fee_rate, bool subtract_fee_from_amount) {
  Amount fee = 0;
  int vsize = 0;
  int change_pos = 0;
  if (fee_rate <= 0) fee_rate = EstimateFee();
  auto psbt =
      CreatePsbt(wallet_id, outputs, inputs, fee_rate, subtract_fee_from_amount,
                 true, fee, vsize, change_pos);
  auto rs = storage_->CreatePsbt(chain_, wallet_id, psbt, fee, memo, change_pos,
                                 outputs, fee_rate, subtract_fee_from_amount);
  rs.set_vsize(vsize);
  storage_listener_();
  return rs;
}

bool NunchukImpl::ExportTransaction(const std::string& wallet_id,
                                    const std::string& tx_id,
                                    const std::string& file_path) {
  std::string psbt = storage_->GetPsbt(chain_, wallet_id, tx_id);
  if (psbt.empty()) {
    throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
  }
  return storage_->WriteFile(file_path, psbt);
}

Transaction NunchukImpl::ImportPsbt(const std::string& wallet_id,
                                    const std::string& base64_psbt) {
  std::string psbt = boost::trim_copy(base64_psbt);
  std::string tx_id = GetTxIdFromPsbt(psbt);

  try {
    auto tx = storage_->GetTransaction(chain_, wallet_id, tx_id);
    if (tx.get_status() != TransactionStatus::PENDING_SIGNATURES) return tx;
    std::string existed_psbt = tx.get_psbt();
    if (existed_psbt == psbt) {
      return tx;
    }
    std::string combined_psbt =
        CoreUtils::getInstance().CombinePsbt({psbt, existed_psbt});
    storage_->UpdatePsbt(chain_, wallet_id, combined_psbt);
    storage_listener_();
    return GetTransaction(wallet_id, tx_id);
  } catch (StorageException& se) {
    if (se.code() != StorageException::TX_NOT_FOUND) throw;
    auto rs = storage_->CreatePsbt(chain_, wallet_id, psbt);
    storage_listener_();
    return rs;
  }
}

Transaction NunchukImpl::ImportTransaction(const std::string& wallet_id,
                                           const std::string& file_path) {
  std::string psbt = boost::trim_copy(storage_->LoadFile(file_path));
  if (boost::starts_with(psbt, "psbt")) {
    psbt = EncodeBase64(MakeUCharSpan(psbt));
  }
  return ImportPsbt(wallet_id, psbt);
}

Transaction NunchukImpl::SignTransaction(const std::string& wallet_id,
                                         const std::string& tx_id,
                                         const Device& device) {
  std::string psbt = storage_->GetPsbt(chain_, wallet_id, tx_id);
  if (psbt.empty()) {
    throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
  }
  DLOG_F(INFO, "NunchukImpl::SignTransaction(), psbt='%s'", psbt.c_str());
  auto mastersigner_id = device.get_master_fingerprint();
  std::string signed_psbt;
  auto mastersigner = GetMasterSigner(mastersigner_id);

  switch (mastersigner.get_type()) {
    case SignerType::FOREIGN_SOFTWARE:
      throw NunchukException(
          NunchukException::INVALID_SIGNER_TYPE,
          strprintf(
              "Can not sign with foreign software "
              "signer wallet_id = '%s' tx_id = '%s' mastersigner_id = '%s'",
              wallet_id, tx_id, mastersigner_id));
    case SignerType::SOFTWARE: {
      auto software_signer =
          storage_->GetSoftwareSigner(chain_, mastersigner_id);
      auto wallet = GetWallet(wallet_id);
      if (wallet.get_address_type() == AddressType::TAPROOT) {
        std::vector<std::string> keypaths;
        auto base = wallet.get_signers()[0].get_derivation_path();
        int internal =
            storage_->GetCurrentAddressIndex(chain_, wallet_id, true);
        for (int index = 0; index <= internal; index++) {
          keypaths.push_back(
              boost::str(boost::format{"%s/1/%d"} % base % index));
        }
        int external =
            storage_->GetCurrentAddressIndex(chain_, wallet_id, false);
        for (int index = 0; index <= external; index++) {
          keypaths.push_back(
              boost::str(boost::format{"%s/0/%d"} % base % index));
        }
        signed_psbt = software_signer.SignTaprootTx(psbt, keypaths);
      } else {
        signed_psbt = software_signer.SignTx(psbt);
      }
      storage_->ClearSignerPassphrase(chain_, mastersigner_id);
      break;
    }
    case SignerType::HARDWARE:
      signed_psbt = hwi_.SignTx(device, psbt);
      break;
    case SignerType::COLDCARD_NFC:
      signed_psbt = hwi_.SignTx(device, psbt);
      break;
    case SignerType::NFC:
      throw NunchukException(
          NunchukException::INVALID_SIGNER_TYPE,
          strprintf("Transaction must be sign with NFC "
                    "wallet_id = '%s' tx_id = '%s' mastersigner_id = '%s'",
                    wallet_id, tx_id, mastersigner_id));
    case SignerType::UNKNOWN:
      throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                             strprintf("Can not sign with unknown key type"
                                       "mastersigner_id = '%s'",
                                       mastersigner_id));
    case SignerType::AIRGAP:
      throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                             strprintf("Transaction must be sign with Airgap "
                                       "mastersigner_id = '%s'",
                                       mastersigner_id));
    case SignerType::SERVER:
      throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                             strprintf("Can not sign with server key "
                                       "mastersigner_id = '%s'",
                                       mastersigner_id));
  }

  DLOG_F(INFO, "NunchukImpl::SignTransaction(), signed_psbt='%s'",
         signed_psbt.c_str());
  storage_->UpdatePsbt(chain_, wallet_id, signed_psbt);
  storage_listener_();
  return GetTransaction(wallet_id, tx_id);
}

Transaction NunchukImpl::SignTransaction(const Wallet& wallet,
                                         const Transaction& tx,
                                         const Device& device) {
  std::string psbt = tx.get_psbt();
  if (psbt.empty()) {
    throw NunchukException(NunchukException::INVALID_PSBT, "Invalid psbt");
  }
  DLOG_F(INFO, "NunchukImpl::SignTransaction(), psbt='%s'", psbt.c_str());
  auto mastersigner_id = device.get_master_fingerprint();
  std::string signed_psbt;
  auto mastersigner = GetMasterSigner(mastersigner_id);
  switch (mastersigner.get_type()) {
    case SignerType::SOFTWARE: {
      auto software_signer =
          storage_->GetSoftwareSigner(chain_, mastersigner_id);
      // if (wallet.get_address_type() == AddressType::TAPROOT) {
      //   std::vector<std::string> keypaths;
      //   auto base = wallet.get_signers()[0].get_derivation_path();
      //   for (int index = 0; index <= 1000; index++) {
      //     keypaths.push_back(boost::str(boost::format{"%s/1/%d"} % base %
      //     index));
      //   }
      //   for (int index = 0; index <= 1000; index++) {
      //     keypaths.push_back(boost::str(boost::format{"%s/0/%d"} % base %
      //     index));
      //   }
      //   signed_psbt = software_signer.SignTaprootTx(psbt, keypaths);
      // } else {
      signed_psbt = software_signer.SignTx(psbt);
      //}
      storage_->ClearSignerPassphrase(chain_, mastersigner_id);
      break;
    }
    case SignerType::HARDWARE:
      signed_psbt = hwi_.SignTx(device, psbt);
      break;
    case SignerType::COLDCARD_NFC:
      signed_psbt = hwi_.SignTx(device, psbt);
      break;
    case SignerType::FOREIGN_SOFTWARE:
      throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                             strprintf("Can not sign with foreign software "
                                       "mastersigner_id = '%s'",
                                       mastersigner_id));
    case SignerType::NFC:
      throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                             strprintf("Transaction must be sign with NFC "
                                       "mastersigner_id = '%s'",
                                       mastersigner_id));
    case SignerType::UNKNOWN:
      throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                             strprintf("Can not sign with unknown key type"
                                       "mastersigner_id = '%s'",
                                       mastersigner_id));
    case SignerType::AIRGAP:
      throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                             strprintf("Transaction must be sign with Airgap "
                                       "mastersigner_id = '%s'",
                                       mastersigner_id));
    case SignerType::SERVER:
      throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                             strprintf("Can not sign with server key "
                                       "mastersigner_id = '%s'",
                                       mastersigner_id));
  }

  DLOG_F(INFO, "NunchukImpl::SignTransaction(), signed_psbt='%s'",
         signed_psbt.c_str());
  Transaction signed_tx = tx;
  signed_tx.set_psbt(signed_psbt);
  return signed_tx;
}

std::string NunchukImpl::SignMessage(const SingleSigner& signer,
                                     const std::string& message) {
  switch (signer.get_type()) {
    case SignerType::SOFTWARE: {
      auto ss =
          storage_->GetSoftwareSigner(chain_, signer.get_master_signer_id());
      return ss.SignMessage(message, signer.get_derivation_path());
    }
    case SignerType::HARDWARE: {
      Device device{signer.get_master_fingerprint()};
      return hwi_.SignMessage(device, message, signer.get_derivation_path());
    }
    case SignerType::UNKNOWN:
    case SignerType::AIRGAP:
    case SignerType::FOREIGN_SOFTWARE:
    case SignerType::NFC:
    case SignerType::COLDCARD_NFC:
    case SignerType::SERVER:
      break;
  }
  throw NunchukException(
      NunchukException::INVALID_SIGNER_TYPE,
      strprintf("Can not sign message mastersigner_id = '%s'",
                signer.get_master_signer_id()));
}

std::string NunchukImpl::GetSignerAddress(const SingleSigner& signer,
                                          AddressType address_type) {
  if (signer.get_public_key().empty()) {
    std::string descriptor = GetDescriptor(signer, address_type);
    return CoreUtils::getInstance().DeriveAddress(descriptor);
  } else {
    if (address_type == AddressType::LEGACY) {
      CPubKey pubkey(ParseHex(signer.get_public_key()));
      return EncodeDestination(PKHash(pubkey.GetID()));
    }
  }
  throw NunchukException(NunchukException::INVALID_ADDRESS_TYPE,
                         "Invalid address type");
}

Transaction NunchukImpl::BroadcastTransaction(const std::string& wallet_id,
                                              const std::string& tx_id) {
  std::string raw_tx = GetRawTransaction(wallet_id, tx_id);
  auto tx = DecodeRawTransaction(raw_tx);
  std::string new_txid = tx.GetHash().GetHex();
  std::string reject_msg{};

  if (GetTransactionWeight(CTransaction(tx)) > MAX_STANDARD_TX_WEIGHT) {
    reject_msg = "Tx-size";
  } else {
    try {
      synchronizer_->Broadcast(raw_tx);
    } catch (NunchukException& ne) {
      if (ne.code() != NunchukException::NETWORK_REJECTED) throw;
      reject_msg = ne.what();
    }
  }
  return UpdateTransaction(wallet_id, tx_id, new_txid, raw_tx, reject_msg);
}

Transaction NunchukImpl::UpdateTransaction(const std::string& wallet_id,
                                           const std::string& tx_id,
                                           const std::string& new_txid,
                                           const std::string& raw_tx,
                                           const std::string& reject_msg) {
  if (tx_id.empty() || storage_->GetPsbt(chain_, wallet_id, tx_id).empty()) {
    storage_->InsertTransaction(chain_, wallet_id, raw_tx, 0, 0);
  } else if (!new_txid.empty() && tx_id != new_txid) {
    // finalizepsbt will change the txid for legacy and nested-segwit
    // transactions. We need to update our PSBT record in the DB
    storage_->UpdatePsbtTxId(chain_, wallet_id, tx_id, new_txid);
  }
  if (reject_msg.empty()) {
    storage_->UpdateTransaction(chain_, wallet_id, raw_tx, 0, 0);
  } else {
    time_t t = std::time(0);
    storage_->UpdateTransaction(chain_, wallet_id, raw_tx, -2, t, reject_msg);
  }
  return GetTransaction(wallet_id, new_txid);
}

Transaction NunchukImpl::GetTransaction(const std::string& wallet_id,
                                        const std::string& tx_id) {
  return storage_->GetTransaction(chain_, wallet_id, tx_id);
}

std::string NunchukImpl::GetRawTransaction(const std::string& wallet_id,
                                           const std::string& tx_id) {
  auto [tx_value, is_hex_tx] =
      storage_->GetPsbtOrRawTx(chain_, wallet_id, tx_id);
  if (tx_value.empty()) {
    throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
  }
  return is_hex_tx ? std::move(tx_value)
                   : CoreUtils::getInstance().FinalizePsbt(tx_value);
}

bool NunchukImpl::DeleteTransaction(const std::string& wallet_id,
                                    const std::string& tx_id) {
  auto rs = storage_->DeleteTransaction(chain_, wallet_id, tx_id);
  storage_listener_();
  return rs;
}

AppSettings NunchukImpl::GetAppSettings() { return app_settings_; }

AppSettings NunchukImpl::UpdateAppSettings(const AppSettings& settings) {
  app_settings_ = settings;
  chain_ = app_settings_.get_chain();
  hwi_.SetPath(app_settings_.get_hwi_path());
  hwi_.SetChain(chain_);
  hwi_tapsigner_->SetChain(NunchukChain2TapsignerChain(chain_));
  CoreUtils::getInstance().SetChain(chain_);
  if (synchronizer_->NeedRecreate(settings)) {
    std::fill(estimate_fee_cached_time_,
              estimate_fee_cached_time_ + ESTIMATE_FEE_CACHE_SIZE, 0);
    std::fill(estimate_fee_cached_value_,
              estimate_fee_cached_value_ + ESTIMATE_FEE_CACHE_SIZE, 0);
    synchronizer_ = MakeSynchronizer(app_settings_, account_);
    synchronizer_->Run();
  }
  return settings;
}

Transaction NunchukImpl::DraftTransaction(
    const std::string& wallet_id, const std::map<std::string, Amount>& outputs,
    const std::vector<UnspentOutput>& inputs, Amount fee_rate,
    bool subtract_fee_from_amount) {
  Amount fee = 0;
  int vsize = 0;
  int change_pos = 0;
  if (fee_rate <= 0) fee_rate = EstimateFee();
  auto psbt =
      CreatePsbt(wallet_id, outputs, inputs, fee_rate, subtract_fee_from_amount,
                 false, fee, vsize, change_pos);
  Wallet wallet = GetWallet(wallet_id);
  int m = wallet.get_m();
  auto tx = GetTransactionFromPartiallySignedTransaction(
      DecodePsbt(psbt), wallet.get_signers(), m);

  Amount sub_amount{0};
  for (size_t i = 0; i < tx.get_outputs().size(); i++) {
    if (i == change_pos) continue;
    sub_amount += tx.get_outputs()[i].second;
  }
  for (auto&& output : outputs) {
    tx.add_user_output({output.first, output.second});
  }

  tx.set_m(m);
  tx.set_fee(fee);
  tx.set_change_index(change_pos);
  tx.set_receive(false);
  tx.set_sub_amount(sub_amount);
  tx.set_fee_rate(fee_rate);
  tx.set_subtract_fee_from_amount(subtract_fee_from_amount);
  tx.set_vsize(vsize);
  return tx;
}

Transaction NunchukImpl::ReplaceTransaction(const std::string& wallet_id,
                                            const std::string& tx_id,
                                            Amount new_fee_rate) {
  auto tx = storage_->GetTransaction(chain_, wallet_id, tx_id);
  if (new_fee_rate < tx.get_fee_rate()) {
    throw NunchukException(
        NunchukException::INVALID_FEE_RATE,
        strprintf("Invalid new fee rate wallet_id = '%s' tx_id = '%s'",
                  wallet_id, tx_id));
  }

  std::map<std::string, Amount> outputs;
  for (auto&& output : tx.get_user_outputs()) {
    outputs[output.first] = output.second;
  }
  auto inputs = GetUnspentOutputsFromTxInputs(wallet_id, tx.get_inputs());

  Amount fee = 0;
  int vsize = 0;
  int change_pos = 0;
  auto psbt =
      CreatePsbt(wallet_id, outputs, inputs, new_fee_rate,
                 tx.subtract_fee_from_amount(), true, fee, vsize, change_pos);
  auto rs = storage_->CreatePsbt(chain_, wallet_id, psbt, fee, tx.get_memo(),
                                 change_pos, outputs, new_fee_rate,
                                 tx.subtract_fee_from_amount(), tx.get_txid());
  rs.set_vsize(vsize);
  storage_listener_();
  return rs;
}

bool NunchukImpl::UpdateTransactionMemo(const std::string& wallet_id,
                                        const std::string& tx_id,
                                        const std::string& new_memo) {
  return storage_->UpdateTransactionMemo(chain_, wallet_id, tx_id, new_memo);
}

bool NunchukImpl::UpdateTransactionSchedule(const std::string& wallet_id,
                                            const std::string& tx_id,
                                            time_t ts) {
  return storage_->UpdateTransactionSchedule(chain_, wallet_id, tx_id, ts);
}

void NunchukImpl::CacheMasterSignerXPub(const std::string& mastersigner_id,
                                        std::function<bool(int)> progress) {
  auto mastersigner = GetMasterSigner(mastersigner_id);
  switch (mastersigner.get_type()) {
    case SignerType::FOREIGN_SOFTWARE:
      throw NunchukException(
          NunchukException::INVALID_SIGNER_TYPE,
          strprintf("Can not cache xpub with foreign software "
                    "signer mastersigner_id = '%s'",
                    mastersigner_id));
    case SignerType::SOFTWARE: {
      auto software_signer =
          storage_->GetSoftwareSigner(chain_, mastersigner_id);
      storage_->CacheMasterSignerXPub(
          chain_, mastersigner_id,
          [&](const std::string& path) {
            return software_signer.GetXpubAtPath(path);
          },
          progress, false);
      storage_listener_();
      break;
    }
    case SignerType::HARDWARE: {
      Device device{mastersigner_id};
      storage_->CacheMasterSignerXPub(
          chain_, mastersigner_id,
          [&](const std::string& path) {
            return hwi_.GetXpubAtPath(device, path);
          },
          progress, false);
      storage_listener_();
      break;
    }
    case SignerType::NFC:
    case SignerType::AIRGAP:
    case SignerType::COLDCARD_NFC:
    case SignerType::UNKNOWN:
    case SignerType::SERVER:
      throw NunchukException(
          NunchukException::INVALID_SIGNER_TYPE,
          strprintf("Can not cache xpub for this signer mastersigner_id = '%s'",
                    mastersigner_id));
  }
}

bool NunchukImpl::ExportHealthCheckMessage(const std::string& message,
                                           const std::string& file_path) {
  return storage_->WriteFile(file_path, message);
}

std::string NunchukImpl::ImportHealthCheckSignature(
    const std::string& file_path) {
  return boost::trim_copy(storage_->LoadFile(file_path));
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
    httplib::Client cli("https://api.nunchuk.io");
    auto res = cli.Get("/v1.1/fees/recommended");
    if (res) {
      json recommended = json::parse(res->body);
      estimate_fee_cached_time_[3] = current_time;
      estimate_fee_cached_time_[4] = current_time;
      estimate_fee_cached_time_[5] = current_time;
      estimate_fee_cached_value_[3] = recommended["fastestFee"];
      estimate_fee_cached_value_[4] = recommended["hourFee"];
      estimate_fee_cached_value_[5] = recommended["minimumFee"];
      return estimate_fee_cached_value_[cached_index];
    }
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
  return storage_->GetSelectedWallet(chain_);
}

bool NunchukImpl::SetSelectedWallet(const std::string& wallet_id) {
  storage_->SetSelectedWallet(chain_, wallet_id);
  auto wallet = GetWallet(wallet_id);
  wallet.set_last_used(std::time(nullptr));
  return storage_->UpdateWallet(chain_, wallet);
}

void NunchukImpl::DisplayAddressOnDevice(
    const std::string& wallet_id, const std::string& address,
    const std::string& device_fingerprint) {
  Wallet wallet = GetWallet(wallet_id);
  std::string desc = wallet.get_descriptor(
      DescriptorPath::EXTERNAL,
      wallet.is_escrow()
          ? -1
          : storage_->GetAddressIndex(chain_, wallet_id, address));
  std::string desc2 = wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL);
  if (device_fingerprint.empty()) {
    auto devices = GetDevices();
    for (auto&& device : devices) {
      for (auto&& signer : wallet.get_signers()) {
        if (signer.get_master_fingerprint() ==
            device.get_master_fingerprint()) {
          if (device.get_type() == "bitbox02") {
            hwi_.DisplayAddress(device, desc2);
          } else {
            hwi_.DisplayAddress(device, desc);
          }
        }
      }
    }
  } else {
    try {
      hwi_.DisplayAddress(Device{device_fingerprint}, desc);
    } catch (NunchukException& he) {
      hwi_.DisplayAddress(Device{device_fingerprint}, desc2);
    }
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
  auto content = storage_->GetMultisigConfig(chain_, wallet_id);
  std::vector<uint8_t> data(content.begin(), content.end());
  return nunchuk::bcr::EncodeUniformResource(data);
}

std::vector<std::string> NunchukImpl::ExportCoboTransaction(
    const std::string& wallet_id, const std::string& tx_id) {
  std::string base64_psbt = storage_->GetPsbt(chain_, wallet_id, tx_id);
  if (base64_psbt.empty()) {
    throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
  }
  bool invalid;
  auto psbt = DecodeBase64(base64_psbt.c_str(), &invalid);
  if (invalid) {
    throw NunchukException(
        NunchukException::INVALID_PSBT,
        strprintf("Invalid base64 wallet_id = '%s' tx_id = '%s'", wallet_id,
                  tx_id));
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

SingleSigner NunchukImpl::ParseKeystoneSigner(const std::string& qr_data) {
  auto decoded = ur::URDecoder::decode(qr_data);
  auto i = decoded.cbor().begin();
  auto end = decoded.cbor().end();
  CryptoAccount account{};
  decodeCryptoAccount(i, end, account);
  CryptoHDKey key = account.outputDescriptors[0];

  auto signer = SingleSigner("Keystone", key.get_xpub(), {}, key.get_path(),
                             key.get_xfp(), 0);
  signer.set_type(SignerType::AIRGAP);
  return signer;
}

std::vector<std::string> NunchukImpl::ExportKeystoneWallet(
    const std::string& wallet_id, int fragment_len) {
  auto content = storage_->GetMultisigConfig(chain_, wallet_id);
  std::vector<uint8_t> data(content.begin(), content.end());
  ur::ByteVector cbor;
  encodeBytes(cbor, data);
  auto encoder = ur::UREncoder(ur::UR("bytes", cbor), fragment_len);
  std::vector<std::string> parts;
  do {
    parts.push_back(to_upper_copy(encoder.next_part()));
  } while (encoder.seq_num() <= 2 * encoder.seq_len());
  return parts;
}

std::vector<std::string> NunchukImpl::ExportKeystoneTransaction(
    const std::string& wallet_id, const std::string& tx_id, int fragment_len) {
  std::string base64_psbt = storage_->GetPsbt(chain_, wallet_id, tx_id);
  if (base64_psbt.empty()) {
    throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
  }
  bool invalid;
  auto data = DecodeBase64(base64_psbt.c_str(), &invalid);
  if (invalid) {
    throw NunchukException(
        NunchukException::INVALID_PSBT,
        strprintf("Invalid base64 wallet_id = '%s' tx_id = '%s'", wallet_id,
                  tx_id));
  }
  CryptoPSBT psbt{data};
  ur::ByteVector cbor;
  encodeCryptoPSBT(cbor, psbt);
  auto encoder = ur::UREncoder(ur::UR("crypto-psbt", cbor), fragment_len);
  std::vector<std::string> parts;
  do {
    parts.push_back(to_upper_copy(encoder.next_part()));
  } while (encoder.seq_num() <= 2 * encoder.seq_len());
  return parts;
}

Transaction NunchukImpl::ImportKeystoneTransaction(
    const std::string& wallet_id, const std::vector<std::string>& qr_data) {
  auto decoder = ur::URDecoder();
  for (auto&& part : qr_data) {
    decoder.receive_part(part);
  }
  if (!decoder.is_complete() || !decoder.is_success()) {
    throw NunchukException(
        NunchukException::INVALID_PARAMETER,
        strprintf("Invalid BC-UR2 input wallet_id = '%s'", wallet_id));
  }
  auto decoded = decoder.result_ur();
  auto i = decoded.cbor().begin();
  auto end = decoded.cbor().end();
  CryptoPSBT psbt{};
  decodeCryptoPSBT(i, end, psbt);
  return ImportPsbt(wallet_id, EncodeBase64(MakeUCharSpan(psbt.data)));
}

Wallet NunchukImpl::ImportKeystoneWallet(
    const std::vector<std::string>& qr_data, const std::string& description) {
  auto wallet = Utils::ParseKeystoneWallet(chain_, qr_data);
  wallet.set_description(description);
  wallet.set_create_date(std::time(0));
  return CreateWallet(wallet, true);
}

std::vector<SingleSigner> NunchukImpl::ParsePassportSigners(
    const std::vector<std::string>& qr_data) {
  if (qr_data.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "QR data is empty");
  }
  std::smatch sm;
  std::vector<unsigned char> config;

  if (std::regex_match(qr_data[0], sm, BC_UR_REGEX)) {  // BC_UR format
    config = nunchuk::bcr::DecodeUniformResource(qr_data);
  } else {  // BC_UR2 format
    auto decoder = ur::URDecoder();
    for (auto&& part : qr_data) {
      decoder.receive_part(part);
    }
    if (!decoder.is_complete() || !decoder.is_success()) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid BC-UR2 input");
    }
    auto cbor = decoder.result_ur().cbor();
    auto i = cbor.begin();
    auto end = cbor.end();
    decodeBytes(i, end, config);
  }

  std::string config_str(config.begin(), config.end());
  std::vector<SingleSigner> signers;
  if (ParsePassportSignerConfig(chain_, config_str, signers)) {
    for (auto&& signer : signers) {
      signer.set_type(SignerType::AIRGAP);
    }
    return signers;
  } else {
    throw NunchukException(NunchukException::INVALID_FORMAT,
                           "Invalid data format");
  }
}

std::vector<std::string> NunchukImpl::ExportPassportWallet(
    const std::string& wallet_id, int fragment_len) {
  auto content = storage_->GetMultisigConfig(chain_, wallet_id);
  std::vector<uint8_t> data(content.begin(), content.end());
  ur::ByteVector cbor;
  encodeBytes(cbor, data);
  auto encoder = ur::UREncoder(ur::UR("bytes", cbor), fragment_len);
  std::vector<std::string> parts;
  do {
    parts.push_back(to_upper_copy(encoder.next_part()));
  } while (encoder.seq_num() <= 2 * encoder.seq_len());
  return parts;
}

std::vector<std::string> NunchukImpl::ExportPassportTransaction(
    const std::string& wallet_id, const std::string& tx_id, int fragment_len) {
  std::string base64_psbt = storage_->GetPsbt(chain_, wallet_id, tx_id);
  if (base64_psbt.empty()) {
    throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
  }
  bool invalid;
  auto data = DecodeBase64(base64_psbt.c_str(), &invalid);
  if (invalid) {
    throw NunchukException(
        NunchukException::INVALID_PSBT,
        strprintf("Invalid base64 wallet_id = '%s' tx_id = '%s'", wallet_id,
                  tx_id));
  }
  CryptoPSBT psbt{data};
  ur::ByteVector cbor;
  encodeCryptoPSBT(cbor, psbt);
  auto encoder = ur::UREncoder(ur::UR("crypto-psbt", cbor), fragment_len);
  std::vector<std::string> parts;
  do {
    parts.push_back(to_upper_copy(encoder.next_part()));
  } while (encoder.seq_num() <= 2 * encoder.seq_len());
  return parts;
}

Transaction NunchukImpl::ImportPassportTransaction(
    const std::string& wallet_id, const std::vector<std::string>& qr_data) {
  if (qr_data.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "QR data is empty");
  }
  std::smatch sm;
  std::vector<unsigned char> data;

  if (std::regex_match(qr_data[0], sm, BC_UR_REGEX)) {  // BC_UR format
    data = nunchuk::bcr::DecodeUniformResource(qr_data);
  } else {  // BC_UR2 format
    auto decoder = ur::URDecoder();
    for (auto&& part : qr_data) {
      decoder.receive_part(part);
    }
    if (!decoder.is_complete() || !decoder.is_success()) {
      throw NunchukException(
          NunchukException::INVALID_PARAMETER,
          strprintf("Invalid BC-UR2 input wallet_id = '%s'", wallet_id));
    }
    auto decoded = decoder.result_ur();
    auto i = decoded.cbor().begin();
    auto end = decoded.cbor().end();
    CryptoPSBT psbt{};
    decodeCryptoPSBT(i, end, psbt);
    data = psbt.data;
  }
  return ImportPsbt(wallet_id, EncodeBase64(MakeUCharSpan(data)));
}

std::vector<SingleSigner> NunchukImpl::ParseSeedSigners(
    const std::vector<std::string>& qr_data) {
  if (qr_data.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "QR data is empty");
  }
  auto decoder = ur::URDecoder();
  for (auto&& part : qr_data) {
    decoder.receive_part(part);
  }

  if (!decoder.is_complete() || !decoder.is_success()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid BC-UR2 input");
  }

  auto i = decoder.result_ur().cbor().begin();
  auto end = decoder.result_ur().cbor().end();
  CryptoAccount account{};
  decodeCryptoAccount(i, end, account);

  std::vector<SingleSigner> signers;

  std::ostringstream iss;
  iss << std::setfill('0') << std::setw(8) << std::hex
      << account.masterFingerprint;
  const std::string xfp = iss.str();

  for (auto&& key : account.outputDescriptors) {
    const std::string path = key.get_path();
    signers.emplace_back(SingleSigner(
        GetSignerNameFromDerivationPath(path, "SeedSigner-"), key.get_xpub(),
        {}, path, key.get_xfp(), 0, {}, false, SignerType::AIRGAP));
  }

  if (signers.empty()) {
    throw NunchukException(NunchukException::INVALID_FORMAT,
                           "Invalid data format");
  }

  return signers;
}

std::vector<SingleSigner> NunchukImpl::ParseQRSigners(
    const std::vector<std::string>& qr_data) {
  if (qr_data.empty()) {
    throw NunchukException(NunchukException::INVALID_FORMAT,
                           "Invalid data format");
  }
  const auto parse_signer_string = [&]() -> std::vector<SingleSigner> {
    return {ParseSignerString(qr_data[0])};
  };

  const auto parse_keystone_signer = [&]() -> std::vector<SingleSigner> {
    return {ParseKeystoneSigner(qr_data[0])};
  };

  auto ret =
      RunThrowOne(parse_signer_string, parse_keystone_signer,
                  std::bind(&Nunchuk::ParseSeedSigners, this, qr_data),
                  std::bind(&Nunchuk::ParsePassportSigners, this, qr_data));
  for (SingleSigner& signer : ret) {
    signer = Utils::SanitizeSingleSigner(signer);
  }
  return ret;
}

std::vector<std::string> NunchukImpl::ExportBCR2020010Wallet(
    const std::string& wallet_id, int fragment_len) {
  Wallet wallet = GetWallet(wallet_id);
  CryptoOutput co = CryptoOutput::from_wallet(wallet);
  ur::ByteVector cbor;
  encodeCryptoOutput(cbor, co);
  auto encoder = ur::UREncoder(ur::UR("crypto-output", cbor), fragment_len);
  std::vector<std::string> parts;
  do {
    parts.push_back(to_upper_copy(encoder.next_part()));
  } while (encoder.seq_num() <= 2 * encoder.seq_len());
  return parts;
}

std::string NunchukImpl::ExportBackup() { return storage_->ExportBackup(); }

bool NunchukImpl::SyncWithBackup(const std::string& data,
                                 std::function<bool(int)> progress) {
  auto rs = storage_->SyncWithBackup(data, progress);
  if (rs) {
    auto wallet_ids = storage_->ListWallets(chain_);
    for (auto&& id : wallet_ids) ScanWalletAddress(id);
  }
  return rs;
}
std::vector<SingleSigner> NunchukImpl::ParseJSONSigners(
    const std::string& json_str, SignerType signer_type) {
  std::vector<SingleSigner> signers;
  if (ParsePassportSignerConfig(chain_, json_str, signers)) {
    for (auto&& signer : signers) {
      signer.set_type(signer_type);
    }
    return signers;
  } else {
    throw NunchukException(NunchukException::INVALID_FORMAT,
                           "Invalid data format");
  }
}

std::vector<Wallet> NunchukImpl::ParseJSONWallets(const std::string& json_str) {
  static const std::array<std::tuple<std::string, std::string, AddressType>, 3>
      FILTER_WALLETS{{
          {"bip84", "m/84h - Native Segwit (Recommended)",
           AddressType::NATIVE_SEGWIT},
          {"bip49", "m/49h - Nested Segwit", AddressType::NESTED_SEGWIT},
          {"bip44", "m/44h - Legacy", AddressType::LEGACY},
      }};

  try {
    const nlohmann::json data = json::parse(json_str);
    const std::string xfp = data["xfp"];

    std::vector<Wallet> result;
    for (auto&& [bip, tmp_name, address_type] : FILTER_WALLETS) {
      auto bip_iter = data.find(bip);
      if (bip_iter == data.end()) {
        continue;
      }

      const std::string xpub = bip_iter.value()["xpub"];
      const std::string derivation_path = bip_iter.value()["deriv"];

      SingleSigner signer = Utils::SanitizeSingleSigner(SingleSigner(
          GetSignerNameFromDerivationPath(derivation_path, "COLDCARD-"), xpub,
          {}, derivation_path, xfp, std::time(nullptr), {}, false,
          SignerType::COLDCARD_NFC));

      Wallet wallet({}, 1, 1, {std::move(signer)}, address_type, false,
                    std::time(0));
      wallet.set_name(tmp_name);
      result.emplace_back(std::move(wallet));
    }
    return result;
  } catch (BaseException& e) {
    throw;
  } catch (...) {
    throw NunchukException(NunchukException::INVALID_FORMAT,
                           "Invalid data format");
  }
}

Transaction NunchukImpl::ImportRawTransaction(const std::string& wallet_id,
                                              const std::string& raw_tx,
                                              const std::string& tx_id) {
  CMutableTransaction mtx = DecodeRawTransaction(raw_tx);
  std::string new_txid = mtx.GetHash().GetHex();

  if (!tx_id.empty() && new_txid != tx_id) {
    // finalizepsbt will change the txid for legacy and nested-segwit
    // transactions. We need to update our PSBT record in the DB
    storage_->UpdatePsbtTxId(chain_, wallet_id, tx_id, new_txid);
  }

  storage_->UpdateTransaction(chain_, wallet_id, raw_tx, -1, 0);
  storage_listener_();
  return GetTransaction(wallet_id, new_txid);
}

std::string NunchukImpl::GetWalletExportData(const std::string& wallet_id,
                                             ExportFormat format) {
  return storage_->GetWalletExportData(chain_, wallet_id, format);
}

std::string NunchukImpl::GetWalletExportData(const Wallet& wallet,
                                             ExportFormat format) {
  switch (format) {
    case ExportFormat::COLDCARD:
      return ::GetMultisigConfig(wallet);
    case ExportFormat::DESCRIPTOR:
      return wallet.get_descriptor(DescriptorPath::ANY);
    case ExportFormat::BSMS:
      return GetDescriptorRecord(wallet);
    case ExportFormat::DB:
      return {};
    case ExportFormat::COBO:
      return {};
    case ExportFormat::CSV:
      return {};
  }
  return {};
}

void NunchukImpl::RescanBlockchain(int start_height, int stop_height) {
  synchronizer_->RescanBlockchain(start_height, stop_height);
}

void NunchukImpl::AddBalanceListener(
    std::function<void(std::string, Amount)> listener) {
  synchronizer_->AddBalanceListener(listener);
}

void NunchukImpl::AddBalancesListener(
    std::function<void(std::string, Amount, Amount)> listener) {
  synchronizer_->AddBalancesListener(listener);
}

void NunchukImpl::AddBlockListener(
    std::function<void(int, std::string)> listener) {
  synchronizer_->AddBlockListener(listener);
}

void NunchukImpl::AddTransactionListener(
    std::function<void(std::string, TransactionStatus, std::string)> listener) {
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

void NunchukImpl::AddStorageUpdateListener(std::function<void()> listener) {
  storage_listener_.connect(listener);
}

std::string NunchukImpl::CreatePsbt(
    const std::string& wallet_id, const std::map<std::string, Amount>& outputs,
    const std::vector<UnspentOutput>& inputs, Amount fee_rate,
    bool subtract_fee_from_amount, bool utxo_update_psbt, Amount& fee,
    int& vsize, int& change_pos) {
  Wallet wallet = GetWallet(wallet_id);
  std::vector<UnspentOutput> utxos = inputs;
  if (utxos.empty()) {
    utxos = GetUnspentOutputs(wallet_id);
    auto check = [&](const UnspentOutput& coin) {
      if (coin.is_locked()) return true;
      if (coin.get_schedule_time() > 0) return true;
      if (coin.get_status() == CoinStatus::OUTGOING_PENDING_CONFIRMATION)
        return true;
      return false;
    };
    utxos.erase(std::remove_if(utxos.begin(), utxos.end(), check), utxos.end());
  }

  std::vector<TxInput> selector_inputs;
  std::vector<TxOutput> selector_outputs;
  for (const auto& output : outputs) {
    selector_outputs.push_back(TxOutput(output.first, output.second));
  }

  std::string change_address;
  if (wallet.is_escrow()) {
    // Use the only address as change_address to pass in selector
    change_address = storage_->GetAllAddresses(chain_, wallet_id)[0];
  } else {
    auto unused = GetAddresses(wallet_id, false, true);
    change_address = unused.empty() ? NewAddress(wallet_id, true) : unused[0];
  }
  std::string error;
  CoinSelector selector{GetDescriptorsImportString(wallet), change_address};
  selector.set_fee_rate(CFeeRate(fee_rate));
  selector.set_discard_rate(CFeeRate(synchronizer_->RelayFee()));

  // For escrow use all utxos as inputs
  if (!selector.Select(utxos, wallet.is_escrow() ? utxos : inputs,
                       change_address, subtract_fee_from_amount,
                       selector_outputs, selector_inputs, fee, vsize, error,
                       change_pos)) {
    throw NunchukException(NunchukException::COIN_SELECTION_ERROR,
                           error + strprintf(" wallet_id = '%s'", wallet_id));
  }

  std::string psbt =
      CoreUtils::getInstance().CreatePsbt(selector_inputs, selector_outputs);
  if (!utxo_update_psbt) return psbt;
  return storage_->FillPsbt(chain_, wallet_id, psbt);
}

std::string NunchukImpl::SignHealthCheckMessage(const SingleSigner& signer,
                                                const std::string& message) {
  SignerType signerType = signer.get_type();
  std::string id = signer.get_master_fingerprint();

  bool isPsbt = message.size() != 64;
  if (signerType == SignerType::SOFTWARE) {
    auto ss = storage_->GetSoftwareSigner(chain_, id);
    if (isPsbt) return GetPartialSignature(ss.SignTx(message), id);
    return ss.SignMessage(message, signer.get_derivation_path());
  } else if (signerType == SignerType::HARDWARE ||
             signerType == SignerType::COLDCARD_NFC) {
    Device device{id};
    if (isPsbt) return GetPartialSignature(hwi_.SignTx(device, message), id);
    return hwi_.SignMessage(device, message, signer.get_derivation_path());
  } else if (signerType == SignerType::FOREIGN_SOFTWARE) {
    throw NunchukException(
        NunchukException::INVALID_SIGNER_TYPE,
        strprintf("Can not sign with foreign software id = '%s'", id));
  } else if (signerType == SignerType::NFC) {
    throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                           strprintf("Must be sign with NFC id = '%s'", id));
  } else if (signerType == SignerType::AIRGAP) {
    throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                           strprintf("Must be sign with Airgap id = '%s'", id));
  }
  throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                         "Invalid signer type");
}

bool NunchukImpl::UpdateCoinMemo(const std::string& wallet_id,
                                 const std::string& tx_id, int vout,
                                 const std::string& memo) {
  return storage_->UpdateCoinMemo(chain_, wallet_id, tx_id, vout, memo);
}

bool NunchukImpl::LockCoin(const std::string& wallet_id,
                           const std::string& tx_id, int vout) {
  return storage_->LockCoin(chain_, wallet_id, tx_id, vout);
}

bool NunchukImpl::UnlockCoin(const std::string& wallet_id,
                             const std::string& tx_id, int vout) {
  return storage_->UnlockCoin(chain_, wallet_id, tx_id, vout);
}

CoinTag NunchukImpl::CreateCoinTag(const std::string& wallet_id,
                                   const std::string& name,
                                   const std::string& color) {
  return storage_->CreateCoinTag(chain_, wallet_id, name, color);
}

std::vector<CoinTag> NunchukImpl::GetCoinTags(const std::string& wallet_id) {
  return storage_->GetCoinTags(chain_, wallet_id);
}

bool NunchukImpl::UpdateCoinTag(const std::string& wallet_id,
                                const CoinTag& tag) {
  return storage_->UpdateCoinTag(chain_, wallet_id, tag);
}

bool NunchukImpl::DeleteCoinTag(const std::string& wallet_id, int tag_id) {
  return storage_->DeleteCoinTag(chain_, wallet_id, tag_id);
}

bool NunchukImpl::AddToCoinTag(const std::string& wallet_id, int tag_id,
                               const std::string& tx_id, int vout) {
  return storage_->AddToCoinTag(chain_, wallet_id, tag_id, tx_id, vout);
}

bool NunchukImpl::RemoveFromCoinTag(const std::string& wallet_id, int tag_id,
                                    const std::string& tx_id, int vout) {
  return storage_->RemoveFromCoinTag(chain_, wallet_id, tag_id, tx_id, vout);
}

std::vector<UnspentOutput> NunchukImpl::GetCoinByTag(
    const std::string& wallet_id, int tag_id) {
  return storage_->GetCoinByTag(chain_, wallet_id, tag_id);
}

CoinCollection NunchukImpl::CreateCoinCollection(const std::string& wallet_id,
                                                 const std::string& name) {
  return storage_->CreateCoinCollection(chain_, wallet_id, name);
}

std::vector<CoinCollection> NunchukImpl::GetCoinCollections(
    const std::string& wallet_id) {
  return storage_->GetCoinCollections(chain_, wallet_id);
}

bool NunchukImpl::UpdateCoinCollection(const std::string& wallet_id,
                                       const CoinCollection& collection) {
  return storage_->UpdateCoinCollection(chain_, wallet_id, collection);
}

bool NunchukImpl::DeleteCoinCollection(const std::string& wallet_id,
                                       int collection_id) {
  return storage_->DeleteCoinCollection(chain_, wallet_id, collection_id);
}

bool NunchukImpl::AddToCoinCollection(const std::string& wallet_id,
                                      int collection_id,
                                      const std::string& tx_id, int vout) {
  return storage_->AddToCoinCollection(chain_, wallet_id, collection_id, tx_id,
                                       vout);
}

bool NunchukImpl::RemoveFromCoinCollection(const std::string& wallet_id,
                                           int collection_id,
                                           const std::string& tx_id, int vout) {
  return storage_->RemoveFromCoinCollection(chain_, wallet_id, collection_id,
                                            tx_id, vout);
}

std::vector<UnspentOutput> NunchukImpl::GetCoinInCollection(
    const std::string& wallet_id, int collection_id) {
  return storage_->GetCoinInCollection(chain_, wallet_id, collection_id);
}

std::string NunchukImpl::ExportCoinControlData(const std::string& wallet_id) {
  return storage_->ExportCoinControlData(chain_, wallet_id);
}

bool NunchukImpl::ImportCoinControlData(const std::string& wallet_id,
                                        const std::string& data, bool force) {
  return storage_->ImportCoinControlData(chain_, wallet_id, data, force);
}

std::string NunchukImpl::ExportBIP329(const std::string& wallet_id) {
  return storage_->ExportBIP329(chain_, wallet_id);
}

void NunchukImpl::ImportBIP329(const std::string& wallet_id,
                               const std::string& data) {
  storage_->ImportBIP329(chain_, wallet_id, data);
}

std::vector<std::vector<UnspentOutput>> NunchukImpl::GetCoinAncestry(
    const std::string& wallet_id, const std::string& tx_id, int vout) {
  return storage_->GetAncestry(chain_, wallet_id, tx_id, vout);
}

bool NunchukImpl::IsMyAddress(const std::string& wallet_id,
                              const std::string& address) {
  return storage_->IsMyAddress(chain_, wallet_id, address);
}

bool NunchukImpl::IsCPFP(const std::string& wallet_id, const Transaction& tx,
                         Amount& package_fee_rate) {
  bool rs = false;
  Amount package_fee = tx.get_fee();
  int64_t package_size = tx.get_vsize();
  std::vector<UnspentOutput> utxos = GetUnspentOutputs(wallet_id);
  for (auto&& [txid, vout] : tx.get_inputs()) {
    for (auto&& coin : utxos) {
      if (coin.get_txid() == txid && coin.get_vout() == vout) {
        if (coin.get_height() == 0) {
          rs = true;
          auto prev_tx = GetTransaction(wallet_id, txid);
          auto mtx = DecodeRawTransaction(prev_tx.get_raw());
          package_size += GetVirtualTransactionSize(CTransaction(mtx));

          Amount prev_input_amount = 0;
          for (auto&& input : prev_tx.get_inputs()) {
            auto txin_raw = synchronizer_->GetRawTx(input.first);
            auto txin = DecodeRawTransaction(txin_raw);
            prev_input_amount += txin.vout[input.second].nValue;
          }
          Amount prev_output_amount = std::accumulate(
              std::begin(prev_tx.get_outputs()),
              std::end(prev_tx.get_outputs()), Amount(0),
              [](Amount acc, const TxOutput& out) { return acc + out.second; });
          package_fee += prev_input_amount - prev_output_amount;
        }
        break;
      }
    }
  }
  package_fee_rate = std::floor(1000.0 * package_fee / package_size);
  return rs;
}

std::pair<std::string, Transaction> NunchukImpl::ImportDummyTx(
    const std::string& dummy_transaction) {
  json info = json::parse(dummy_transaction);
  std::string wallet_id = info["wallet_local_id"];
  std::string id = info["id"];
  std::string body = info["request_body"];
  std::vector<std::string> tokens{};
  if (info["signatures"] != nullptr) {
    json signatures = info["signatures"];
    for (auto&& item : signatures) {
      tokens.push_back(item["signature"]);
    }
  }
  return {id, storage_->ImportDummyTx(chain_, wallet_id, id, body, tokens)};
}

RequestTokens NunchukImpl::SaveDummyTxRequestToken(const std::string& wallet_id,
                                                   const std::string& id,
                                                   const std::string& token) {
  return storage_->SaveDummyTxRequestToken(chain_, wallet_id, id, token);
}

bool NunchukImpl::DeleteDummyTx(const std::string& wallet_id,
                                const std::string& id) {
  return storage_->DeleteDummyTx(chain_, wallet_id, id);
}

RequestTokens NunchukImpl::GetDummyTxRequestToken(const std::string& wallet_id,
                                                  const std::string& id) {
  return storage_->GetDummyTxRequestToken(chain_, wallet_id, id);
}

std::map<std::string, Transaction> NunchukImpl::GetDummyTxs(
    const std::string& wallet_id) {
  return storage_->GetDummyTxs(chain_, wallet_id);
}

Transaction NunchukImpl::GetDummyTx(const std::string& wallet_id,
                                    const std::string& id) {
  return storage_->GetDummyTx(chain_, wallet_id, id);
}

std::unique_ptr<Nunchuk> MakeNunchuk(const AppSettings& appsettings,
                                     const std::string& passphrase) {
  return std::unique_ptr<NunchukImpl>(
      new NunchukImpl(appsettings, passphrase, ""));
}

std::unique_ptr<Nunchuk> MakeNunchukForAccount(const AppSettings& appsettings,
                                               const std::string& passphrase,
                                               const std::string& account) {
  return std::unique_ptr<NunchukImpl>(
      new NunchukImpl(appsettings, passphrase, account));
}

}  // namespace nunchuk
