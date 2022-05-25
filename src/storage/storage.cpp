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

#include "storage.h"

#include <descriptor.h>
#include <utils/bip32.hpp>
#include <utils/txutils.hpp>
#include <utils/json.hpp>
#include <utils/loguru.hpp>
#include <utils/bsms.hpp>
#include <boost/filesystem/string_file.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <mutex>
#include <set>
#include <sstream>
#include <cstring>
#include <algorithm>

#include <univalue.h>
#include <rpc/util.h>
#include <policy/policy.h>
#include <crypto/sha256.h>

#ifdef _WIN32
#include <shlobj.h>
#endif

using json = nlohmann::json;
namespace fs = boost::filesystem;
namespace ba = boost::algorithm;

namespace nunchuk {

fs::path NunchukStorage::GetDefaultDataDir() const {
  // Windows: C:\Users\Username\AppData\Roaming\Nunchuk
  // Mac: ~/Library/Application Support/Nunchuk
  // Unix: ~/.nunchuk
#ifdef _WIN32
  // Windows
  WCHAR pszPath[MAX_PATH] = L"";
  if (SHGetSpecialFolderPathW(nullptr, pszPath, CSIDL_APPDATA, true)) {
    return fs::path(pszPath) / "Nunchuk";
  }
  return fs::path("Nunchuk");
#else
  fs::path pathRet;
  char* pszHome = getenv("HOME");
  if (pszHome == nullptr || std::strlen(pszHome) == 0)
    pathRet = fs::path("/");
  else
    pathRet = fs::path(pszHome);
#ifdef __APPLE__
  // Mac
  return pathRet / "Library/Application Support/Nunchuk";
#else
  // Unix
  return pathRet / ".nunchuk";
#endif
#endif
}

bool NunchukStorage::WriteFile(const std::string& file_path,
                               const std::string& value) {
  fs::save_string_file(fs::system_complete(file_path), value);
  return true;
}

std::string NunchukStorage::LoadFile(const std::string& file_path) {
  std::string value;
  fs::load_string_file(fs::system_complete(file_path), value);
  return value;
}

bool NunchukStorage::ExportWallet(Chain chain, const std::string& wallet_id,
                                  const std::string& file_path,
                                  ExportFormat format) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto wallet_db = GetWalletDb(chain, wallet_id);
  switch (format) {
    case ExportFormat::COLDCARD:
      return WriteFile(file_path, wallet_db.GetMultisigConfig());
    case ExportFormat::DESCRIPTOR: {
      return WriteFile(
          file_path, wallet_db.GetWallet().get_descriptor(DescriptorPath::ANY));
    }
    case ExportFormat::BSMS: {
      return WriteFile(file_path, GetDescriptorRecord(wallet_db.GetWallet()));
    }
    case ExportFormat::DB:
      if (passphrase_.empty()) {
        fs::copy_file(GetWalletDir(chain, wallet_id), file_path);
      } else {
        wallet_db.DecryptDb(file_path);
      }
      return true;
    default:
      return false;
  }
}

std::string NunchukStorage::ImportWalletDb(Chain chain,
                                           const std::string& file_path) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto wallet_db = NunchukWalletDb{chain, "", file_path, ""};
  std::string id = wallet_db.GetId();
  auto wallet_file = GetWalletDir(chain, id);
  if (fs::exists(wallet_file)) {
    throw StorageException(StorageException::WALLET_EXISTED,
                           strprintf("Wallet existed! id = '%s'", id));
  }
  wallet_db.EncryptDb(wallet_file.string(), passphrase_);
  return id;
}

NunchukStorage::NunchukStorage(const std::string& datadir,
                               const std::string& passphrase,
                               const std::string& account)
    : passphrase_(passphrase), account_(account) {
  if (!datadir.empty()) {
    datadir_ = fs::system_complete(datadir);
    if (!fs::is_directory(datadir_)) {
      throw StorageException(StorageException::INVALID_DATADIR,
                             "Datadir is not directory!");
    }
  } else {
    datadir_ = GetDefaultDataDir();
  }

  basedatadir_ = datadir_;
  if (!account_.empty()) {
    std::string aid = ba::to_lower_copy(account_);
    CSHA256 hasher;
    std::vector<unsigned char> stream(aid.begin(), aid.end());
    hasher.Write((unsigned char*)&(*stream.begin()),
                 stream.end() - stream.begin());
    uint256 hash;
    hasher.Finalize(hash.begin());
    datadir_ = datadir_ / hash.GetHex();
  }
  if (fs::create_directories(datadir_ / "testnet")) {
    fs::create_directories(datadir_ / "testnet" / "wallets");
    fs::create_directories(datadir_ / "testnet" / "signers");
  }
  if (fs::create_directories(datadir_ / "mainnet")) {
    fs::create_directories(datadir_ / "mainnet" / "wallets");
    fs::create_directories(datadir_ / "mainnet" / "signers");
  }
  if (fs::create_directories(datadir_ / "signet")) {
    fs::create_directories(datadir_ / "signet" / "wallets");
    fs::create_directories(datadir_ / "signet" / "signers");
  }
  fs::create_directories(datadir_ / "tmp");
}

void NunchukStorage::SetPassphrase(const std::string& value) {
  if (value == passphrase_) {
    throw NunchukException(NunchukException::PASSPHRASE_ALREADY_USED,
                           "Passphrase used");
  }
  SetPassphrase(Chain::MAIN, value);
  SetPassphrase(Chain::TESTNET, value);
  SetPassphrase(Chain::SIGNET, value);
  passphrase_ = value;
}

void NunchukStorage::SetPassphrase(Chain chain, const std::string& value) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto wallets = ListWallets0(chain);
  auto signers = ListMasterSigners0(chain);
  if (passphrase_.empty()) {
    for (auto&& wallet_id : wallets) {
      auto old_file = GetWalletDir(chain, wallet_id);
      auto new_file = datadir_ / "tmp" / wallet_id;
      GetWalletDb(chain, wallet_id).EncryptDb(new_file.string(), value);
      fs::copy_file(new_file, old_file, fs::copy_option::overwrite_if_exists);
      fs::remove(new_file);
    }
    for (auto&& signer_id : signers) {
      auto old_file = GetSignerDir(chain, signer_id);
      auto new_file = datadir_ / "tmp" / signer_id;
      GetSignerDb(chain, signer_id).EncryptDb(new_file.string(), value);
      fs::copy_file(new_file, old_file, fs::copy_option::overwrite_if_exists);
      fs::remove(new_file);
    }
    {
      auto old_file = GetRoomDir(chain);
      auto new_file = datadir_ / "tmp" / "matrix";
      GetRoomDb(chain).EncryptDb(new_file.string(), value);
      fs::copy_file(new_file, old_file, fs::copy_option::overwrite_if_exists);
      fs::remove(new_file);
    }
  } else if (value.empty()) {
    for (auto&& wallet_id : wallets) {
      auto old_file = GetWalletDir(chain, wallet_id);
      auto new_file = datadir_ / "tmp" / wallet_id;
      GetWalletDb(chain, wallet_id).DecryptDb(new_file.string());
      fs::copy_file(new_file, old_file, fs::copy_option::overwrite_if_exists);
      fs::remove(new_file);
    }
    for (auto&& signer_id : signers) {
      auto old_file = GetSignerDir(chain, signer_id);
      auto new_file = datadir_ / "tmp" / signer_id;
      GetSignerDb(chain, signer_id).DecryptDb(new_file.string());
      fs::copy_file(new_file, old_file, fs::copy_option::overwrite_if_exists);
      fs::remove(new_file);
    }
    {
      auto old_file = GetRoomDir(chain);
      auto new_file = datadir_ / "tmp" / "matrix";
      GetRoomDb(chain).DecryptDb(new_file.string());
      fs::copy_file(new_file, old_file, fs::copy_option::overwrite_if_exists);
      fs::remove(new_file);
    }
  } else {
    for (auto&& wallet_id : wallets) {
      GetWalletDb(chain, wallet_id).ReKey(value);
    }
    for (auto&& signer_id : signers) {
      GetSignerDb(chain, signer_id).ReKey(value);
    }
    GetRoomDb(chain).ReKey(value);
  }
}

std::string NunchukStorage::ChainStr(Chain chain) const {
  switch (chain) {
    case Chain::MAIN:
      return "mainnet";
    case Chain::TESTNET:
      return "testnet";
    case Chain::REGTEST:
      return "regtest";
    case Chain::SIGNET:
      return "signet";
  }
}

fs::path NunchukStorage::GetWalletDir(Chain chain,
                                      const std::string& id) const {
  if (id.empty()) {
    throw StorageException(StorageException::WALLET_NOT_FOUND,
                           "Wallet id can not empty!");
  }
  return datadir_ / ChainStr(chain) / "wallets" / id;
}

fs::path NunchukStorage::GetSignerDir(Chain chain,
                                      const std::string& id) const {
  if (id.empty()) {
    throw StorageException(StorageException::SIGNER_NOT_FOUND,
                           "Signer id can not empty!");
  }
  return datadir_ / ChainStr(chain) / "signers" / ba::to_lower_copy(id);
}

fs::path NunchukStorage::GetAppStateDir(Chain chain) const {
  return datadir_ / ChainStr(chain) / "state";
}

fs::path NunchukStorage::GetPrimaryDir(Chain chain) const {
  return basedatadir_ / ChainStr(chain) / "primary";
}

fs::path NunchukStorage::GetRoomDir(Chain chain) const {
  return datadir_ / ChainStr(chain) / "room";
}

NunchukWalletDb NunchukStorage::GetWalletDb(Chain chain,
                                            const std::string& id) {
  fs::path db_file = GetWalletDir(chain, id);
  if (!fs::exists(db_file)) {
    throw StorageException(StorageException::WALLET_NOT_FOUND,
                           strprintf("Wallet not exists! id = '%s'", id));
  }
  return NunchukWalletDb{chain, id, db_file.string(), passphrase_};
}

NunchukSignerDb NunchukStorage::GetSignerDb(Chain chain,
                                            const std::string& id) {
  fs::path db_file = GetSignerDir(chain, id);
  if (!fs::exists(db_file)) {
    throw StorageException(StorageException::MASTERSIGNER_NOT_FOUND,
                           strprintf("Signer not exists! id = '%s'", id));
  }
  return NunchukSignerDb{chain, id, db_file.string(), passphrase_};
}

NunchukAppStateDb NunchukStorage::GetAppStateDb(Chain chain) {
  fs::path db_file = GetAppStateDir(chain);
  bool is_new = !fs::exists(db_file);
  auto db = NunchukAppStateDb{chain, "", db_file.string(), ""};
  if (is_new) db.Init();
  return db;
}

NunchukPrimaryDb NunchukStorage::GetPrimaryDb(Chain chain) {
  fs::path db_file = GetPrimaryDir(chain);
  bool is_new = !fs::exists(db_file);
  auto db = NunchukPrimaryDb{chain, "", db_file.string(), ""};
  if (is_new) db.Init();
  return db;
}

NunchukRoomDb NunchukStorage::GetRoomDb(Chain chain) {
  fs::path db_file = GetRoomDir(chain);
  bool is_new = !fs::exists(db_file);
  auto db = NunchukRoomDb{chain, "", db_file.string(), passphrase_};
  if (is_new) db.Init();
  return db;
}

Wallet NunchukStorage::CreateWallet(Chain chain, const std::string& name, int m,
                                    int n,
                                    const std::vector<SingleSigner>& signers,
                                    AddressType address_type, bool is_escrow,
                                    const std::string& description,
                                    bool allow_used_signer) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return CreateWallet0(chain, name, m, n, signers, address_type, is_escrow,
                       description, allow_used_signer, std::time(0));
}

Wallet NunchukStorage::CreateWallet0(Chain chain, const std::string& name,
                                     int m, int n,
                                     const std::vector<SingleSigner>& signers,
                                     AddressType address_type, bool is_escrow,
                                     const std::string& description,
                                     bool allow_used_signer,
                                     time_t create_date) {
  if (m > n) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid parameter: m > n");
  }
  if (n != signers.size()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid parameter: n and signers are not match");
  }
  WalletType wallet_type =
      n == 1 ? WalletType::SINGLE_SIG
             : (is_escrow ? WalletType::ESCROW : WalletType::MULTI_SIG);
  for (auto&& signer : signers) {
    auto master_id = signer.get_master_fingerprint();
    NunchukSignerDb signer_db{
        chain, master_id, GetSignerDir(chain, master_id).string(), passphrase_};
    if (signer_db.IsMaster() && !signer.get_xpub().empty()) {
      int index = GetIndexFromPath(signer.get_derivation_path());
      if (FormalizePath(
              GetBip32Path(chain, wallet_type, address_type, index)) !=
          FormalizePath(signer.get_derivation_path())) {
        throw NunchukException(
            NunchukException::INVALID_BIP32_PATH,
            strprintf("Invalid bip32 path! master_id = '%s'", master_id));
      }
      signer_db.AddXPub(wallet_type, address_type, index, signer.get_xpub());
      if (!signer_db.UseIndex(wallet_type, address_type, index) &&
          !allow_used_signer) {
        throw StorageException(
            StorageException::SIGNER_USED,
            strprintf("Signer used! master_id = '%s'", master_id));
      }
    } else {
      try {
        signer_db.GetRemoteSigner(signer.get_derivation_path());
        signer_db.UseRemote(signer.get_derivation_path());
      } catch (StorageException& se) {
        if (se.code() == StorageException::SIGNER_NOT_FOUND) {
          signer_db.AddRemote("import", signer.get_xpub(),
                              signer.get_public_key(),
                              signer.get_derivation_path(), true);
        } else {
          throw;
        }
      }
    }
  }
  std::string external_desc = GetDescriptorForSigners(
      signers, m, DescriptorPath::EXTERNAL_ALL, address_type, wallet_type);
  std::string id = GetDescriptorChecksum(external_desc);
  fs::path wallet_file = GetWalletDir(chain, id);
  if (fs::exists(wallet_file)) {
    throw StorageException(StorageException::WALLET_EXISTED,
                           strprintf("Wallet existed! id = '%s'", id));
  }
  NunchukWalletDb wallet_db{chain, id, wallet_file.string(), passphrase_};
  wallet_db.InitWallet(name, m, n, signers, address_type, is_escrow,
                       create_date, description);
  Wallet wallet(id, m, n, signers, address_type, is_escrow, create_date);
  wallet.set_name(name);
  wallet.set_description(description);
  wallet.set_balance(0);
  GetAppStateDb(chain).RemoveDeletedWallet(id);
  return wallet;
}

std::string NunchukStorage::CreateMasterSigner(Chain chain,
                                               const std::string& name,
                                               const Device& device,
                                               const std::string& mnemonic) {
  std::unique_lock<std::shared_mutex> lock(access_);
  std::string id = ba::to_lower_copy(device.get_master_fingerprint());
  NunchukSignerDb signer_db{chain, id, GetSignerDir(chain, id).string(),
                            passphrase_};
  signer_db.InitSigner(name, device, mnemonic);
  GetAppStateDb(chain).RemoveDeletedSigner(id);
  return id;
}

SingleSigner NunchukStorage::CreateSingleSigner(
    Chain chain, const std::string& name, const std::string& xpub,
    const std::string& public_key, const std::string& derivation_path,
    const std::string& master_fingerprint) {
  std::unique_lock<std::shared_mutex> lock(access_);
  std::string id = master_fingerprint;
  NunchukSignerDb signer_db{chain, id, GetSignerDir(chain, id).string(),
                            passphrase_};
  if (signer_db.IsMaster()) {
    throw StorageException(StorageException::SIGNER_EXISTS,
                           strprintf("Signer exists id = '%s'", id));
  }
  if (!signer_db.AddRemote(name, xpub, public_key, derivation_path)) {
    throw StorageException(StorageException::SIGNER_EXISTS,
                           strprintf("Signer exists id = '%s'", id));
  }
  auto signer = SingleSigner(name, xpub, public_key, derivation_path,
                             master_fingerprint, 0);
  signer.set_type(SignerType::AIRGAP);
  GetAppStateDb(chain).RemoveDeletedSigner(id);
  return signer;
}

SingleSigner NunchukStorage::GetSignerFromMasterSigner(
    Chain chain, const std::string& mastersigner_id,
    const WalletType& wallet_type, const AddressType& address_type, int index) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto signer_db = GetSignerDb(chain, mastersigner_id);
  std::string path = GetBip32Path(chain, wallet_type, address_type, index);
  auto signer = SingleSigner(
      signer_db.GetName(), signer_db.GetXpub(wallet_type, address_type, index),
      "", path, signer_db.GetFingerprint(), signer_db.GetLastHealthCheck(),
      mastersigner_id);
  signer.set_type(signer_db.GetSignerType());
  return signer;
}

std::vector<SingleSigner> NunchukStorage::GetSignersFromMasterSigner(
    Chain chain, const std::string& mastersigner_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id).GetSingleSigners();
}

void NunchukStorage::CacheMasterSignerXPub(
    Chain chain, const std::string& id,
    std::function<std::string(std::string)> getxpub,
    std::function<bool(int)> progress, bool first) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto signer_db = GetSignerDb(chain, id);

  int count = 0;
  auto total = first ? 8 : TOTAL_CACHE_NUMBER;
  progress(count++ * 100 / total);

  // Retrieve standard BIP32 paths when connected to a device for the first time
  if (first) {
    auto cachePath = [&](const std::string& path) {
      signer_db.AddXPub(path, getxpub(path), "custom");
      progress(count++ * 100 / total);
    };
    cachePath("m");
    cachePath(chain == Chain::MAIN ? MAINNET_HEALTH_CHECK_PATH
                                   : TESTNET_HEALTH_CHECK_PATH);
  }

  auto cacheIndex = [&](WalletType w, AddressType a, int n) {
    int index = signer_db.GetCachedIndex(w, a);
    if (index < 0 && w == WalletType::MULTI_SIG) index = 0;
    for (int i = index + 1; i <= index + n; i++) {
      signer_db.AddXPub(w, a, i, getxpub(GetBip32Path(chain, w, a, i)));
      progress(count++ * 100 / total);
    }
  };
  cacheIndex(WalletType::MULTI_SIG, AddressType::ANY,
             first ? 1 : MULTISIG_CACHE_NUMBER);
  cacheIndex(WalletType::SINGLE_SIG, AddressType::NATIVE_SEGWIT,
             first ? 1 : SINGLESIG_BIP84_CACHE_NUMBER);
  cacheIndex(WalletType::SINGLE_SIG, AddressType::TAPROOT,
             first ? 1 : SINGLESIG_BIP86_CACHE_NUMBER);
  cacheIndex(WalletType::SINGLE_SIG, AddressType::NESTED_SEGWIT,
             first ? 1 : SINGLESIG_BIP49_CACHE_NUMBER);
  cacheIndex(WalletType::SINGLE_SIG, AddressType::LEGACY,
             first ? 1 : SINGLESIG_BIP48_CACHE_NUMBER);
  cacheIndex(WalletType::ESCROW, AddressType::ANY,
             first ? 1 : ESCROW_CACHE_NUMBER);
}

int NunchukStorage::GetCurrentIndexFromMasterSigner(
    Chain chain, const std::string& mastersigner_id,
    const WalletType& wallet_type, const AddressType& address_type) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id)
      .GetUnusedIndex(wallet_type, address_type);
}

int NunchukStorage::GetCachedIndexFromMasterSigner(
    Chain chain, const std::string& mastersigner_id,
    const WalletType& wallet_type, const AddressType& address_type) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id)
      .GetCachedIndex(wallet_type, address_type);
}

std::string NunchukStorage::GetMasterSignerXPub(
    Chain chain, const std::string& mastersigner_id, const std::string& path) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id).GetXpub(path);
}

std::vector<std::string> NunchukStorage::ListWallets(Chain chain) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return ListWallets0(chain);
}

std::vector<std::string> NunchukStorage::ListWallets0(Chain chain) {
  fs::path directory = (datadir_ / ChainStr(chain) / "wallets");
  std::vector<std::string> ids;
  for (auto&& f : fs::directory_iterator(directory)) {
    auto id = f.path().filename().string();
    if (id.size() != 8) continue;
    ids.push_back(id);
  }
  return ids;
}

std::vector<std::string> NunchukStorage::ListMasterSigners(Chain chain) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return ListMasterSigners0(chain);
}

std::vector<std::string> NunchukStorage::ListMasterSigners0(Chain chain) {
  fs::path directory = (datadir_ / ChainStr(chain) / "signers");
  std::vector<std::string> ids;
  for (auto&& f : fs::directory_iterator(directory)) {
    auto id = f.path().filename().string();
    if (id.size() != 8) continue;
    ids.push_back(id);
  }
  return ids;
}

Wallet NunchukStorage::GetWallet(Chain chain, const std::string& id,
                                 bool create_signers_if_not_exist) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto wallet_db = GetWalletDb(chain, id);
  Wallet wallet = wallet_db.GetWallet();
  std::vector<SingleSigner> signers;

  for (auto&& signer : wallet.get_signers()) {
    std::string name = signer.get_name();
    std::string master_id = signer.get_master_fingerprint();
    time_t last_health_check = signer.get_last_health_check();
    NunchukSignerDb signer_db{
        chain, master_id, GetSignerDir(chain, master_id).string(), passphrase_};
    SignerType signer_type = signer_db.GetSignerType();
    if (signer_db.IsMaster()) {
      name = signer_db.GetName();
      last_health_check = signer_db.GetLastHealthCheck();
    } else {
      // master_id is used by the caller to check if the signer is master or
      // remote
      master_id = "";
      signer_type = SignerType::AIRGAP;
      try {
        auto remote = signer_db.GetRemoteSigner(signer.get_derivation_path());
        name = remote.get_name();
        last_health_check = remote.get_last_health_check();
      } catch (StorageException& se) {
        if (se.code() == StorageException::SIGNER_NOT_FOUND &&
            create_signers_if_not_exist) {
          signer_db.AddRemote(signer.get_name(), signer.get_xpub(),
                              signer.get_public_key(),
                              signer.get_derivation_path(), true);
        } else {
          throw;
        }
      }
    }
    SingleSigner true_signer(name, signer.get_xpub(), signer.get_public_key(),
                             signer.get_derivation_path(),
                             signer.get_master_fingerprint(), last_health_check,
                             master_id);
    true_signer.set_type(signer_type);
    signers.push_back(true_signer);
  }
  Wallet true_wallet(id, wallet.get_m(), wallet.get_n(), signers,
                     wallet.get_address_type(), wallet.is_escrow(),
                     wallet.get_create_date());
  true_wallet.set_name(wallet.get_name());
  true_wallet.set_balance(wallet.get_balance());
  return true_wallet;
}

MasterSigner NunchukStorage::GetMasterSigner(Chain chain,
                                             const std::string& id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto mid = ba::to_lower_copy(id);
  auto signer_db = GetSignerDb(chain, mid);
  Device device{signer_db.GetDeviceType(), signer_db.GetDeviceModel(),
                signer_db.GetFingerprint()};
  SignerType signer_type = signer_db.GetSignerType();
  if (signer_type == SignerType::SOFTWARE) {
    if (signer_passphrase_.count(mid) == 0 && signer_db.IsSoftware("")) {
      signer_passphrase_[mid] = "";
    }
    device.set_needs_pass_phrase_sent(signer_passphrase_.count(id) == 0);
  }
  MasterSigner signer{id, device, signer_db.GetLastHealthCheck(), signer_type};
  signer.set_name(signer_db.GetName());
  return signer;
}

SoftwareSigner NunchukStorage::GetSoftwareSigner(Chain chain,
                                                 const std::string& id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto mid = ba::to_lower_copy(id);
  auto signer_db = GetSignerDb(chain, mid);
  if (signer_passphrase_.count(mid) == 0) {
    auto software_signer = signer_db.GetSoftwareSigner("");
    signer_passphrase_[mid] = "";
    return software_signer;
  }
  return signer_db.GetSoftwareSigner(signer_passphrase_.at(mid));
}

bool NunchukStorage::UpdateWallet(Chain chain, const Wallet& wallet) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto wallet_db = GetWalletDb(chain, wallet.get_id());
  return wallet_db.SetName(wallet.get_name()) &&
         wallet_db.SetDescription(wallet.get_description());
}

bool NunchukStorage::UpdateMasterSigner(Chain chain,
                                        const MasterSigner& signer) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetSignerDb(chain, signer.get_id()).SetName(signer.get_name());
}

bool NunchukStorage::DeleteWallet(Chain chain, const std::string& id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  GetWalletDb(chain, id).DeleteWallet();
  GetAppStateDb(chain).AddDeletedWallet(id);
  return fs::remove(GetWalletDir(chain, id));
}

bool NunchukStorage::DeleteMasterSigner(Chain chain, const std::string& id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  GetSignerDb(chain, id).DeleteSigner();
  GetAppStateDb(chain).AddDeletedSigner(id);
  return fs::remove(GetSignerDir(chain, id));
}

bool NunchukStorage::SetHealthCheckSuccess(Chain chain,
                                           const std::string& mastersigner_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id).SetLastHealthCheck(std::time(0));
}

bool NunchukStorage::SetHealthCheckSuccess(Chain chain,
                                           const SingleSigner& signer) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetSignerDb(chain, signer.get_master_fingerprint())
      .SetRemoteLastHealthCheck(signer.get_derivation_path(), std::time(0));
}

bool NunchukStorage::AddAddress(Chain chain, const std::string& wallet_id,
                                const std::string& address, int index,
                                bool internal) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).AddAddress(address, index, internal);
}

std::vector<std::string> NunchukStorage::GetAddresses(
    Chain chain, const std::string& wallet_id, bool used, bool internal) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetAddresses(used, internal);
}

std::vector<std::string> NunchukStorage::GetAllAddresses(
    Chain chain, const std::string& wallet_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetAllAddresses();
}

int NunchukStorage::GetCurrentAddressIndex(Chain chain,
                                           const std::string& wallet_id,
                                           bool internal) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetCurrentAddressIndex(internal);
}

Transaction NunchukStorage::InsertTransaction(
    Chain chain, const std::string& wallet_id, const std::string& raw_tx,
    int height, time_t blocktime, Amount fee, const std::string& memo,
    int change_pos) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto db = GetWalletDb(chain, wallet_id);
  auto tx =
      db.InsertTransaction(raw_tx, height, blocktime, fee, memo, change_pos);
  db.FillSendReceiveData(tx);
  return tx;
}

std::vector<Transaction> NunchukStorage::GetTransactions(
    Chain chain, const std::string& wallet_id, int count, int skip) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto db = GetWalletDb(chain, wallet_id);
  auto vtx = db.GetTransactions(count, skip);

  // remove invalid, out-of-date Send transactions
  auto utxos = db.GetUnspentOutputs(false);
  auto is_valid_input = [utxos](const TxInput& input) {
    for (auto&& utxo : utxos) {
      if (input.first == utxo.get_txid() && input.second == utxo.get_vout())
        return true;
    }
    return false;
  };
  auto end = std::remove_if(vtx.begin(), vtx.end(), [&](const Transaction& tx) {
    if (tx.get_height() == -1) {
      for (auto&& input : tx.get_inputs()) {
        if (!is_valid_input(input)) {
          return true;
        }
      }
    }
    return false;
  });
  vtx.erase(end, vtx.end());

  for (auto&& tx : vtx) {
    db.FillSendReceiveData(tx);
  }
  return vtx;
}

std::vector<UnspentOutput> NunchukStorage::GetUnspentOutputs(
    Chain chain, const std::string& wallet_id, bool remove_locked) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetUnspentOutputs(remove_locked);
}

Transaction NunchukStorage::GetTransaction(Chain chain,
                                           const std::string& wallet_id,
                                           const std::string& tx_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto db = GetWalletDb(chain, wallet_id);
  auto tx = db.GetTransaction(tx_id);
  db.FillSendReceiveData(tx);
  return tx;
}

bool NunchukStorage::UpdateTransaction(Chain chain,
                                       const std::string& wallet_id,
                                       const std::string& raw_tx, int height,
                                       time_t blocktime,
                                       const std::string& reject_msg) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id)
      .UpdateTransaction(raw_tx, height, blocktime, reject_msg);
}

bool NunchukStorage::UpdateTransactionMemo(Chain chain,
                                           const std::string& wallet_id,
                                           const std::string& tx_id,
                                           const std::string& memo) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).UpdateTransactionMemo(tx_id, memo);
}

bool NunchukStorage::DeleteTransaction(Chain chain,
                                       const std::string& wallet_id,
                                       const std::string& tx_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  GetAppStateDb(chain).AddDeletedTransaction(tx_id);
  return GetWalletDb(chain, wallet_id).DeleteTransaction(tx_id);
}

Transaction NunchukStorage::CreatePsbt(
    Chain chain, const std::string& wallet_id, const std::string& psbt,
    Amount fee, const std::string& memo, int change_pos,
    const std::map<std::string, Amount>& outputs, Amount fee_rate,
    bool subtract_fee_from_amount, const std::string& replace_tx) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto db = GetWalletDb(chain, wallet_id);
  auto tx = db.CreatePsbt(psbt, fee, memo, change_pos, outputs, fee_rate,
                          subtract_fee_from_amount, replace_tx);
  db.FillSendReceiveData(tx);
  GetAppStateDb(chain).RemoveDeletedTransaction(tx.get_txid());
  return tx;
}

bool NunchukStorage::UpdatePsbt(Chain chain, const std::string& wallet_id,
                                const std::string& psbt) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).UpdatePsbt(psbt);
}

bool NunchukStorage::UpdatePsbtTxId(Chain chain, const std::string& wallet_id,
                                    const std::string& old_id,
                                    const std::string& new_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).UpdatePsbtTxId(old_id, new_id);
}

std::string NunchukStorage::GetPsbt(Chain chain, const std::string& wallet_id,
                                    const std::string& tx_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetPsbt(tx_id);
}

bool NunchukStorage::SetUtxos(Chain chain, const std::string& wallet_id,
                              const std::string& address,
                              const std::string& utxo) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).SetUtxos(address, utxo);
}

Amount NunchukStorage::GetBalance(Chain chain, const std::string& wallet_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetBalance();
}
std::string NunchukStorage::FillPsbt(Chain chain, const std::string& wallet_id,
                                     const std::string& psbt) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).FillPsbt(psbt);
}

// non-reentrant function
void NunchukStorage::MaybeMigrate(Chain chain) {
  static std::once_flag flag;
  std::call_once(flag, [&] {
    std::unique_lock<std::shared_mutex> lock(access_);
    auto wallets = ListWallets0(chain);
    for (auto&& wallet_id : wallets) {
      GetWalletDb(chain, wallet_id).MaybeMigrate();
    }

    // migrate app state
    auto appstate = GetAppStateDb(chain);
    int64_t current_ver = appstate.GetStorageVersion();
    if (current_ver == STORAGE_VER) return;
    if (current_ver < 3) {
      for (auto&& wallet_id : wallets) {
        GetWallet(chain, wallet_id, true);
      }
    }
    DLOG_F(INFO, "NunchukAppStateDb migrate to version %d", STORAGE_VER);
    appstate.SetStorageVersion(STORAGE_VER);
  });
}

int NunchukStorage::GetChainTip(Chain chain) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetAppStateDb(chain).GetChainTip();
}

bool NunchukStorage::SetChainTip(Chain chain, int value) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetAppStateDb(chain).SetChainTip(value);
}

std::string NunchukStorage::GetSelectedWallet(Chain chain) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetAppStateDb(chain).GetSelectedWallet();
}

bool NunchukStorage::SetSelectedWallet(Chain chain, const std::string& value) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetAppStateDb(chain).SetSelectedWallet(value);
}

std::vector<SingleSigner> NunchukStorage::GetRemoteSigners(Chain chain) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto signers = ListMasterSigners0(chain);
  std::vector<SingleSigner> rs;
  for (auto&& signer_id : signers) {
    auto remote = GetSignerDb(chain, signer_id).GetRemoteSigners();
    rs.insert(rs.end(), remote.begin(), remote.end());
  }
  return rs;
}

bool NunchukStorage::DeleteRemoteSigner(Chain chain,
                                        const std::string& master_fingerprint,
                                        const std::string& derivation_path) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetSignerDb(chain, master_fingerprint)
      .DeleteRemoteSigner(derivation_path);
}

bool NunchukStorage::UpdateRemoteSigner(Chain chain,
                                        const SingleSigner& remotesigner) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetSignerDb(chain, remotesigner.get_master_fingerprint())
      .SetRemoteName(remotesigner.get_derivation_path(),
                     remotesigner.get_name());
}

bool NunchukStorage::IsMasterSigner(Chain chain, const std::string& id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetSignerDb(chain, id).IsMaster();
}

int NunchukStorage::GetAddressIndex(Chain chain, const std::string& wallet_id,
                                    const std::string& address) {
  std::shared_lock<std::shared_mutex> lock(access_);
  int index = GetWalletDb(chain, wallet_id).GetAddressIndex(address);
  if (index < 0)
    throw StorageException(
        StorageException::ADDRESS_NOT_FOUND,
        strprintf("Address not found wallet_id = '%s'", wallet_id));
  return index;
}

Amount NunchukStorage::GetAddressBalance(Chain chain,
                                         const std::string& wallet_id,
                                         const std::string& address) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetAddressBalance(address);
}

std::string NunchukStorage::GetMultisigConfig(Chain chain,
                                              const std::string& wallet_id,
                                              bool is_cobo) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetMultisigConfig(is_cobo);
}

void NunchukStorage::SendSignerPassphrase(Chain chain,
                                          const std::string& mastersigner_id,
                                          const std::string& passphrase) {
  std::unique_lock<std::shared_mutex> lock(access_);
  GetSignerDb(chain, mastersigner_id).GetSoftwareSigner(passphrase);
  signer_passphrase_[ba::to_lower_copy(mastersigner_id)] = passphrase;
}

void NunchukStorage::ClearSignerPassphrase(Chain chain,
                                           const std::string& mastersigner_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  signer_passphrase_.erase(ba::to_lower_copy(mastersigner_id));
}

std::string NunchukStorage::ExportBackup() {
  std::unique_lock<std::shared_mutex> lock(access_);

  auto exportChain = [&](Chain chain) {
    json rs;
    rs["wallets"] = json::array();
    auto wids = ListWallets0(chain);
    for (auto&& id : wids) {
      auto wallet_db = GetWalletDb(chain, id);
      auto w = wallet_db.GetWallet();
      json wallet = {
          {"id", w.get_id()},
          {"name", w.get_name()},
          {"descriptor", w.get_descriptor(DescriptorPath::ANY)},
          {"create_date", w.get_create_date()},
          {"description", w.get_description()},
          {"pending_signatures", json::array()},
      };
      auto txs = wallet_db.GetTransactions();
      for (auto&& tx : txs) {
        if (tx.get_status() != TransactionStatus::PENDING_SIGNATURES) continue;
        json outputs = json::array();
        for (auto&& o : tx.get_user_outputs()) {
          outputs.push_back({{"address", o.first}, {"amount", o.second}});
        }
        wallet["pending_signatures"].push_back(
            {{"psbt", tx.get_psbt()},
             {"fee", tx.get_fee()},
             {"memo", tx.get_memo()},
             {"change_pos", tx.get_change_index()},
             {"fee_rate", tx.get_fee_rate()},
             {"subtract_fee_from_amount", tx.subtract_fee_from_amount()},
             {"outputs", outputs}});
      }
      rs["wallets"].push_back(wallet);
    }

    rs["signers"] = json::array();
    auto sids = ListMasterSigners0(chain);
    for (auto&& id : sids) {
      auto signerDb = GetSignerDb(chain, id);
      if (signerDb.GetId().empty()) continue;
      json signer = {{"id", signerDb.GetId()},
                     {"name", signerDb.GetName()},
                     {"device_type", signerDb.GetDeviceType()},
                     {"device_model", signerDb.GetDeviceModel()},
                     {"last_health_check", signerDb.GetLastHealthCheck()},
                     {"bip32", json::array()},
                     {"remote", json::array()}};
      auto singleSigners = signerDb.GetSingleSigners(false);
      for (auto&& singleSigner : singleSigners) {
        signer["bip32"].push_back({{"path", singleSigner.get_derivation_path()},
                                   {"xpub", singleSigner.get_xpub()}});
      }
      auto remoteSigners = signerDb.GetRemoteSigners();
      for (auto&& singleSigner : remoteSigners) {
        signer["remote"].push_back(
            {{"path", singleSigner.get_derivation_path()},
             {"xpub", singleSigner.get_xpub()},
             {"pubkey", singleSigner.get_public_key()},
             {"name", singleSigner.get_name()},
             {"last_health_check", singleSigner.get_last_health_check()}});
      }
      rs["signers"].push_back(signer);
    }
    auto appstate = GetAppStateDb(chain);
    rs["deleted_wallets"] = appstate.GetDeletedWallets();
    rs["deleted_signers"] = appstate.GetDeletedSigners();
    rs["deleted_txs"] = appstate.GetDeletedTransactions();
    return rs;
  };

  time_t ts = std::time(0);
  json data = {{"testnet", exportChain(Chain::TESTNET)},
               {"mainnet", exportChain(Chain::MAIN)},
               {"signet", exportChain(Chain::SIGNET)},
               {"ts", ts}};
  GetAppStateDb(Chain::MAIN).SetLastExportTs(ts);
  return data.dump();
}

bool NunchukStorage::SyncWithBackup(const std::string& dataStr,
                                    std::function<bool(int)> progress) {
  std::unique_lock<std::shared_mutex> lock(access_);

  int percent = 0;

  auto hasTx = [](const std::vector<Transaction>& txs, const std::string& id,
                  bool pendingOnly) {
    auto check = [id, pendingOnly](const Transaction& t) {
      return t.get_txid() == id &&
             (!pendingOnly ||
              t.get_status() == TransactionStatus::PENDING_SIGNATURES);
    };
    return std::any_of(txs.begin(), txs.end(), check);
  };
  auto importChain = [&](Chain chain, json& d) {
    if (d == nullptr) return;
    auto appstate = GetAppStateDb(chain);
    json signers = d["signers"];
    auto dsids = appstate.GetDeletedSigners();
    for (auto&& signer : signers) {
      std::string id = signer["id"];
      if (id.empty()) continue;
      if (std::find(dsids.begin(), dsids.end(), id) != dsids.end()) continue;
      fs::path db_file = GetSignerDir(chain, id);
      NunchukSignerDb db{chain, id, db_file.string(), passphrase_};
      if (!signer["name"].get<std::string>().empty()) {
        db.InitSigner(signer["name"],
                      {signer["device_type"], signer["device_model"], id}, "");
        db.SetLastHealthCheck(signer["last_health_check"]);
        for (auto&& ss : signer["bip32"]) {
          db.AddXPub(ss["path"], ss["xpub"], GetBip32Type(ss["path"]));
        }
      }
      for (auto&& ss : signer["remote"]) {
        db.AddRemote(ss["name"], ss["xpub"], ss["pubkey"], ss["path"]);
        db.SetRemoteLastHealthCheck(ss["path"], ss["last_health_check"]);
      }
    }
    if (d["deleted_signers"] != nullptr) {
      std::vector<std::string> deleted_signers = d["deleted_signers"];
      for (auto&& id : deleted_signers) {
        appstate.AddDeletedSigner(id);
        fs::remove(GetSignerDir(chain, id));
      }
    }
    percent += 25;
    progress(percent);

    json wallets = d["wallets"];
    auto dwids = appstate.GetDeletedWallets();
    for (auto&& wallet : wallets) {
      std::string id = wallet["id"];
      if (id.empty()) continue;
      if (std::find(dwids.begin(), dwids.end(), id) != dwids.end()) continue;
      fs::path db_file = GetWalletDir(chain, id);
      if (!fs::exists(db_file)) {
        AddressType a;
        WalletType w;
        int m;
        int n;
        std::vector<SingleSigner> signers;
        if (ParseDescriptors(wallet["descriptor"], a, w, m, n, signers)) {
          CreateWallet0(chain, wallet["name"], m, n, signers, a,
                        w == WalletType::ESCROW, wallet["description"], true,
                        wallet["create_date"]);
        }
      } else {
        auto db = GetWalletDb(chain, id);
        db.SetName(wallet["name"]);
        db.SetDescription(wallet["description"]);
      }

      if (wallet["pending_signatures"] == nullptr) continue;
      auto wallet_db = GetWalletDb(chain, id);
      json pending_txs = wallet["pending_signatures"];
      auto txs = wallet_db.GetTransactions();
      auto dtxids = appstate.GetDeletedTransactions();
      for (auto&& tx : pending_txs) {
        std::string psbt = tx["psbt"];
        PartiallySignedTransaction psbtx = DecodePsbt(psbt);
        std::string tx_id = psbtx.tx.value().GetHash().GetHex();
        if (hasTx(txs, tx_id, false)) continue;
        if (std::find(dtxids.begin(), dtxids.end(), tx_id) != dtxids.end())
          continue;
        std::map<std::string, Amount> outputs;
        for (auto&& output : tx["outputs"]) {
          outputs[output["address"]] = output["amount"];
        }
        try {
          wallet_db.CreatePsbt(psbt, tx["fee"], tx["memo"], tx["change_pos"],
                               outputs, tx["fee_rate"],
                               tx["subtract_fee_from_amount"], {});
        } catch (...) {
        }
      }

      if (d["deleted_txs"] != nullptr) {
        std::vector<std::string> deleted_txs = d["deleted_txs"];
        for (auto&& id : deleted_txs) {
          appstate.AddDeletedTransaction(id);
          if (hasTx(txs, id, true)) wallet_db.DeleteTransaction(id);
        }
      }
    }
    if (d["deleted_wallets"] != nullptr) {
      std::vector<std::string> deleted_wallets = d["deleted_wallets"];
      for (auto&& id : deleted_wallets) {
        appstate.AddDeletedWallet(id);
        fs::remove(GetWalletDir(chain, id));
      }
    }
    percent += 25;
    progress(percent);
  };

  auto appState = GetAppStateDb(Chain::MAIN);
  json data = json::parse(dataStr);
  time_t ts = data["ts"];
  if (ts != appState.GetLastExportTs()) {
    importChain(Chain::TESTNET, data["testnet"]);
    importChain(Chain::MAIN, data["mainnet"]);
    importChain(Chain::SIGNET, data["signet"]);
  } else {
    progress(100);
  }
  return appState.SetLastSyncTs(ts);
}

time_t NunchukStorage::GetLastSyncTs() {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetAppStateDb(Chain::MAIN).GetLastSyncTs();
}

time_t NunchukStorage::GetLastExportTs() {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetAppStateDb(Chain::MAIN).GetLastExportTs();
}

std::vector<PrimaryKey> NunchukStorage::GetPrimaryKeys(Chain chain) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetPrimaryDb(chain).GetPrimaryKeys();
}

void NunchukStorage::AddPrimaryKey(Chain chain, const PrimaryKey& key) {
  std::unique_lock<std::shared_mutex> lock(access_);
  GetPrimaryDb(chain).AddPrimaryKey(key);
}

}  // namespace nunchuk
