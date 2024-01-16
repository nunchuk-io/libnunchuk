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
#include <exception>
#include <utility>
#include <utils/bip32.hpp>
#include <utils/txutils.hpp>
#include <utils/json.hpp>
#include <utils/loguru.hpp>
#include <utils/bsms.hpp>
#include <utils/multisigconfig.hpp>
#include <utils/enumconverter.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/filesystem/fstream.hpp>
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

std::map<std::string, std::shared_ptr<NunchukStorage>>
    NunchukStorage::instances_;
std::shared_mutex NunchukStorage::access_;

std::shared_ptr<NunchukStorage> NunchukStorage::get(const std::string& acc) {
  if (const auto it = instances_.find(acc); it != instances_.end()) {
    return it->second;
  }
  return instances_[acc] = std::make_shared<NunchukStorage>(acc);
}

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
  const auto path = fs::system_complete(file_path);
  fs::ofstream file(path, std::ios_base::binary);

  if (!file.is_open()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Can not open file");
  }

  const std::size_t sz = value.size();
  if (BOOST_UNLIKELY(sz > static_cast<boost::uintmax_t>(
                              (std::numeric_limits<std::streamsize>::max)()))) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "String size exceeds max write size");
  }

  if (!file.write(value.c_str(), static_cast<std::streamsize>(sz))) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Can not write file");
  }

  if (file.bad()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Can not write file");
  }

  return true;
}

std::string NunchukStorage::LoadFile(const std::string& file_path) {
  const auto path = fs::system_complete(file_path);
  fs::ifstream file(path, std::ios_base::binary);
  if (!file.is_open()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Can not open file");
  }

  const boost::uintmax_t sz = boost::filesystem::file_size(path);
  if (BOOST_UNLIKELY(sz > static_cast<boost::uintmax_t>(
                              (std::numeric_limits<std::streamsize>::max)()))) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "File size exceeds max read size");
  }

  std::string value(static_cast<std::size_t>(sz), '\0');
  if (sz > 0u) {
    if (!file.read(&value[0], static_cast<std::streamsize>(sz))) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Can not read file");
    }
  }
  if (file.bad()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Can not read file");
  }
  return value;
}

bool NunchukStorage::ExportWallet(Chain chain, const std::string& wallet_id,
                                  const std::string& file_path,
                                  ExportFormat format) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto wallet_db = GetWalletDb(chain, wallet_id);
  auto wallet = wallet_db.GetWallet(true, true);
  switch (format) {
    case ExportFormat::COLDCARD:
      return WriteFile(file_path, ::GetMultisigConfig(wallet));
    case ExportFormat::DESCRIPTOR:
      return WriteFile(file_path, wallet.get_descriptor(DescriptorPath::ANY));
    case ExportFormat::BSMS:
      return WriteFile(file_path, GetDescriptorRecord(wallet));
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

std::string NunchukStorage::GetWalletExportData(Chain chain,
                                                const std::string& wallet_id,
                                                ExportFormat format) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto wallet_db = GetWalletDb(chain, wallet_id);
  auto wallet = wallet_db.GetWallet(true, true);
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

NunchukStorage::NunchukStorage(const std::string& acc) : account_(acc) {}

void NunchukStorage::Init(const std::string& datadir,
                          const std::string& passphrase) {
  passphrase_ = passphrase;
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

void NunchukStorage::SetPassphrase(Chain chain, const std::string& value) {
  std::unique_lock<std::shared_mutex> lock(access_);
  if (value == passphrase_) {
    throw NunchukException(NunchukException::PASSPHRASE_ALREADY_USED,
                           "Passphrase used");
  }
  auto rekey = [&](const fs::path& old_file, const std::string& id) {
    auto new_file = datadir_ / "tmp" / id;
    NunchukDb db{chain, id, old_file.string(), passphrase_};
    if (value.empty()) {
      db.DecryptDb(new_file.string());
    } else if (passphrase_.empty()) {
      db.EncryptDb(new_file.string(), value);
    } else {
      return db.ReKey(value);
    }
    fs::copy_file(new_file, old_file, fs::copy_option::overwrite_if_exists);
    fs::remove(new_file);
  };

  auto wallets = ListWallets0(chain);
  for (auto&& wallet_id : wallets) {
    rekey(GetWalletDir(chain, wallet_id), wallet_id);
  }
  auto signers = ListMasterSigners0(chain);
  for (auto&& signer_id : signers) {
    rekey(GetSignerDir(chain, signer_id), signer_id);
  }
  rekey(GetRoomDir(chain), "matrix");
  passphrase_ = value;
}

fs::path NunchukStorage::ChainStr(Chain chain) const {
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
  throw NunchukException(NunchukException::INVALID_CHAIN, "Invalid chain");
}

fs::path NunchukStorage::GetWalletDir(Chain chain, std::string id) const {
  if (id.empty()) {
    throw StorageException(StorageException::WALLET_NOT_FOUND,
                           "Wallet id can not empty!");
  }
  return datadir_ / ChainStr(chain) / "wallets" / id;
}

fs::path NunchukStorage::GetSignerDir(Chain chain, std::string id) const {
  if (id.empty()) {
    throw StorageException(StorageException::SIGNER_NOT_FOUND,
                           "Signer id can not empty!");
  }
  std::string lowercase_id = ba::to_lower_copy(id);
  fs::path path = datadir_;
  path /= ChainStr(chain);
  path /= "signers";
  path /= lowercase_id;
  return path;
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

fs::path NunchukStorage::GetTapprotocolDir(Chain chain) const {
  return datadir_ / ChainStr(chain) / "tap-protocol";
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
  db.Init();
  return db;
}

NunchukTapprotocolDb NunchukStorage::GetTaprotocolDb(Chain chain) {
  fs::path db_file = GetTapprotocolDir(chain);
  bool is_new = !fs::exists(db_file);
  auto db = NunchukTapprotocolDb{chain, "", db_file.string(), ""};
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

Wallet NunchukStorage::CreateWallet(Chain chain, const Wallet& wallet) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return CreateWallet0(chain, wallet);
}

Wallet NunchukStorage::CreateWallet0(Chain chain, const Wallet& wallet) {
  const AddressType at = wallet.get_address_type();
  const WalletType wt = wallet.get_wallet_type();

  const auto save_true_signer = [&](SingleSigner signer) {
    const std::string master_id = signer.get_master_fingerprint();
    NunchukSignerDb signer_db{
        chain, master_id, GetSignerDir(chain, master_id).string(), passphrase_};

    if (signer_db.IsMaster() && !signer.get_xpub().empty()) {
      int index = GetIndexFromPath(wt, at, signer.get_derivation_path());
      if (FormalizePath(GetBip32Path(chain, wt, at, index)) ==
          FormalizePath(signer.get_derivation_path())) {
        signer_db.AddXPub(wt, at, index, signer.get_xpub());
        signer_db.UseIndex(wt, at, index, true);
      } else {
        // custom derivation path
        signer_db.AddXPub(signer.get_derivation_path(), signer.get_xpub(),
                          "custom");
      }
      return signer;
    }

    try {
      signer_db.GetRemoteSigner(signer.get_derivation_path());
      signer_db.UseRemote(signer.get_derivation_path());
    } catch (StorageException& se) {
      if (se.code() != StorageException::SIGNER_NOT_FOUND) throw;
      // Import/Recover wallet, signers may not exist => we create as UNKNOWN
      // signers to hide on Key Manager, except for COLDCARD_NFC signers, make
      // them visible to able to sign transaction
      if (signer.get_type() != SignerType::COLDCARD_NFC) {
        signer.set_name("import");
        signer.set_type(SignerType::UNKNOWN);
      }
      signer_db.AddRemote(signer.get_name(), signer.get_xpub(),
                          signer.get_public_key(), signer.get_derivation_path(),
                          true, signer.get_type());
      return signer;
    }
    return signer;
  };

  auto id = wallet.get_id();
  fs::path wallet_file = GetWalletDir(chain, id);
  if (fs::exists(wallet_file)) {
    throw StorageException(StorageException::WALLET_EXISTED,
                           strprintf("Wallet existed! id = '%s'", id));
  }
  std::vector<SingleSigner> true_signers;
  for (auto&& signer : wallet.get_signers()) {
    true_signers.emplace_back(save_true_signer(signer));
  }
  NunchukWalletDb wallet_db{chain, id, wallet_file.string(), passphrase_};
  wallet_db.InitWallet(wallet);
  GetAppStateDb(chain).RemoveDeletedWallet(id);

  Wallet true_wallet = wallet;
  true_wallet.set_signers(true_signers);
  return true_wallet;
}

SingleSigner NunchukStorage::GetTrueSigner0(Chain chain,
                                            const SingleSigner& signer,
                                            bool create_if_not_exist) const {
  const std::string master_id = signer.get_master_fingerprint();
  NunchukSignerDb signer_db{
      chain, master_id, GetSignerDir(chain, master_id).string(), passphrase_};

  if (signer_db.IsMaster()) {
    return SingleSigner(
        signer_db.GetName(), signer.get_xpub(), signer.get_public_key(),
        signer.get_derivation_path(), signer.get_master_fingerprint(),
        signer_db.GetLastHealthCheck(), master_id, false,
        signer_db.GetSignerType(), signer_db.GetTags(), signer_db.IsVisible());
  }

  // remote
  try {
    auto remote = signer_db.GetRemoteSigner(signer.get_derivation_path());
    return SingleSigner(
        remote.get_name(), signer.get_xpub(), signer.get_public_key(),
        signer.get_derivation_path(), signer.get_master_fingerprint(),
        remote.get_last_health_check(), {}, false, signer_db.GetSignerType(),
        signer_db.GetTags(), signer_db.IsVisible());
  } catch (StorageException& se) {
    if (se.code() != StorageException::SIGNER_NOT_FOUND) throw;
    if (create_if_not_exist) {
      signer_db.AddRemote(signer.get_name(), signer.get_xpub(),
                          signer.get_public_key(), signer.get_derivation_path(),
                          true, signer.get_type(), signer.get_tags());
    }
    return signer;
  }
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
  signer_db.SetVisible(true);
  GetAppStateDb(chain).RemoveDeletedSigner(id);
  return id;
}

std::string NunchukStorage::CreateMasterSignerFromMasterXprv(
    Chain chain, const std::string& name, const Device& device,
    const std::string& master_xprv) {
  std::unique_lock<std::shared_mutex> lock(access_);
  std::string id = ba::to_lower_copy(device.get_master_fingerprint());
  NunchukSignerDb signer_db{chain, id, GetSignerDir(chain, id).string(),
                            passphrase_};
  signer_db.SetVisible(true);
  signer_db.InitSignerMasterXprv(name, device, master_xprv);
  GetAppStateDb(chain).RemoveDeletedSigner(id);
  return id;
}

SingleSigner NunchukStorage::CreateSingleSigner(
    Chain chain, const std::string& name, const std::string& xpub,
    const std::string& public_key, const std::string& derivation_path,
    const std::string& master_fingerprint, SignerType signer_type,
    std::vector<SignerTag> tags) {
  std::unique_lock<std::shared_mutex> lock(access_);
  std::string id = master_fingerprint;
  NunchukSignerDb signer_db{chain, id, GetSignerDir(chain, id).string(),
                            passphrase_};
  signer_db.SetVisible(true);
  if (signer_db.IsMaster()) {
    throw StorageException(StorageException::SIGNER_EXISTS,
                           strprintf("Signer exists id = '%s'", id));
  }
  if (!signer_db.AddRemote(name, xpub, public_key, derivation_path, false,
                           signer_type, tags)) {
    throw StorageException(StorageException::SIGNER_EXISTS,
                           strprintf("Signer exists id = '%s'", id));
  }

  GetAppStateDb(chain).RemoveDeletedSigner(id);
  return signer_db.GetRemoteSigner(derivation_path);
}

bool NunchukStorage::HasSigner(Chain chain, const SingleSigner& signer) {
  std::shared_lock<std::shared_mutex> lock(access_);
  std::string id = signer.get_master_fingerprint();
  fs::path db_file = GetSignerDir(chain, id);
  if (!fs::exists(db_file)) return false;
  NunchukSignerDb signer_db{chain, id, db_file.string(), passphrase_};
  if (signer_db.IsMaster()) return true;
  try {
    auto remote = signer_db.GetRemoteSigner(signer.get_derivation_path());
    return remote.get_type() != SignerType::UNKNOWN &&
           remote.get_xpub() == signer.get_xpub() &&
           remote.get_public_key() == signer.get_public_key();

  } catch (StorageException& e) {
    if (e.code() != StorageException::SIGNER_NOT_FOUND) {
      throw;
    }
    return false;
  }
}

SingleSigner NunchukStorage::GetSignerFromMasterSigner(
    Chain chain, const std::string& mastersigner_id,
    const WalletType& wallet_type, const AddressType& address_type, int index) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto signer_db = GetSignerDb(chain, mastersigner_id);
  const std::string path =
      GetBip32Path(chain, wallet_type, address_type, index);
  std::string xpub = signer_db.GetXpub(wallet_type, address_type, index);

  if (xpub.empty()) {
    if (signer_db.GetSignerType() == SignerType::SOFTWARE) {
      auto ss = GetSoftwareSigner0(chain, mastersigner_id);
      xpub = ss.GetXpubAtPath(path);
      signer_db.AddXPub(wallet_type, address_type, index, xpub);
    } else {
      throw NunchukException(
          NunchukException::RUN_OUT_OF_CACHED_XPUB,
          strprintf("[%s] has run out of XPUBs. Please top up.",
                    signer_db.GetName()));
    }
  }
  auto signer = SingleSigner(
      signer_db.GetName(), xpub, "", path, signer_db.GetFingerprint(),
      signer_db.GetLastHealthCheck(), mastersigner_id, false,
      signer_db.GetSignerType(), signer_db.GetTags(), signer_db.IsVisible());
  return signer;
}

SingleSigner NunchukStorage::GetSignerFromMasterSigner(
    Chain chain, const std::string& mastersigner_id, const std::string& path) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto signer_db = GetSignerDb(chain, mastersigner_id);
  std::string xpub = signer_db.GetXpub(path);

  if (xpub.empty()) {
    if (signer_db.GetSignerType() == SignerType::SOFTWARE) {
      auto ss = GetSoftwareSigner0(chain, mastersigner_id);
      xpub = ss.GetXpubAtPath(path);
      signer_db.AddXPub(path, xpub, "custom");
    } else {
      throw NunchukException(
          NunchukException::RUN_OUT_OF_CACHED_XPUB,
          strprintf("[%s] has run out of XPUBs. Please top up.",
                    signer_db.GetName()));
    }
  }
  auto signer = SingleSigner(
      signer_db.GetName(), xpub, "", path, signer_db.GetFingerprint(),
      signer_db.GetLastHealthCheck(), mastersigner_id, false,
      signer_db.GetSignerType(), signer_db.GetTags(), signer_db.IsVisible());
  return signer;
}

SingleSigner NunchukStorage::AddSignerToMasterSigner(
    Chain chain, const std::string& mastersigner_id,
    const SingleSigner& signer) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto signer_db = GetSignerDb(chain, mastersigner_id);
  std::string xpub = signer_db.GetXpub(signer.get_derivation_path());
  if (!xpub.empty()) {
    throw StorageException(
        StorageException::SIGNER_EXISTS,
        strprintf("Signer exists id = '%s'", mastersigner_id));
  }

  signer_db.AddXPub(signer.get_derivation_path(), signer.get_xpub(),
                    GetBip32Type(signer.get_derivation_path()));
  return SingleSigner(signer_db.GetName(), signer.get_xpub(), "",
                      signer.get_derivation_path(), signer_db.GetFingerprint(),
                      signer_db.GetLastHealthCheck(), mastersigner_id, false,
                      signer_db.GetSignerType(), signer_db.GetTags(),
                      signer_db.IsVisible());
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
  auto signer_type = signer_db.GetSignerType();
  bool is_software = signer_type == SignerType::SOFTWARE;
  bool is_nfc = signer_type == SignerType::NFC;
  bool is_bitbox2 = signer_db.GetDeviceType() == "bitbox02";
  bool is_ledger = signer_db.GetDeviceType() == "ledger";
  bool is_trezor = signer_db.GetDeviceType() == "trezor";
  int count = 0;
  auto total = is_software ? 82 : TOTAL_CACHE_NUMBER;
  progress(count++ * 100 / total);

  // Retrieve standard BIP32 paths when connected to a device for the first time
  if (first && !is_bitbox2 && !is_ledger && !is_trezor) {
    auto cachePath = [&](const std::string& path) {
      signer_db.AddXPub(path, getxpub(path), "custom");
      progress(count++ * 100 / total);
    };
    cachePath("m");
    cachePath(chain == Chain::MAIN ? MAINNET_HEALTH_CHECK_PATH
                                   : TESTNET_HEALTH_CHECK_PATH);
  }

  auto cacheNumber = [&](WalletType w, AddressType a) {
    if (is_software) return 10;
    if (is_bitbox2) {
      if (w == WalletType::ESCROW) return 0;
      if (w == WalletType::MULTI_SIG && a == AddressType::LEGACY) return 0;
      if (w == WalletType::SINGLE_SIG && a == AddressType::LEGACY) return 0;
    }
    if (is_ledger) {
      if (w == WalletType::ESCROW) return 0;
      if (w == WalletType::MULTI_SIG && a == AddressType::LEGACY) return 0;
    }
    if (first) return 1;
    if (w == WalletType::ESCROW) return ESCROW_CACHE_NUMBER;
    if (w == WalletType::MULTI_SIG) {
      if (a == AddressType::NATIVE_SEGWIT) return MULTISIG_BIP48_2_CACHE_NUMBER;
      if (a == AddressType::NESTED_SEGWIT) return MULTISIG_BIP48_1_CACHE_NUMBER;
      if (a == AddressType::LEGACY) return MULTISIG_BIP45_CACHE_NUMBER;
    }
    if (w == WalletType::SINGLE_SIG) {
      if (a == AddressType::NATIVE_SEGWIT) return SINGLESIG_BIP84_CACHE_NUMBER;
      if (a == AddressType::TAPROOT) return SINGLESIG_BIP86_CACHE_NUMBER;
      if (a == AddressType::NESTED_SEGWIT) return SINGLESIG_BIP49_CACHE_NUMBER;
      if (a == AddressType::LEGACY) return SINGLESIG_BIP44_CACHE_NUMBER;
    }
    return 0;
  };
  auto cacheIndex = [&](WalletType w, AddressType a) {
    int n = cacheNumber(w, a);
    int index = signer_db.GetCachedIndex(w, a);
    // cache 0 index multisig for old key
    if (index != -1 && w == WalletType::MULTI_SIG) {
      auto xpub = signer_db.GetXpub(w, a, 0);
      if (xpub.empty()) {
        auto path = GetBip32Path(chain, w, a, 0);
        if (is_ledger) std::replace(path.begin(), path.end(), '\'', 'h');
        signer_db.AddXPub(w, a, 0, getxpub(path));
      }
    }
    for (int i = index + 1; i <= index + n; i++) {
      auto path = GetBip32Path(chain, w, a, i);
      if (is_ledger) std::replace(path.begin(), path.end(), '\'', 'h');
      signer_db.AddXPub(w, a, i, getxpub(path));
      progress(count++ * 100 / total);
    }
  };
  cacheIndex(WalletType::MULTI_SIG, AddressType::NATIVE_SEGWIT);
  cacheIndex(WalletType::MULTI_SIG, AddressType::NESTED_SEGWIT);
  cacheIndex(WalletType::MULTI_SIG, AddressType::LEGACY);
  cacheIndex(WalletType::SINGLE_SIG, AddressType::NATIVE_SEGWIT);
  cacheIndex(WalletType::SINGLE_SIG, AddressType::NESTED_SEGWIT);
  cacheIndex(WalletType::SINGLE_SIG, AddressType::LEGACY);
  if (!is_nfc) cacheIndex(WalletType::SINGLE_SIG, AddressType::TAPROOT);
  cacheIndex(WalletType::ESCROW, AddressType::ANY);
  progress(100);
}

bool NunchukStorage::CacheDefaultMasterSignerXpub(
    Chain chain, const std::string& mastersigner_id,
    std::function<std::string(std::string)> getxpub,
    std::function<bool(int)> progress) {
  std::vector<std::string> DEFAULT_PATHS = {
      "m",
      chain == Chain::MAIN ? MAINNET_HEALTH_CHECK_PATH
                           : TESTNET_HEALTH_CHECK_PATH,
      GetBip32Path(chain, WalletType::MULTI_SIG, AddressType::NATIVE_SEGWIT, 0),
      GetBip32Path(chain, WalletType::MULTI_SIG, AddressType::NESTED_SEGWIT, 0),
      GetBip32Path(chain, WalletType::MULTI_SIG, AddressType::LEGACY, 0),
      GetBip32Path(chain, WalletType::SINGLE_SIG, AddressType::NATIVE_SEGWIT,
                   0),
      GetBip32Path(chain, WalletType::SINGLE_SIG, AddressType::NESTED_SEGWIT,
                   0),
      GetBip32Path(chain, WalletType::SINGLE_SIG, AddressType::LEGACY, 0),
      GetBip32Path(chain, WalletType::ESCROW, AddressType::ANY, 0),
  };
  auto signer_db = GetSignerDb(chain, mastersigner_id);

  auto is_exist_path = [&](const std::string& path) {
    if (signer_db.GetXpub(path).empty()) {
      return false;
    }
    return true;
  };

  DEFAULT_PATHS.erase(
      std::remove_if(DEFAULT_PATHS.begin(), DEFAULT_PATHS.end(), is_exist_path),
      DEFAULT_PATHS.end());

  int count = 0;
  int total = DEFAULT_PATHS.size();
  for (auto&& path : DEFAULT_PATHS) {
    progress(count++ * 100 / total);
    signer_db.AddXPub(path, getxpub(path), GetBip32Type(path));
  }
  return count != 0;
}

int NunchukStorage::GetCurrentIndexFromMasterSigner(
    Chain chain, const std::string& mastersigner_id,
    const WalletType& wallet_type, const AddressType& address_type) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id)
      .GetUnusedIndex(wallet_type, address_type);
}

int NunchukStorage::GetLastUsedIndexFromMasterSigner(
    Chain chain, const std::string& mastersigner_id,
    const WalletType& wallet_type, const AddressType& address_type) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetSignerDb(chain, mastersigner_id)
      .GetLastUsedIndex(wallet_type, address_type);
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

std::vector<std::string> NunchukStorage::ListRecentlyUsedWallets(Chain chain) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto ids = ListWallets0(chain);

  std::map<std::string, time_t> last_used_map;
  for (auto&& id : ids) {
    try {
      auto wallet_db = GetWalletDb(chain, id);
      auto wallet = wallet_db.GetWallet(true, true);
      last_used_map.insert({id, wallet.get_last_used()});
    } catch (...) {
    }
  }

  ids.erase(std::remove_if(ids.begin(), ids.end(),
                           [&](const std::string& id) {
                             return last_used_map.find(id) ==
                                    last_used_map.end();
                           }),
            ids.end());

  std::sort(ids.begin(), ids.end(),
            [&](const std::string& lhs, const std::string& rhs) {
              return last_used_map[lhs] > last_used_map[rhs];
            });
  return ids;
}

std::vector<std::string> NunchukStorage::ListWallets0(Chain chain) {
  fs::path directory = (datadir_ / ChainStr(chain) / "wallets");
  std::vector<std::string> ids;
  for (auto&& f : fs::directory_iterator(directory)) {
    auto id = f.path().filename().string();
    if (id.size() == 8) ids.push_back(id);
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
    if (id.size() == 8) ids.push_back(id);
  }
  return ids;
}

Wallet NunchukStorage::GetWallet(Chain chain, const std::string& id,
                                 bool create_signers_if_not_exist) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto wallet_db = GetWalletDb(chain, id);
  Wallet wallet = wallet_db.GetWallet(false, true);

  std::vector<SingleSigner> true_signers;
  for (auto&& signer : wallet.get_signers()) {
    true_signers.push_back(
        GetTrueSigner0(chain, signer, create_signers_if_not_exist));
  }
  Wallet true_wallet(id, wallet.get_m(), wallet.get_n(), true_signers,
                     wallet.get_address_type(), wallet.is_escrow(),
                     wallet.get_create_date());
  true_wallet.set_name(wallet.get_name());
  true_wallet.set_description(wallet.get_description());
  true_wallet.set_balance(wallet.get_balance());
  true_wallet.set_unconfirmed_balance(wallet.get_unconfirmed_balance());
  true_wallet.set_last_used(wallet.get_last_used());
  true_wallet.set_gap_limit(wallet.get_gap_limit());
  return true_wallet;
}

bool NunchukStorage::HasWallet(Chain chain, const std::string& wallet_id) {
  fs::path wallet_file = GetWalletDir(chain, wallet_id);
  return fs::exists(wallet_file);
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
    device.set_needs_pass_phrase_sent(signer_passphrase_.count(mid) == 0);
  }
  MasterSigner signer{id, device, signer_db.GetLastHealthCheck(), signer_type};
  signer.set_name(signer_db.GetName());
  signer.set_tags(signer_db.GetTags());
  signer.set_visible(signer_db.IsVisible());
  return signer;
}

SoftwareSigner NunchukStorage::GetSoftwareSigner(Chain chain,
                                                 const std::string& id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetSoftwareSigner0(chain, id);
}

SoftwareSigner NunchukStorage::GetSoftwareSigner0(Chain chain,
                                                  const std::string& id) {
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
         wallet_db.SetDescription(wallet.get_description()) &&
         wallet_db.SetLastUsed(wallet.get_last_used()) &&
         wallet_db.SetGapLimit(wallet.get_gap_limit());
}

bool NunchukStorage::UpdateMasterSigner(Chain chain,
                                        const MasterSigner& signer) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto signer_db = GetSignerDb(chain, signer.get_id());
  return signer_db.SetName(signer.get_name()) &&
         signer_db.SetTags(signer.get_tags()) &&
         signer_db.SetVisible(signer.is_visible());
}

bool NunchukStorage::DeleteWallet(Chain chain, const std::string& id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  {
    auto wallet_db = GetWalletDb(chain, id);
    auto wallet = wallet_db.GetWallet(true, true);
    WalletType wt = wallet.get_wallet_type();
    AddressType at = wallet.get_address_type();
    for (auto&& signer : wallet.get_signers()) {
      int index = GetIndexFromPath(wt, at, signer.get_derivation_path());
      if (FormalizePath(GetBip32Path(chain, wt, at, index)) !=
          FormalizePath(signer.get_derivation_path())) {
        continue;
      }
      try {
        std::string master_id = signer.get_master_fingerprint();
        std::string db_dir = GetSignerDir(chain, master_id).string();
        NunchukSignerDb signer_db{chain, master_id, db_dir, passphrase_};
        if (signer_db.IsMaster()) signer_db.UseIndex(wt, at, index, false);
      } catch (...) {
      }
    }
    wallet_db.DeleteWallet();
  }
  GetAppStateDb(chain).AddDeletedWallet(id);
  return fs::remove(GetWalletDir(chain, id));
}

bool NunchukStorage::DeleteMasterSigner(Chain chain, const std::string& id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto signer_db = GetSignerDb(chain, id);

  GetTaprotocolDb(chain).DeleteTapsigner(id);

  signer_db.DeleteSigner();
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
  const auto utxos_set = [utxos = db.GetCoins()]() {
    std::set<std::pair<std::string, int>> ret;
    for (auto&& utxo : utxos) {
      ret.insert({utxo.get_txid(), utxo.get_vout()});
    }
    return ret;
  }();

  const auto used_inputs_set = [&]() {
    std::set<std::pair<std::string, int>> ret;
    for (auto&& tx : vtx) {
      if (tx.get_height() > 0) {
        for (auto&& input : tx.get_inputs()) {
          ret.insert(input);
        }
      }
    }
    return ret;
  }();

  auto is_valid_input = [&](const TxInput& input) {
    return utxos_set.find(input) != utxos_set.end();
  };

  auto is_used_input = [&](const TxInput& input) {
    return used_inputs_set.find(input) != used_inputs_set.end();
  };

  auto end = std::remove_if(vtx.begin(), vtx.end(), [&](const Transaction& tx) {
    if (!tx.get_replace_txid().empty() && tx.get_replaced_by_txid().empty()) {
      // TODO: some vtxs are already being moved
      for (auto&& r : vtx) {
        if (r.get_txid() == tx.get_replace_txid() &&
            r.get_status() == TransactionStatus::PENDING_CONFIRMATION) {
          return false;
        }
      }
    }
    if (tx.get_height() == -1) {
      for (auto&& input : tx.get_inputs()) {
        if (!is_valid_input(input)) {
          return true;
        }
      }
    }

    // Remove replaced transaction on recipient's side
    if (tx.get_status() == TransactionStatus::PENDING_CONFIRMATION &&
        std::find_if(tx.get_inputs().begin(), tx.get_inputs().end(),
                     is_used_input) != tx.get_inputs().end()) {
      return true;
    }
    return false;
  });
  vtx.erase(end, vtx.end());

  for (auto&& tx : vtx) {
    db.FillSendReceiveData(tx);
  }
  return vtx;
}

std::vector<UnspentOutput> NunchukStorage::GetUtxos(
    Chain chain, const std::string& wallet_id, bool include_spent) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetUtxos0(chain, wallet_id, include_spent);
}

std::vector<UnspentOutput> NunchukStorage::GetUtxos0(
    Chain chain, const std::string& wallet_id, bool include_spent) {
  auto wallet = GetWalletDb(chain, wallet_id);
  auto coins = wallet.GetCoins();
  std::vector<UnspentOutput> utxos{};
  for (auto&& coin : coins) {
    if (!include_spent && coin.get_status() == CoinStatus::SPENT) continue;
    // coin.set_memo(wallet.GetCoinMemo(coin.get_txid(), coin.get_vout()));
    coin.set_locked(wallet.IsLock(coin.get_txid(), coin.get_vout()));
    coin.set_tags(wallet.GetAddedTags(coin.get_txid(), coin.get_vout()));
    coin.set_collections(
        wallet.GetAddedCollections(coin.get_txid(), coin.get_vout()));
    utxos.push_back(coin);
  }
  return utxos;
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

bool NunchukStorage::UpdateTransactionSchedule(Chain chain,
                                               const std::string& wallet_id,
                                               const std::string& tx_id,
                                               time_t value) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).UpdateTransactionSchedule(tx_id, value);
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

bool NunchukStorage::ReplaceTxId(Chain chain, const std::string& wallet_id,
                                 const std::string& txid,
                                 const std::string& replace_txid) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).ReplaceTxId(txid, replace_txid);
}

std::string NunchukStorage::GetPsbt(Chain chain, const std::string& wallet_id,
                                    const std::string& tx_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetPsbt(tx_id);
}

std::pair<std::string, bool> NunchukStorage::GetPsbtOrRawTx(
    Chain chain, const std::string& wallet_id, const std::string& tx_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetPsbtOrRawTx(tx_id);
}

bool NunchukStorage::SetUtxos(Chain chain, const std::string& wallet_id,
                              const std::string& address,
                              const std::string& utxo) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).SetUtxos(address, utxo);
}

Amount NunchukStorage::GetBalance(Chain chain, const std::string& wallet_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetBalance(false);
}

Amount NunchukStorage::GetUnconfirmedBalance(Chain chain,
                                             const std::string& wallet_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetBalance(true);
}
std::string NunchukStorage::FillPsbt(Chain chain, const std::string& wallet_id,
                                     const std::string& psbt) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).FillPsbt(psbt);
}

void NunchukStorage::MaybeMigrate(Chain chain) {
  std::unique_lock<std::shared_mutex> lock(access_);
  auto wallets = ListWallets0(chain);
  for (auto&& wallet_id : wallets) {
    auto wallet_db = GetWalletDb(chain, wallet_id);
    wallet_db.MaybeMigrate();
    try {
      wallet_db.GetWallet(true, false);
    } catch (...) {
    }
  }
  auto signers = ListMasterSigners0(chain);
  for (auto&& signer_id : signers) {
    GetSignerDb(chain, signer_id).MaybeMigrate();
  }

  // migrate app state
  auto appstate = GetAppStateDb(chain);
  int64_t current_ver = appstate.GetStorageVersion();
  if (current_ver == STORAGE_VER) return;
  DLOG_F(INFO, "NunchukAppStateDb migrate to version %d", STORAGE_VER);
  appstate.SetStorageVersion(STORAGE_VER);
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

SingleSigner NunchukStorage::GetRemoteSigner(Chain chain,
                                             const std::string& xfp,
                                             const std::string& path) {
  return GetSignerDb(chain, xfp).GetRemoteSigner(path);
}

std::vector<SingleSigner> NunchukStorage::GetRemoteSigners(
    Chain chain, const std::string& xfp) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetSignerDb(chain, xfp).GetRemoteSigners();
}

std::vector<SingleSigner> NunchukStorage::GetRemoteSigners(Chain chain) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto signer_ids = ListMasterSigners0(chain);
  std::vector<SingleSigner> rs;
  for (auto&& signer_id : signer_ids) {
    auto remotes = GetSignerDb(chain, signer_id).GetRemoteSigners();
    for (auto&& signer : remotes) {
      auto existed =
          std::find_if(rs.begin(), rs.end(), [&](const SingleSigner& existed) {
            return existed.get_descriptor() == signer.get_descriptor();
          });

      if (existed != rs.end()) {
        // filter out duplicated signers
        if (existed->get_name() == "import") {
          *existed = std::move(signer);
        }
      } else {
        rs.emplace_back(std::move(signer));
      }
    }
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
  auto signer_db = GetSignerDb(chain, remotesigner.get_master_fingerprint());
  return signer_db.SetRemoteName(remotesigner.get_derivation_path(),
                                 remotesigner.get_name()) &&
         signer_db.SetTags(remotesigner.get_tags()) &&
         signer_db.SetVisible(remotesigner.is_visible());
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

std::string NunchukStorage::GetAddressStatus(Chain chain,
                                             const std::string& wallet_id,
                                             const std::string& address) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetAddressStatus(address);
}

std::string NunchukStorage::GetMultisigConfig(Chain chain,
                                              const std::string& wallet_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return ::GetMultisigConfig(
      GetWalletDb(chain, wallet_id).GetWallet(true, true));
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

  auto is_assisted_wallet = [&](const Wallet& wallet) {
    const auto& signers = wallet.get_signers();
    auto server_signer = std::find_if(
        signers.begin(), signers.end(), [](const SingleSigner& signer) {
          return signer.get_type() == SignerType::SERVER;
        });
    return server_signer != signers.end();
  };

  auto exportChain = [&](Chain chain) {
    json rs;
    rs["wallets"] = json::array();
    auto wids = ListWallets0(chain);
    for (auto&& id : wids) {
      try {
        auto wallet_db = GetWalletDb(chain, id);
        auto w = wallet_db.GetWallet(true, true);
        if (is_assisted_wallet(w)) {
          // skip sync assisted wallet
          continue;
        }

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
          if (tx.get_status() != TransactionStatus::PENDING_SIGNATURES)
            continue;
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
      } catch (...) {
      }
    }

    rs["signers"] = json::array();
    rs["tapsigners"] = json::array();
    auto tapprotocolDb = GetTaprotocolDb(chain);
    auto sids = ListMasterSigners0(chain);
    for (auto&& id : sids) {
      auto signerDb = GetSignerDb(chain, id);
      if (signerDb.GetId().empty()) continue;
      if (signerDb.GetSignerType() == SignerType::SERVER) continue;

      json tags = json::array();
      for (auto&& tag : signerDb.GetTags()) {
        tags.emplace_back(SignerTagToStr(tag));
      }

      json signer = {{"id", signerDb.GetId()},
                     {"name", signerDb.GetName()},
                     {"device_type", signerDb.GetDeviceType()},
                     {"signer_type", SignerTypeToStr(signerDb.GetSignerType())},
                     {"tags", tags},
                     {"visible", signerDb.IsVisible()},
                     {"device_model", signerDb.GetDeviceModel()},
                     {"last_health_check", signerDb.GetLastHealthCheck()},
                     {"bip32", json::array()},
                     {"remote", json::array()}};
      if (signerDb.GetDeviceModel() == "tapsigner") {
        try {
          auto tapsignerStatus =
              tapprotocolDb.GetTapsignerStatusFromMasterSigner(
                  signerDb.GetId());
          rs["tapsigners"].push_back(json{
              {"card_ident", tapsignerStatus.get_card_ident()},
              {"master_signer_id", tapsignerStatus.get_master_signer_id()},
              {"birth_height", tapsignerStatus.get_birth_height()},
              {"number_of_backup", tapsignerStatus.get_number_of_backup()},
              {"version", tapsignerStatus.get_version()},
              {"is_testnet", tapsignerStatus.is_testnet()},
          });
        } catch (...) {
          // Don't sync Tapsigner if it doesn't have card_ident
          continue;
        }
      }
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
    auto tapprotocolDb = GetTaprotocolDb(chain);
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

      if (auto signer_type = signer.find("signer_type");
          signer_type != signer.end()) {
        db.UpdateSignerType(SignerTypeFromStr(*signer_type));
      }

      if (auto signer_tags = signer.find("tags"); signer_tags != signer.end()) {
        std::vector<SignerTag> tags;
        for (std::string tag_str : *signer_tags) {
          tags.emplace_back(SignerTagFromStr(tag_str));
        }
        db.SetTags(tags);
      }
      if (auto signer_visible = signer.find("visible");
          signer_visible != signer.end()) {
        db.SetVisible(*signer_visible);
      }
    }
    if (d["deleted_signers"] != nullptr) {
      std::vector<std::string> deleted_signers = d["deleted_signers"];
      for (auto&& id : deleted_signers) {
        appstate.AddDeletedSigner(id);
        fs::remove(GetSignerDir(chain, id));
      }
    }

    if (auto tapsigners = d.find("tapsigners"); tapsigners != d.end()) {
      const auto deleted_signers = appstate.GetDeletedSigners();
      for (auto&& tapsigner : *tapsigners) {
        std::string master_signer_id = tapsigner["master_signer_id"];
        if (std::find(deleted_signers.begin(), deleted_signers.end(),
                      master_signer_id) != deleted_signers.end())
          continue;
        const TapsignerStatus status(
            tapsigner["card_ident"], tapsigner["birth_height"],
            tapsigner["number_of_backup"], tapsigner["version"], std::string{},
            tapsigner["is_testnet"], 0, master_signer_id);
        tapprotocolDb.AddTapsigner(status);
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
      if (!HasWallet(chain, id)) {
        Wallet w = Utils::ParseWalletDescriptor(wallet["descriptor"]);
        w.set_name(wallet["name"]);
        w.set_description(wallet["description"]);
        w.set_create_date(wallet["create_date"]);
        CreateWallet0(chain, w);
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
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetPrimaryDb(chain).GetPrimaryKeys();
}

bool NunchukStorage::AddPrimaryKey(Chain chain, const PrimaryKey& key) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetPrimaryDb(chain).AddPrimaryKey(key);
}

bool NunchukStorage::RemovePrimaryKey(Chain chain, const std::string& account) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetPrimaryDb(chain).RemovePrimaryKey(account);
}

bool NunchukStorage::AddTapsigner(Chain chain, const TapsignerStatus& status) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetTaprotocolDb(chain).AddTapsigner(status);
}
TapsignerStatus NunchukStorage::GetTapsignerStatusFromCardIdent(
    Chain chain, const std::string& card_ident) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetTaprotocolDb(chain).GetTapsignerStatusFromCardIdent(card_ident);
}
TapsignerStatus NunchukStorage::GetTapsignerStatusFromMasterSigner(
    Chain chain, const std::string& master_signer_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetTaprotocolDb(chain).GetTapsignerStatusFromMasterSigner(
      master_signer_id);
}

bool NunchukStorage::DeleteTapsigner(Chain chain,
                                     const std::string& master_signer_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetTaprotocolDb(chain).DeleteTapsigner(master_signer_id);
}

void NunchukStorage::ForceRefresh(Chain chain, const std::string& wallet_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  GetWalletDb(chain, wallet_id).ForceRefresh();
}

bool NunchukStorage::UpdateCoinMemo(Chain chain, const std::string& wallet_id,
                                    const std::string& tx_id, int vout,
                                    const std::string& memo) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).UpdateCoinMemo(tx_id, vout, memo);
}

bool NunchukStorage::LockCoin(Chain chain, const std::string& wallet_id,
                              const std::string& tx_id, int vout) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).LockCoin(tx_id, vout);
}

bool NunchukStorage::UnlockCoin(Chain chain, const std::string& wallet_id,
                                const std::string& tx_id, int vout) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).UnlockCoin(tx_id, vout);
}

CoinTag NunchukStorage::CreateCoinTag(Chain chain, const std::string& wallet_id,
                                      const std::string& name,
                                      const std::string& color) {
  std::unique_lock<std::shared_mutex> lock(access_);
  int id = GetWalletDb(chain, wallet_id).CreateCoinTag(name, color);
  return {id, name, color};
}

std::vector<CoinTag> NunchukStorage::GetCoinTags(Chain chain,
                                                 const std::string& wallet_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetCoinTags();
}

bool NunchukStorage::UpdateCoinTag(Chain chain, const std::string& wallet_id,
                                   const CoinTag& tag) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).UpdateCoinTag(tag);
}

bool NunchukStorage::DeleteCoinTag(Chain chain, const std::string& wallet_id,
                                   int tag_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).DeleteCoinTag(tag_id);
}

bool NunchukStorage::AddToCoinTag(Chain chain, const std::string& wallet_id,
                                  int tag_id, const std::string& tx_id,
                                  int vout) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).AddToCoinTag(tag_id, tx_id, vout);
}

bool NunchukStorage::RemoveFromCoinTag(Chain chain,
                                       const std::string& wallet_id, int tag_id,
                                       const std::string& tx_id, int vout) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).RemoveFromCoinTag(tag_id, tx_id, vout);
}

std::vector<UnspentOutput> NunchukStorage::GetCoinByTag(
    Chain chain, const std::string& wallet_id, int tag_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto coin = GetWalletDb(chain, wallet_id).GetCoinByTag(tag_id);
  auto check = [&](const UnspentOutput& output) {
    std::string c = strprintf("%s:%d", output.get_txid(), output.get_vout());
    return std::find(coin.begin(), coin.end(), c) == coin.end();
  };

  auto utxo = GetUtxos0(chain, wallet_id);
  utxo.erase(std::remove_if(utxo.begin(), utxo.end(), check), utxo.end());
  return utxo;
}

CoinCollection NunchukStorage::CreateCoinCollection(
    Chain chain, const std::string& wallet_id, const std::string& name) {
  std::unique_lock<std::shared_mutex> lock(access_);
  int id = GetWalletDb(chain, wallet_id).CreateCoinCollection(name);
  return {id, name};
}

std::vector<CoinCollection> NunchukStorage::GetCoinCollections(
    Chain chain, const std::string& wallet_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetCoinCollections();
}

bool NunchukStorage::UpdateCoinCollection(Chain chain,
                                          const std::string& wallet_id,
                                          const CoinCollection& collection) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).UpdateCoinCollection(collection);
}

bool NunchukStorage::DeleteCoinCollection(Chain chain,
                                          const std::string& wallet_id,
                                          int collection_id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).DeleteCoinCollection(collection_id);
}

bool NunchukStorage::AddToCoinCollection(Chain chain,
                                         const std::string& wallet_id,
                                         int collection_id,
                                         const std::string& tx_id, int vout) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id)
      .AddToCoinCollection(collection_id, tx_id, vout);
}

bool NunchukStorage::RemoveFromCoinCollection(Chain chain,
                                              const std::string& wallet_id,
                                              int collection_id,
                                              const std::string& tx_id,
                                              int vout) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id)
      .RemoveFromCoinCollection(collection_id, tx_id, vout);
}

std::vector<UnspentOutput> NunchukStorage::GetCoinInCollection(
    Chain chain, const std::string& wallet_id, int collection_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  auto coin = GetWalletDb(chain, wallet_id).GetCoinInCollection(collection_id);
  auto check = [&](const UnspentOutput& output) {
    std::string c = strprintf("%s:%d", output.get_txid(), output.get_vout());
    return std::find(coin.begin(), coin.end(), c) == coin.end();
  };

  auto utxo = GetUtxos0(chain, wallet_id);
  utxo.erase(std::remove_if(utxo.begin(), utxo.end(), check), utxo.end());
  return utxo;
}

std::string NunchukStorage::ExportCoinControlData(
    Chain chain, const std::string& wallet_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).ExportCoinControlData();
}

bool NunchukStorage::ImportCoinControlData(Chain chain,
                                           const std::string& wallet_id,
                                           const std::string& data,
                                           bool force) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).ImportCoinControlData(data, force);
}

std::string NunchukStorage::ExportBIP329(Chain chain,
                                         const std::string& wallet_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).ExportBIP329();
}

void NunchukStorage::ImportBIP329(Chain chain, const std::string& wallet_id,
                                  const std::string& data) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).ImportBIP329(data);
}

bool NunchukStorage::IsMyAddress(Chain chain, const std::string& wallet_id,
                                 const std::string& address) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).IsMyAddress(address);
}

std::string NunchukStorage::GetAddressPath(Chain chain,
                                           const std::string& wallet_id,
                                           const std::string& address) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetAddressPath(address);
}

std::vector<std::vector<UnspentOutput>> NunchukStorage::GetAncestry(
    Chain chain, const std::string& wallet_id, const std::string& tx_id,
    int vout) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetAncestry(tx_id, vout);
}

Transaction NunchukStorage::ImportDummyTx(
    Chain chain, const std::string& wallet_id, const std::string& id,
    const std::string& body, const std::vector<std::string>& tokens) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).ImportDummyTx(id, body, tokens);
}

RequestTokens NunchukStorage::SaveDummyTxRequestToken(
    Chain chain, const std::string& wallet_id, const std::string& id,
    const std::string& token) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).SaveDummyTxRequestToken(id, token);
}

bool NunchukStorage::DeleteDummyTx(Chain chain, const std::string& wallet_id,
                                   const std::string& id) {
  std::unique_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).DeleteDummyTx(id);
}

RequestTokens NunchukStorage::GetDummyTxRequestToken(
    Chain chain, const std::string& wallet_id, const std::string& id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetDummyTxRequestToken(id);
}

std::map<std::string, Transaction> NunchukStorage::GetDummyTxs(
    Chain chain, const std::string& wallet_id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetDummyTxs();
}

Transaction NunchukStorage::GetDummyTx(Chain chain,
                                       const std::string& wallet_id,
                                       const std::string& id) {
  std::shared_lock<std::shared_mutex> lock(access_);
  return GetWalletDb(chain, wallet_id).GetDummyTx(id);
}

}  // namespace nunchuk
