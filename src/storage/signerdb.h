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

#ifndef NUNCHUK_STORAGE_SIGNERDB_H
#define NUNCHUK_STORAGE_SIGNERDB_H

#include "common.h"
#include "db.h"
#include <nunchuk.h>
#include <softwaresigner.h>
#include <vector>
#include <string>

namespace nunchuk {

class NunchukSignerDb : public NunchukDb {
 public:
  using NunchukDb::NunchukDb;
  void InitSigner(const std::string &name, const Device &device,
                  const std::string &mnemonic);
  void InitSignerMasterXprv(const std::string &name, const Device &device,
                            const std::string &master_xprv);
  void MaybeMigrate();
  void DeleteSigner();
  void DeleteSoftwareSigner();
  bool SetName(const std::string &value);
  bool SetTags(const std::vector<SignerTag> &value);
  bool SetVisible(bool value);
  bool SetLastHealthCheck(time_t value);
  bool SetSignerType(SignerType value);
  bool SetNeedBackup(bool value);
  bool AddXPub(const std::string &path, const std::string &xpub,
               const std::string &type);
  bool AddXPub(const WalletType &wallet_type, const AddressType &address_type,
               int index, const std::string &xpub);
  bool UseIndex(const WalletType &wallet_type, const AddressType &address_type,
                int index, bool used = true);
  std::string GetXpub(const std::string &path);
  std::string GetXpub(const WalletType &wallet_type,
                      const AddressType &address_type, int index);
  int GetUnusedIndex(const WalletType &wallet_type,
                     const AddressType &address_type);
  int GetLastUsedIndex(const WalletType &wallet_type,
                       const AddressType &address_type);
  int GetCachedIndex(const WalletType &wallet_type,
                     const AddressType &address_type);
  bool IsNeedBackup() const;
  std::string GetFingerprint() const;
  std::string GetDeviceModel() const;
  std::string GetDeviceType() const;
  std::string GetName() const;
  std::vector<SignerTag> GetTags() const;
  bool IsVisible() const;
  time_t GetLastHealthCheck() const;
  std::vector<SingleSigner> GetSingleSigners(bool usedOnly = true) const;
  bool IsMaster() const;
  bool IsSoftware(const std::string &passphrase) const;
  void InitRemote();
  bool AddRemote(const std::string &name, const std::string &xpub,
                 const std::string &public_key,
                 const std::string &derivation_path, bool used = false,
                 SignerType signer_type = SignerType::AIRGAP,
                 std::vector<SignerTag> tags = {});
  SingleSigner GetRemoteSigner(const std::string &derivation_path) const;
  bool DeleteRemoteSigner(const std::string &derivation_path);
  bool UseRemote(const std::string &derivation_path);
  bool SetRemoteName(const std::string &derivation_path,
                     const std::string &value);
  bool SetRemoteLastHealthCheck(const std::string &derivation_path,
                                time_t value);
  std::vector<SingleSigner> GetRemoteSigners() const;
  SignerType GetSignerType() const;
  SoftwareSigner GetSoftwareSigner(const std::string &passphrase) const;
  std::string GetMnemonic(const std::string &passphrase) const;
  std::string GetMasterXprv() const;
  bool HasMnemonic() const;
  bool HasMasterXprv() const;

 private:
  bool UpdateSignerType(SignerType signer_type);
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_SIGNERDB_H
