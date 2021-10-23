// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
  void DeleteSigner();
  bool SetName(const std::string &value);
  bool SetLastHealthCheck(time_t value);
  bool AddXPub(const std::string &path, const std::string &xpub,
               const std::string &type);
  bool AddXPub(const WalletType &wallet_type, const AddressType &address_type,
               int index, const std::string &xpub);
  bool UseIndex(const WalletType &wallet_type, const AddressType &address_type,
                int index);
  std::string GetXpub(const std::string &path);
  std::string GetXpub(const WalletType &wallet_type,
                      const AddressType &address_type, int index);
  int GetUnusedIndex(const WalletType &wallet_type,
                     const AddressType &address_type);
  int GetCachedIndex(const WalletType &wallet_type,
                     const AddressType &address_type);
  std::string GetFingerprint() const;
  std::string GetDeviceModel() const;
  std::string GetDeviceType() const;
  std::string GetName() const;
  time_t GetLastHealthCheck() const;
  std::vector<SingleSigner> GetSingleSigners(bool usedOnly = true) const;
  bool IsMaster() const;
  void InitRemote();
  bool AddRemote(const std::string &name, const std::string &xpub,
                 const std::string &public_key,
                 const std::string &derivation_path, bool used = false);
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

 private:
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_SIGNERDB_H
