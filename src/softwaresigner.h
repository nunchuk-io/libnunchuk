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

#ifndef NUNCHUK_SOFTWARESIGNER_H
#define NUNCHUK_SOFTWARESIGNER_H

#include <nunchuk.h>
#include <storage/localdb.h>

#include <string>
#include <vector>
#include <key.h>

namespace nunchuk {

class SoftwareSigner {
 public:
  static std::string GenerateMnemonic(int words);
  static bool CheckMnemonic(const std::string& mnemonic);
  static std::vector<std::string> GetBIP39WordList();

  SoftwareSigner(const std::string& mnemonic, const std::string& passphrase);
  SoftwareSigner(const std::string& master_xprv);
  SoftwareSigner(const Wallet& group_wallet);
  CExtKey GetExtKeyAtPath(const std::string& derivation_path) const;
  std::string GetXpubAtPath(const std::string& derivation_path) const;
  std::string GetAddressAtPath(const std::string& derivation_path) const;
  std::string GetMasterFingerprint() const;
  std::string SignTx(const std::string& base64_psbt) const;
  std::string SignTaprootTx(const NunchukLocalDb& db,
                            const std::string& base64_psbt,
                            const Wallet& wallet,
                            int external_index, int internal_index);
  std::string SignMessage(const std::string& message,
                          const std::string& derivation_path) const;

  void SetupBoxKey(const std::string& path);
  std::string HashMessage(const std::string& message);
  std::string EncryptMessage(const std::string& plaintext);
  std::string DecryptMessage(const std::string& ciphertext);

 private:
  static std::mutex* mu_;
  CExtKey GetBip32RootKey(const std::string& mnemonic,
                          const std::string& passphrase) const;
  CExtKey bip32rootkey_;
  std::vector<uint8_t> boxKey_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_SOFTWARESIGNER_H
