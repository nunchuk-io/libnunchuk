// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_SOFTWARESIGNER_H
#define NUNCHUK_SOFTWARESIGNER_H

#include <nunchuk.h>

#include <string>
#include <vector>
#include <key.h>

namespace nunchuk {

class SoftwareSigner {
 public:
  static std::string GenerateMnemonic();
  static bool CheckMnemonic(const std::string& mnemonic);
  static std::vector<std::string> GetBip39WordList();

  SoftwareSigner(const std::string& mnemonic);
  CExtKey GetExtKeyAtPath(const std::string& derivation_path) const;
  std::string GetXpubAtPath(const std::string& derivation_path) const;
  std::string GetMasterFingerprint() const;
  std::string SignTx(const std::string& base64_psbt) const;
  std::string SignMessage(const std::string& message,
                          const std::string& derivation_path) const;

 private:
  CExtKey GetBip32RootKey(const std::string& mnemonic) const;
  CExtKey bip32rootkey_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_SOFTWARESIGNER_H
