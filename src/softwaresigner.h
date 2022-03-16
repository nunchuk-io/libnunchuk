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

#include <string>
#include <vector>
#include <key.h>

namespace nunchuk {

class SoftwareSigner {
 public:
  static std::string GenerateMnemonic();
  static bool CheckMnemonic(const std::string& mnemonic);
  static std::vector<std::string> GetBIP39WordList();

  SoftwareSigner(const std::string& mnemonic, const std::string& passphrase);
  CExtKey GetExtKeyAtPath(const std::string& derivation_path) const;
  std::string GetXpubAtPath(const std::string& derivation_path) const;
  std::string GetMasterFingerprint() const;
  std::string SignTx(const std::string& base64_psbt) const;
  std::string SignTaprootTx(const std::string& base64_psbt,
                            const std::vector<std::string>& keypaths) const;
  std::string SignMessage(const std::string& message,
                          const std::string& derivation_path) const;

 private:
  CExtKey GetBip32RootKey(const std::string& mnemonic,
                          const std::string& passphrase) const;
  CExtKey bip32rootkey_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_SOFTWARESIGNER_H
