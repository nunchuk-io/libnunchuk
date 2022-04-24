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

#ifndef NUNCHUK_HWISERVICE_H
#define NUNCHUK_HWISERVICE_H

#include <nunchuk.h>

#include <memory>
#include <string>
#include <vector>

namespace nunchuk {

//! Interface for handling HWI function
class HWIService {
 public:
  HWIService(std::string path = "hwi", Chain chain = Chain::TESTNET);

  void SetPath(const std::string &path);
  void SetChain(Chain chain);
  std::vector<Device> Enumerate() const;
  std::string GetXpubAtPath(const Device &device,
                            const std::string derivation_path) const;
  std::string GetMasterFingerprint(const Device &device) const;
  std::string SignTx(const Device &device,
                     const std::string &base64_psbt) const;
  std::string SignMessage(const Device &device, const std::string &message,
                          const std::string &derivation_path) const;
  std::string DisplayAddress(const Device &device,
                             const std::string &desc) const;
  void PromptPin(const Device &device) const;
  void SendPin(const Device &device, const std::string &pin) const;
  void SendPassphrase(const Device &device,
                      const std::string &passphrase) const;

 private:
  void CheckVersion();
  std::string RunCmd(const std::vector<std::string> &) const;
  std::string hwi_;
  Chain chain_;
  int version_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_HWISERVICE_H
