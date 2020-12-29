// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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

 private:
  std::string RunCmd(const std::vector<std::string> &) const;
  std::string hwi_;
  bool testnet_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_HWISERVICE_H
