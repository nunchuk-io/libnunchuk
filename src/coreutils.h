// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_COREUTILS_H
#define NUNCHUK_COREUTILS_H

#include <nunchuk.h>

namespace nunchuk {

class CoreUtils {
 public:
  void SetChain(Chain chain);
  std::string CombinePsbt(const std::vector<std::string> psbts);
  std::string FinalizePsbt(const std::string &combined);
  std::string DecodeRawTransaction(const std::string &raw_tx);
  std::string CreatePsbt(const std::vector<TxInput> vin,
                         const std::vector<TxOutput> vout);
  std::string DecodePsbt(const std::string &base64_psbt);
  std::string DeriveAddresses(const std::string &descriptor, int index = -1);
  bool VerifyMessage(const std::string &address, const std::string &signature,
                     const std::string &message);

  static CoreUtils &getInstance();
  CoreUtils(CoreUtils const &) = delete;
  void operator=(CoreUtils const &) = delete;

 private:
  CoreUtils();
};

}  // namespace nunchuk

#endif  // NUNCHUK_COREUTILS_H
