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
  std::string DeriveAddress(const std::string &descriptor, int index = -1);
  std::vector<std::string> DeriveAddresses(const std::string &descriptor,
                                           int fromIndex, int toIndex);
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
