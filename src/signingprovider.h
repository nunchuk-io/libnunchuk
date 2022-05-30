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

#ifndef NUNCHUK_SIGNINGPROVIDER_H
#define NUNCHUK_SIGNINGPROVIDER_H

#include <string>
#include <map>
#include <vector>
#include <future>
#include <script/signingprovider.h>

class SigningProviderCache {
 public:
  bool GetKeyOrigin(const CKeyID &keyid, KeyOriginInfo &info);
  FlatSigningProvider GetProvider(const std::string &desc);
  void PreCalculate(const std::string &desc);
  void SetMaxIndex(const std::string &wallet_id, int idx);
  int GetMaxIndex(const std::string &wallet_id);

  static SigningProviderCache &getInstance();
  SigningProviderCache(SigningProviderCache const &) = delete;
  void operator=(SigningProviderCache const &) = delete;

 private:
  SigningProviderCache();
  ~SigningProviderCache();

  std::map<std::string, bool> marker_;
  std::map<std::string, FlatSigningProvider> providers_;
  std::vector<std::future<void>> runner_;
  std::map<std::string, int> max_index_;
};

#endif  // NUNCHUK_SIGNINGPROVIDER_H
