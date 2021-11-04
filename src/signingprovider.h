// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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

  static SigningProviderCache &getInstance();
  SigningProviderCache(SigningProviderCache const &) = delete;
  void operator=(SigningProviderCache const &) = delete;

 private:
  SigningProviderCache();
  ~SigningProviderCache();

  std::map<std::string, bool> marker_;
  std::map<std::string, FlatSigningProvider> providers_;
  std::vector<std::future<void>> runner_;
};

#endif  // NUNCHUK_SIGNINGPROVIDER_H
