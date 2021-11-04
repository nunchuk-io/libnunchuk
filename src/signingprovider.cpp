// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <embeddedrpc.h>

#include "signingprovider.h"
#include <univalue.h>
#include <rpc/util.h>

SigningProviderCache::SigningProviderCache() {}

SigningProviderCache::~SigningProviderCache() {}

SigningProviderCache &SigningProviderCache::getInstance() {
  static SigningProviderCache instance;
  return instance;
}

bool SigningProviderCache::GetKeyOrigin(const CKeyID &keyid,
                                        KeyOriginInfo &info) {
  for (auto &&p : providers_) {
    if (p.second.GetKeyOrigin(keyid, info)) return true;
  }
  return false;
}

FlatSigningProvider SigningProviderCache::GetProvider(const std::string &desc) {
  if (!providers_.count(desc)) {
    FlatSigningProvider provider;
    UniValue uv;
    uv.read(desc);
    auto descs = uv.get_array();
    for (size_t i = 0; i < descs.size(); ++i) {
      EvalDescriptorStringOrObject(descs[i], provider);
    }
    providers_[desc] = provider;
  }
  return providers_[desc];
}

void SigningProviderCache::PreCalculate(const std::string &desc) {
  if (marker_.count(desc) || providers_.count(desc)) return;
  marker_[desc] = true;
  runner_.push_back(
      std::async(std::launch::async, [this, desc] { GetProvider(desc); }));
}