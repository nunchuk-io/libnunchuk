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
  std::shared_lock<std::shared_mutex> lock(access_);
  for (auto &&p : providers_) {
    if (p.second.get().GetKeyOrigin(keyid, info)) return true;
  }
  return false;
}

FlatSigningProvider Eval(const std::string &desc) {
  FlatSigningProvider provider;
  UniValue uv;
  uv.read(desc);
  auto descs = uv.get_array();
  for (size_t i = 0; i < descs.size(); ++i) {
    EvalDescriptorStringOrObject(descs[i], provider);
  }
  return provider;
}

FlatSigningProvider SigningProviderCache::GetProvider(const std::string &desc) {
  if (!providers_.count(desc)) PreCalculate(desc);
  return providers_[desc].get();
}

void SigningProviderCache::PreCalculate(const std::string &desc) {
  std::unique_lock<std::shared_mutex> lock(access_);
  if (providers_.count(desc)) return;
  providers_[desc] = std::async(std::launch::async, Eval, desc);
}

void SigningProviderCache::SetMaxIndex(const std::string &wallet_id, int idx) {
  if (max_index_.count(wallet_id) && max_index_[wallet_id] > idx) return;
  max_index_[wallet_id] = idx;
}

int SigningProviderCache::GetMaxIndex(const std::string &wallet_id) {
  if (max_index_.count(wallet_id)) return max_index_[wallet_id];
  return 100;
}
