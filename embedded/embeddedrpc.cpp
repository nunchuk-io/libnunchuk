// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "embeddedrpc.h"

#include <chainparams.h>
#include <pubkey.h>
#include <validation.h>

// required for util/translation.h
const std::function<std::string(const char *)> G_TRANSLATION_FUN = nullptr;

// required for validation.h
static const ECCVerifyHandle verify_handle;

EmbeddedRpc::EmbeddedRpc() {}

void EmbeddedRpc::Init(const std::string &chain) {
  static std::once_flag flag;
  std::call_once(flag, [&] {
    chain_ = chain;
    SelectParams(chain);
    RegisterMiscRPCCommands(table_);
    RegisterRawTransactionRPCCommands(table_);
    SetRPCWarmupFinished();
    initialized_ = true;
  });
}

void EmbeddedRpc::SetChain(const std::string &chain) {
  if (!initialized_) throw std::runtime_error("uninitialized");
  if (chain_ == chain) return;
  chain_ = chain;
  SelectParams(chain_);
}

std::string EmbeddedRpc::SendRequest(const std::string &body) const {
  if (!initialized_) throw std::runtime_error("uninitialized");
  JSONRPCRequest req(context_ref_);
  UniValue val_request;
  val_request.read(body);
  req.parse(val_request);
  try {
    auto resp = table_.execute(req);
    return JSONRPCReply(resp, NullUniValue, req.id);
  } catch (const UniValue &err) {
    return JSONRPCReply(NullUniValue, err, req.id);
  }
}

EmbeddedRpc &EmbeddedRpc::getInstance() {
  static EmbeddedRpc instance;
  return instance;
}
