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

#include "embeddedrpc.h"

#include <chainparams.h>
#include <pubkey.h>
#include <validation.h>

// required for util/translation.h
const std::function<std::string(const char *)> G_TRANSLATION_FUN = nullptr;

// required for validation.h
static const ECCVerifyHandle verify_handle;

EmbeddedRpc::EmbeddedRpc() {}

EmbeddedRpc::~EmbeddedRpc() { ECC_Stop(); }

void EmbeddedRpc::Init(const std::string &chain) {
  static std::once_flag flag;
  std::call_once(flag, [&] {
    ECC_Start();
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
  JSONRPCRequest req;
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
