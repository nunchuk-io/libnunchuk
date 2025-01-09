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
#include <kernel/chainparams.h>  // IWYU pragma: export
#include <common/url.h>

// required for util/translation.h
const std::function<std::string(const char *)> G_TRANSLATION_FUN = nullptr;

EmbeddedRpc::EmbeddedRpc() {}

EmbeddedRpc::~EmbeddedRpc() {}

void EmbeddedRpc::Init(const std::string &chain) {
  static std::once_flag flag;
  static ECC_Context ecc_context{};
  std::call_once(flag, [&] {
    ECC_InitSanityCheck();
    chain_ = chain;
    SelectParams(ChainTypeFromString(chain).value());
    RegisterAllCoreRPCCommands(table_);
    SetRPCWarmupFinished();
    initialized_ = true;
  });
}

void EmbeddedRpc::SetChain(const std::string &chain) {
  if (!initialized_) throw std::runtime_error("uninitialized");
  if (chain_ == chain) return;
  chain_ = chain;
  SelectParams(ChainTypeFromString(chain).value());
}

const std::string &EmbeddedRpc::GetChain() const {
  if (!initialized_) throw std::runtime_error("uninitialized");
  return chain_;
}

std::string EmbeddedRpc::SendRequest(const std::string &body) const {
  if (!initialized_) throw std::runtime_error("uninitialized");
  JSONRPCRequest req;
  UniValue val_request;
  val_request.read(body);
  req.parse(val_request);
  try {
    auto resp = table_.execute(req);
    return JSONRPCReplyObj(std::move(resp), NullUniValue, req.id, JSONRPCVersion::V2).write();
  } catch (const UniValue &err) {
    return JSONRPCReplyObj(NullUniValue, err, req.id, JSONRPCVersion::V2).write();
  }
}

EmbeddedRpc &EmbeddedRpc::getInstance() {
  static EmbeddedRpc instance;
  return instance;
}
