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

#include "coreutils.h"

#include <embeddedrpc.h>
#include <utils/json.hpp>
#include <utils/addressutils.hpp>
#include <utils/errorutils.hpp>
#include <iostream>

using json = nlohmann::json;
namespace nunchuk {

static std::string GetChainString(Chain chain) {
  switch (chain) {
    case Chain::MAIN:
      return "main";
    case Chain::TESTNET:
      return "test";
    case Chain::SIGNET:
      return "signet";
    case Chain::REGTEST:
      return "regtest";
  }
  throw NunchukException(NunchukException::INVALID_CHAIN, "Unknown chain");
}

static Chain GetStringChain(const std::string &chain) {
  if (chain == "main") {
    return Chain::MAIN;
  }
  if (chain == "test") {
    return Chain::TESTNET;
  }
  if (chain == "signet") {
    return Chain::SIGNET;
  }
  if (chain == "regtest") {
    return Chain::REGTEST;
  }
  throw NunchukException(NunchukException::INVALID_CHAIN, "Unknown chain");
}

CoreUtils &CoreUtils::getInstance() {
  static CoreUtils instance;
  return instance;
}

CoreUtils::CoreUtils() { EmbeddedRpc::getInstance().Init(); }

std::string CoreUtils::SendRequest(const std::string &method,
                                   const json &params) {
  json req = {{"method", method}, {"params", params}, {"id", "placeholder"}};
  return EmbeddedRpc::getInstance().SendRequest(req.dump());
}

void CoreUtils::SetChain(Chain chain) {
  EmbeddedRpc::getInstance().SetChain(GetChainString(chain));
}

Chain CoreUtils::GetChain() const {
  return GetStringChain(EmbeddedRpc::getInstance().GetChain());
}

static json ParseResponse(const std::string &resp) {
  if (resp.empty()) {
    throw RPCException(RPCException::RPC_REQUEST_ERROR, "Send request error");
  }

  try {
    json rs = json::parse(resp);
    if (rs["error"] != nullptr) {
      int code = rs["error"]["code"];
      throw RPCException(code - 3000,
                         NormalizeErrorMessage(rs["error"]["message"]));
    }
    return rs["result"];
  } catch (json::exception &se) {
    throw RPCException(RPCException::RPC_DESERIALIZATION_ERROR,
                       NormalizeErrorMessage(se.what()));
  }
}

std::string CoreUtils::CombinePsbt(const std::vector<std::string> &psbts) {
  std::string resp = SendRequest("combinepsbt", json::array({json(psbts)}));
  return ParseResponse(resp);
}

std::string CoreUtils::FinalizePsbt(const std::string &combined) {
  std::string resp = SendRequest("finalizepsbt", json::array({combined, true}));
  json rs = ParseResponse(resp);
  if (!rs["complete"]) {
    throw NunchukException(NunchukException::PSBT_INCOMPLETE,
                           "Psbt incomplete");
  }
  return rs["hex"];
}

std::string CoreUtils::DecodeRawTransaction(const std::string &raw_tx) {
  std::string resp = SendRequest("decoderawtransaction", json::array({raw_tx}));
  return ParseResponse(resp).dump();
}

std::string CoreUtils::CreatePsbt(const std::vector<TxInput> &vin,
                                  const std::vector<TxOutput> &vout,
                                  uint32_t locktime) {
  json inputs = json::array();
  for (auto &el : vin) {
    json input = {{"txid", el.txid}, {"vout", el.vout}};
    if (el.nSequence > 0) {
      input["sequence"] = el.nSequence;
    }
    inputs.push_back(input);
  }
  json outputs = json::array();
  for (auto &el : vout) {
    outputs.push_back({{el.first, Utils::ValueFromAmount(el.second)}});
  }
  json params = json::array({inputs, outputs, locktime, true});  // replaceable
  std::string resp = SendRequest("createpsbt", params);
  return ParseResponse(resp);
}

std::string CoreUtils::DecodePsbt(const std::string &base64_psbt) {
  std::string resp = SendRequest("decodepsbt", json::array({base64_psbt}));
  return ParseResponse(resp).dump();
}

std::string CoreUtils::DeriveAddress(const std::string &descriptor, int index) {
  json params = index >= 0
                    ? json::array({descriptor, json::array({index, index})})
                    : json::array({descriptor});
  std::string resp = SendRequest("deriveaddresses", params);
  return ParseResponse(resp)[0];
}

std::vector<std::string> CoreUtils::DeriveAddresses(
    const std::string &descriptor, int fromIndex, int toIndex) {
  json params = json::array({descriptor, json::array({fromIndex, toIndex})});
  std::string resp = SendRequest("deriveaddresses", params);
  return ParseResponse(resp);
}

bool CoreUtils::VerifyMessage(const std::string &address,
                              const std::string &signature,
                              const std::string &message) {
  json params = json::array({address, signature, message});
  std::string resp = SendRequest("verifymessage", params);
  return ParseResponse(resp);
}

}  // namespace nunchuk
