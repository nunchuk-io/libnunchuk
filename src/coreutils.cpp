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

CoreUtils &CoreUtils::getInstance() {
  static CoreUtils instance;
  return instance;
}

CoreUtils::CoreUtils() { EmbeddedRpc::getInstance().Init(); }

void CoreUtils::SetChain(Chain chain) {
  EmbeddedRpc::getInstance().SetChain(GetChainString(chain));
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
  json req = {{"method", "combinepsbt"},
              {"params", json::array({json(psbts)})},
              {"id", "placeholder"}};
  std::string resp = EmbeddedRpc::getInstance().SendRequest(req.dump());
  return ParseResponse(resp);
}

std::string CoreUtils::FinalizePsbt(const std::string &combined) {
  json req = {{"method", "finalizepsbt"},
              {"params", json::array({combined, true})},
              {"id", "placeholder"}};
  std::string resp = EmbeddedRpc::getInstance().SendRequest(req.dump());
  json rs = ParseResponse(resp);
  if (!rs["complete"]) {
    throw NunchukException(NunchukException::PSBT_INCOMPLETE,
                           "Psbt incomplete");
  }
  return rs["hex"];
}

std::string CoreUtils::DecodeRawTransaction(const std::string &raw_tx) {
  json req = {{"method", "decoderawtransaction"},
              {"params", json::array({raw_tx})},
              {"id", "placeholder"}};
  std::string resp = EmbeddedRpc::getInstance().SendRequest(req.dump());
  return ParseResponse(resp).dump();
}

std::string CoreUtils::CreatePsbt(const std::vector<TxInput> &vin,
                                  const std::vector<TxOutput> &vout) {
  json input = json::array();
  for (auto &el : vin) {
    input.push_back({{"txid", el.first}, {"vout", el.second}});
  }
  json output = json::array();
  for (auto &el : vout) {
    output.push_back({{el.first, Utils::ValueFromAmount(el.second)}});
  }
  json params = json::array({input,   // inputs
                             output,  // ouputs
                             0,       // locktime
                             true});  // replaceable
  json req = {
      {"method", "createpsbt"}, {"params", params}, {"id", "placeholder"}};
  std::string resp = EmbeddedRpc::getInstance().SendRequest(req.dump());
  return ParseResponse(resp);
}

std::string CoreUtils::DecodePsbt(const std::string &base64_psbt) {
  json req = {{"method", "decodepsbt"},
              {"params", json::array({base64_psbt})},
              {"id", "placeholder"}};
  std::string resp = EmbeddedRpc::getInstance().SendRequest(req.dump());
  return ParseResponse(resp).dump();
}

std::string CoreUtils::DeriveAddress(const std::string &descriptor, int index) {
  json params = index >= 0
                    ? json::array({descriptor, json::array({index, index})})
                    : json::array({descriptor});
  json req = {
      {"method", "deriveaddresses"}, {"params", params}, {"id", "placeholder"}};
  std::string resp = EmbeddedRpc::getInstance().SendRequest(req.dump());
  return ParseResponse(resp)[0];
}

std::vector<std::string> CoreUtils::DeriveAddresses(
    const std::string &descriptor, int fromIndex, int toIndex) {
  json params = json::array({descriptor, json::array({fromIndex, toIndex})});
  json req = {
      {"method", "deriveaddresses"}, {"params", params}, {"id", "placeholder"}};
  std::string resp = EmbeddedRpc::getInstance().SendRequest(req.dump());
  return ParseResponse(resp);
}

bool CoreUtils::VerifyMessage(const std::string &address,
                              const std::string &signature,
                              const std::string &message) {
  json params = json::array({address, signature, message});
  json req = {
      {"method", "verifymessage"}, {"params", params}, {"id", "placeholder"}};
  std::string resp = EmbeddedRpc::getInstance().SendRequest(req.dump());
  return ParseResponse(resp);
}

}  // namespace nunchuk
