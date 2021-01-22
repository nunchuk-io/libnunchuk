// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coreutils.h"

#include <embeddedrpc.h>
#include <utils/json.hpp>
#include <utils/addressutils.hpp>
#include <iostream>

using json = nlohmann::json;
namespace nunchuk {

static std::string GetChainString(Chain chain) {
  switch (chain) {
    case Chain::MAIN:
      return "main";
    case Chain::TESTNET:
      return "test";
    case Chain::REGTEST:
      return "regtest";
  }
  throw NunchukException(NunchukException::INVALID_CHAIN, "unknown chain");
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
    throw RPCException(RPCException::RPC_REQUEST_ERROR, "send request error");
  }
  json rs = json::parse(resp);
  if (rs["error"] != nullptr) {
    int code = rs["error"]["code"];
    std::string message = rs["error"]["message"];
    throw RPCException(code - 3000, message.c_str());
  }
  return rs["result"];
}

std::string CoreUtils::CombinePsbt(const std::vector<std::string> psbts) {
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
                           "psbt incomplete");
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

std::string CoreUtils::CreatePsbt(const std::vector<TxInput> vin,
                                  const std::vector<TxOutput> vout) {
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

std::string CoreUtils::DeriveAddresses(const std::string &descriptor,
                                       int index) {
  json params = index >= 0
                    ? json::array({descriptor, json::array({index, index})})
                    : json::array({descriptor});
  json req = {
      {"method", "deriveaddresses"}, {"params", params}, {"id", "placeholder"}};
  std::string resp = EmbeddedRpc::getInstance().SendRequest(req.dump());
  return ParseResponse(resp)[0];
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