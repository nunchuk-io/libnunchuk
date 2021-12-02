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

#include <backend/corerpc/client.h>
#include <utils/loguru.hpp>
#include "httplib5.h"
#include <util/strencodings.h>
#include <utils/json.hpp>

#include <iostream>

using json = nlohmann::json;

namespace nunchuk {

static json ParseResponse(const std::string& resp) {
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

std::string CoreRpcClient::SendRequest(const std::string& path,
                                       const std::string& body) {
  std::string auth = (std::string("Basic ") + EncodeBase64(user_ + ":" + pw_));
  httplib5::Headers headers = {{"Authorization", auth}};
  httplib5::Client cli(host_, port_);

  auto res = cli.Post(path.c_str(), headers, body, "text/plain");
  if (res) {
    return res->body;
  }
  return "";
}

CoreRpcClient::CoreRpcClient(const AppSettings& appsettings) {
  host_ = appsettings.get_corerpc_host();
  port_ = appsettings.get_corerpc_port();
  user_ = appsettings.get_corerpc_username();
  pw_ = appsettings.get_corerpc_password();
  name_ = "nunchuk";
}

CoreRpcClient::~CoreRpcClient() {}

void CoreRpcClient::Broadcast(const std::string& raw_tx) {
  json req = {{"method", "sendrawtransaction"},
              {"params", json::array({raw_tx})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/wallet/" + name_, req.dump());
  ParseResponse(resp);
}

Amount CoreRpcClient::EstimateFee(int conf_target) {
  json req = {{"method", "estimatesmartfee"},
              {"params", json::array({conf_target})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/", req.dump());
  json rs = ParseResponse(resp);
  return Utils::AmountFromValue(rs["feerate"].dump());
}

Amount CoreRpcClient::RelayFee() {
  json req = {{"method", "getmempoolinfo"},
              {"params", json::array({})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/", req.dump());
  json rs = ParseResponse(resp);
  return Utils::AmountFromValue(rs["minrelaytxfee"].dump());
}

json CoreRpcClient::GetBlockchainInfo() {
  json req = {{"method", "getblockchaininfo"},
              {"params", json::array({})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/", req.dump());
  return ParseResponse(resp);
}

void CoreRpcClient::ImportDescriptors(const std::string& descriptors) {
  json options = {{"rescan", true}};
  json req = {{"method", "importmulti"},
              {"params", json::array({json::parse(descriptors), options})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/wallet/" + name_, req.dump());
  json rs = ParseResponse(resp);
  for (auto& el : rs.items()) {
    if (!el.value()["success"]) {
      throw std::runtime_error("import descriptors fail");
    }
  }
}

json CoreRpcClient::GetWalletInfo() {
  json req = {{"method", "getwalletinfo"},
              {"params", json::array({})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/wallet/" + name_, req.dump());
  return ParseResponse(resp);
}

json CoreRpcClient::GetAddressInfo(const std::string& address) {
  json req = {{"method", "getaddressinfo"},
              {"params", json::array({address})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/wallet/" + name_, req.dump());
  return ParseResponse(resp);
}

void CoreRpcClient::CreateWallet() {
  json req = {{"method", "createwallet"},
              {"params", json::array({name_, true, true, "", false})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/", req.dump());
  json rs = ParseResponse(resp);
  if (rs["name"] != name_) {
    throw std::runtime_error("create wallet error");
  }
}

void CoreRpcClient::LoadWallet() {
  json req = {{"method", "loadwallet"},
              {"params", json::array({name_})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/", req.dump());
  json rs = ParseResponse(resp);
  if (rs["name"] != name_) {
    throw std::runtime_error("load wallet error");
  }
}

void CoreRpcClient::RescanBlockchain(int start_height, int stop_height) {
  json params = stop_height > 0 ? json::array({start_height, stop_height})
                                : json::array({start_height});
  json req = {{"method", "rescanblockchain"},
              {"params", params},
              {"id", "placeholder"}};
  SendRequest("/wallet/" + name_, req.dump());
}

json CoreRpcClient::ListTransactions() {
  json req = {{"method", "listtransactions"},
              {"params", json::array({"*", 1000, 0, true})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/wallet/" + name_, req.dump());
  return ParseResponse(resp);
}

json CoreRpcClient::GetTransaction(const std::string& tx_id) {
  json req = {{"method", "gettransaction"},
              {"params", json::array({tx_id, true, true})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/wallet/" + name_, req.dump());
  return ParseResponse(resp);
}

json CoreRpcClient::ListUnspent() {
  json req = {{"method", "listunspent"},
              {"params", json::array({})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/wallet/" + name_, req.dump());
  return ParseResponse(resp);
}

}  // namespace nunchuk