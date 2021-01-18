// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcclient.h"
#include <utils/loguru.hpp>
#include <utils/httplib.h>
#include <util/strencodings.h>
#include <utils/json.hpp>

#include <iostream>

using json = nlohmann::json;

namespace nunchuk {

static json ParseResponse(const std::string& resp) {
  if (resp.empty()) {
    throw RPCException(RPCException::RPC_REQUEST_ERROR, "send request error");
  }
  std::cout << resp << std::endl;
  json rs = json::parse(resp);
  if (rs["error"] != nullptr) {
    int code = rs["error"]["code"];
    std::string message = rs["error"]["message"];
    throw RPCException(3000 + code, message.c_str());
  }
  return rs["result"];
}

std::string RpcClient::SendRequest(const std::string& path,
                                   const std::string& body) {
  httplib::Client cli(host_, port_);
  httplib::Headers headers = {
      {"Authorization",
       (std::string("Basic ") + EncodeBase64(user_ + ":" + pw_)).c_str()}};

  auto res = cli.Post(path.c_str(), headers, body, "text/plain");
  if (res) {
    return res->body;
  }
  return "";
}

RpcClient::RpcClient(const AppSettings& appsettings) {
  user_ = "electrumx";
  pw_ = "iKC4xhLw92ny2NJjm9N8t0kk_F5aKA2VFelT2azc3C8=";
  host_ = "18.141.210.87";
  port_ = 18332;
  name_ = "nunchuk";
}

RpcClient::~RpcClient() {}

void RpcClient::Broadcast(const std::string& raw_tx) {
  json req = {{"method", "sendrawtransaction"},
              {"params", json::array({raw_tx})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/wallet/" + name_, req.dump());
  ParseResponse(resp);
}

Amount RpcClient::EstimateFee(int conf_target) {
  json req = {{"method", "estimatesmartfee"},
              {"params", json::array({conf_target})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/", req.dump());
  if (resp.empty()) {
    throw std::runtime_error("send rpc request error");
  }
  json rs = ParseResponse(resp);
  return Utils::AmountFromValue(rs["feerate"].dump());
}

Amount RpcClient::RelayFee() {
  json req = {{"method", "getmempoolinfo"},
              {"params", json::array({})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/", req.dump());
  if (resp.empty()) {
    throw std::runtime_error("send rpc request error");
  }
  json rs = ParseResponse(resp);
  return Utils::AmountFromValue(rs["minrelaytxfee"].dump());
}

int RpcClient::GetChainTip() {
  json req = {{"method", "getblockchaininfo"},
              {"params", json::array({})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/", req.dump());
  if (resp.empty()) {
    throw std::runtime_error("send rpc request error");
  }
  json rs = ParseResponse(resp);
  return rs["blocks"].get<int>();
}

void RpcClient::ImportDescriptors(const std::string& descriptors) {
  json options = {{"rescan", true}};
  json req = {{"method", "importmulti"},
              {"params", json::array({json::parse(descriptors), options})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/wallet/" + name_, req.dump());
  if (resp.empty()) {
    throw std::runtime_error("send rpc request error");
  }
  json rs = ParseResponse(resp);
  for (auto& el : rs.items()) {
    if (!el.value()["success"]) {
      throw std::runtime_error("import descriptors fail");
    }
  }
}

void RpcClient::GetWalletInfo() {
  json req = {{"method", "getwalletinfo"},
              {"params", json::array({})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/wallet/" + name_, req.dump());
  json rs = ParseResponse(resp);
}

void RpcClient::CreateWallet() {
  json req = {{"method", "createwallet"},
              {"params", json::array({name_, true, true, "", false})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/", req.dump());
  json rs = ParseResponse(resp);
  if (rs["name"] != name_) {
    throw std::runtime_error("create wallet error");
  }
}

void RpcClient::LoadWallet() {
  json req = {{"method", "loadwallet"},
              {"params", json::array({name_})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/", req.dump());
  json rs = ParseResponse(resp);
  if (rs["name"] != name_) {
    throw std::runtime_error("load wallet error");
  }
}

void RpcClient::ListTransactions() {
  json req = {{"method", "listtransactions"},
              {"params", json::array({"*", 1000, 0, true})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/wallet/" + name_, req.dump());
  json rs = ParseResponse(resp);
}

void RpcClient::GetTransaction(const std::string& tx_id) {
  json req = {{"method", "gettransaction"},
              {"params", json::array({tx_id, true, true})},
              {"id", "placeholder"}};
  std::string resp = SendRequest("/wallet/" + name_, req.dump());
  json rs = ParseResponse(resp);
}

void RpcClient::ListUnspent() {}

}  // namespace nunchuk