/*
 * This file is part of the Nunchuk software (https://nunchuk.io/)
 * Copyright (C) 2022, 2023 Nunchuk
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "groupservice.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <utils/httplib.h>
#include <utils/json.hpp>
#include <utils/secretbox.h>
#include <utils/stringutils.hpp>
#include <utils/enumconverter.hpp>
#include <descriptor.h>
#include <boost/algorithm/string.hpp>
#include <coreutils.h>

using json = nlohmann::json;

namespace nunchuk {

static const std::string MIME_TYPE = "application/json";
static const std::string SECRET_PATH = "m/83696968'/128169'/32'/0'";
static const std::string KEYPAIR_PATH = "m/83696968'/128169'/32'/0'";

json GetHttpResponseData(const std::string& resp) {
  // std::cout << "resp " << resp << std::endl;
  json parsed = json::parse(resp);
  if (parsed["error"] != nullptr) {
    if (parsed["error"]["code"] == 5404) {
      throw GroupException(GroupException::WALLET_NOT_FOUND,
                           parsed["error"]["message"]);
    }
    throw GroupException(GroupException::SERVER_REQUEST_ERROR,
                         parsed["error"]["message"]);
  }
  return parsed["data"];
}

GroupService::GroupService(const std::string& baseUrl) : baseUrl_(baseUrl) {}

GroupService::GroupService(const std::string& baseUrl,
                           const std::string& ephemeralPub,
                           const std::string& ephemeralPriv,
                           const std::string& deviceToken,
                           const std::string& uid)
    : baseUrl_(baseUrl),
      ephemeralPub_(ephemeralPub),
      ephemeralPriv_(ephemeralPriv),
      deviceToken_(deviceToken),
      uid_(uid) {}

void GroupService::SetEphemeralKey(const std::string& pub,
                                   const std::string priv) {
  ephemeralPub_ = pub;
  ephemeralPriv_ = priv;
}

void GroupService::SetDeviceInfo(const std::string& token,
                                 const std::string uid) {
  deviceToken_ = token;
  uid_ = uid;
}

void GroupService::SetAccessToken(const std::string& token) {
  accessToken_ = token;
}

std::pair<std::string, std::string> GroupService::ParseUrl(
    const std::string& group_url) {
  std::string url = "/v1.1/shared-wallets/url/parse";
  std::string body = json({{"url", group_url}}).dump();
  json data = GetHttpResponseData(Post(url, {body.begin(), body.end()}));
  return {data["group_id"], data["redirect_url"]};
}

GroupConfig GroupService::GetConfig() {
  std::string url = "/v1.1/shared-wallets/configs";
  json data = GetHttpResponseData(Get(url));
  GroupConfig rs{};
  rs.set_total(data["total"]);
  rs.set_remain(data["remaining"]);
  json limits = data["address_key_limits"];
  for (auto&& limit : limits) {
    rs.set_max_keys(AddressTypeFromStr(limit["address_type"]),
                    limit["max_keys"]);
  }
  return rs;
}

std::pair<std::string, std::string> GroupService::RegisterDevice(
    const std::string& osName, const std::string& osVersion,
    const std::string& appVersion, const std::string& deviceClass,
    const std::string& deviceId) {
  std::string url = "/v1.1/shared-wallets/devices/register";
  std::string body = "{}";
  std::string auth = (std::string("Bearer ") + accessToken_);
  httplib::Headers headers = {
      {"X-NC-OS-NAME", osName},         {"X-NC-OS-VERSION", osVersion},
      {"X-NC-APP-VERSION", appVersion}, {"X-NC-DEVICE-CLASS", deviceClass},
      {"X-NC-DEVICE-ID", deviceId},     {"Authorization", auth},
  };
  httplib::Client client(baseUrl_.c_str());
  client.enable_server_certificate_verification(false);
  auto res = client.Post(url.c_str(), headers, (const char*)body.data(),
                         body.size(), MIME_TYPE.c_str());
  if (!res || res->status != 200) {
    throw GroupException(GroupException::SERVER_REQUEST_ERROR,
                         res ? res->body : "Server error");
  }
  auto data = GetHttpResponseData(res->body);
  deviceToken_ = data["device_token"];
  uid_ = data["uid"];
  return {deviceToken_, uid_};
}

GroupSandbox GroupService::ParseGroupData(const std::string& groupId,
                                          bool finalized,
                                          const nlohmann::json& info) {
  GroupSandbox rs(groupId);
  rs.set_finalized(finalized);
  rs.set_state_id(info["stateId"]);

  json config = nullptr;
  std::vector<std::string> keys{};
  for (auto& [key, value] : info["state"].items()) {
    if (key == ephemeralPub_) {
      if (!value.get<std::string>().empty()) {
        config =
            json::parse(Publicbox(ephemeralPub_, ephemeralPriv_).Open(value));
      }
    } else if (value.get<std::string>().empty()) {
      rs.set_need_broadcast(true);
    }
    keys.push_back(key);
  }
  if (config == nullptr) {
    rs.set_need_broadcast(false);
    return rs;
  }

  std::vector<SingleSigner> signers{};
  for (auto& item : config["signers"]) {
    signers.push_back(ParseSignerString(item));
  }
  rs.set_name(config["name"]);
  rs.set_m(config["m"]);
  rs.set_n(config["n"]);
  rs.set_address_type(AddressType(config["addressType"]));
  rs.set_signers(signers);
  rs.set_ephemeral_keys(keys);
  if (rs.is_finalized()) {
    rs.set_pubkey(config["pubkey"]);
    rs.set_wallet_id(config["walletId"]);
  }
  return rs;
}

GroupSandbox GroupService::ParseGroup(const json& group) {
  bool finalized = group["status"] == "ACTIVE";
  auto rs = ParseGroupData(group["id"], finalized,
                           finalized ? group["finalize"] : group["init"]);
  rs.set_url(group["url"]);
  return rs;
}

GroupSandbox GroupService::ParseGroupResponse(const std::string& resp) {
  json data = GetHttpResponseData(resp);
  json group = data["group"];
  return ParseGroup(group);
}

std::string GroupService::GroupToEvent(const GroupSandbox& group,
                                       const std::string& type) {
  json signers = json::array();
  for (auto&& signer : group.get_signers()) {
    if (!signer.get_master_fingerprint().empty()) {
      signers.push_back(signer.get_descriptor());
    }
  }
  json plaintext = {
      {"m", group.get_m()},
      {"n", group.get_n()},
      {"addressType", group.get_address_type()},
      {"signers", signers},
      {"name", group.get_name()},
  };

  if (group.is_finalized()) {
    if (group.get_pubkey().empty() || group.get_wallet_id().empty()) {
      throw GroupException(GroupException::INVALID_PARAMETER,
                           "Invalid wallet id");
    }
    plaintext["pubkey"] = group.get_pubkey();
    plaintext["walletId"] = group.get_wallet_id();
  }

  json state{};
  for (auto&& ephemeralKey : group.get_ephemeral_keys()) {
    state[ephemeralKey] = Publicbox(ephemeralPub_, ephemeralPriv_)
                              .Box(plaintext.dump(), ephemeralKey);
  }
  json data = {
      {"version", 1},
      {"stateId", group.get_state_id() + 1},
      {"state", state},
  };
  if (group.is_finalized()) {
    data["wallet_id"] =
        group.get_pubkey();  // we use pubkey as server wallet id
  }
  json body = {
      {"group_id", group.get_id()},
      {"type", type},
      {"data", data},
  };
  return body.dump();
}

GroupMessage GroupService::ParseMessageData(const std::string& id,
                                            const std::string& walletGid,
                                            const nlohmann::json& data) {
  std::string walletId = GetWalletIdFromGid(walletGid);
  GroupMessage rs(id, walletId);
  auto walletSigner = walletSigner_.at(walletId);
  if (!CoreUtils::getInstance().VerifyMessage(walletGid, data["sig"],
                                              data["msg"])) {
    throw GroupException(GroupException::INVALID_SIGNATURE, "Invalid message");
  }
  json plaintext = json::parse(walletSigner->DecryptMessage(data["msg"]));
  rs.set_content(plaintext["content"]);
  // TODO: set signer iif plaintext["signature"] is valid
  rs.set_signer(plaintext["signer"]);
  return rs;
}

std::string GroupService::MessageToEvent(const std::string& walletId,
                                         const std::string& content,
                                         const std::string& signer,
                                         const std::string& signature) {
  HasWallet(walletId, true);
  json plaintext = {
      {"content", content},
      {"signer", signer},
      {"signature", signature},
  };
  auto walletSigner = walletSigner_.at(walletId);
  auto msg = walletSigner->EncryptMessage(plaintext.dump());
  auto sig = walletSigner->SignMessage(msg, KEYPAIR_PATH);
  auto wallet_gid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);

  json data = {
      {"version", 1},
      {"msg", msg},
      {"sig", sig},
  };
  json body = {
      {"wallet_id", wallet_gid},
      {"type", "chat"},
      {"data", data},
  };
  return body.dump();
}

std::pair<std::string, std::string> GroupService::ParseTransactionData(
    const std::string& walletGid, const nlohmann::json& data) {
  std::string walletId = GetWalletIdFromGid(walletGid);
  auto walletSigner = walletSigner_.at(walletId);
  if (!CoreUtils::getInstance().VerifyMessage(walletGid, data["sig"],
                                              data["msg"])) {
    throw GroupException(GroupException::INVALID_SIGNATURE, "Invalid message");
  }
  json plaintext = json::parse(walletSigner->DecryptMessage(data["msg"]));
  return {plaintext["psbt"], plaintext["txId"]};
}

std::string GroupService::TransactionToEvent(const std::string& walletId,
                                             const std::string& txId,
                                             const std::string& psbt) {
  HasWallet(walletId, true);
  json plaintext = {{"psbt", psbt}, {"txId", txId}};
  auto walletSigner = walletSigner_.at(walletId);
  auto msg = walletSigner->EncryptMessage(plaintext.dump());
  auto sig = walletSigner->SignMessage(msg, KEYPAIR_PATH);
  auto wallet_gid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);
  auto tx_gid = walletSigner->HashMessage(txId);

  json data = {
      {"version", 1},
      {"msg", msg},
      {"sig", sig},
  };
  json body = {
      {"id", tx_gid},
      {"type", "chat"},
      {"data", data},
  };
  return body.dump();
}

GroupSandbox GroupService::CreateGroup(const std::string& name, int m, int n,
                                       AddressType addressType,
                                       const SingleSigner& signer) {
  if (m <= 0 || n <= 0 || m > n) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid m/n");
  }
  std::string url = "/v1.1/shared-wallets/groups";
  GroupSandbox group("");
  group.set_name(name);
  group.set_m(m);
  group.set_n(n);
  group.set_address_type(addressType);
  group.set_signers({signer});
  group.set_ephemeral_keys({ephemeralPub_});
  std::string body = GroupToEvent(group, "init");
  std::string rs = Post(url, {body.begin(), body.end()});
  return ParseGroupResponse(rs);
}

GroupSandbox GroupService::GetGroup(const std::string& groupId) {
  std::string url = std::string("/v1.1/shared-wallets/groups/") + groupId;
  std::string rs = Get(url);
  return ParseGroupResponse(rs);
}

std::vector<GroupSandbox> GroupService::GetGroups(
    const std::vector<std::string>& groupIds) {
  std::string url =
      std::string("/v1.1/shared-wallets/groups/batch?group_ids=") +
      join(groupIds, ',');
  json data = GetHttpResponseData(Get(url));
  json groups = data["groups"];
  std::vector<GroupSandbox> rs{};
  for (auto&& group : groups) {
    rs.push_back(ParseGroup(group));
  }
  return rs;
}

GroupSandbox GroupService::JoinGroup(const std::string& groupId) {
  std::string url = std::string("/v1.1/shared-wallets/groups/") + groupId;
  json data = GetHttpResponseData(Get(url));
  json group = data["group"];
  if (group["status"] == "ACTIVE") {
    throw GroupException(GroupException::SERVER_REQUEST_ERROR,
                         "Group finalized");
  }
  if (group["init"]["state"][ephemeralPub_] != nullptr) {
    throw GroupException(GroupException::SERVER_REQUEST_ERROR,
                         "Already joined");
  }
  group["init"]["state"][ephemeralPub_] = "";
  group["init"]["stateId"] = group["init"]["stateId"].get<int>() + 1;
  json event = {
      {"group_id", groupId},
      {"type", "init"},
      {"data", group["init"]},
  };
  std::string body = event.dump();
  GetHttpResponseData(
      Post("/v1.1/shared-wallets/events/send", {body.begin(), body.end()}));
  return ParseGroup(group);
}

GroupSandbox GroupService::UpdateGroup(const GroupSandbox& group) {
  if (group.get_m() <= 0 || group.get_n() <= 0 ||
      group.get_m() > group.get_n()) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid m/n");
  }
  if (group.is_finalized() && group.get_signers().size() != group.get_n()) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid signers");
  }
  std::string url = "/v1.1/shared-wallets/events/send";
  auto body = GroupToEvent(group, group.is_finalized() ? "finalize" : "init");
  GetHttpResponseData(Post(url, {body.begin(), body.end()}));
  return group;
}

GroupWalletConfig GroupService::GetWalletConfig(const std::string& walletId) {
  HasWallet(walletId, true);
  auto walletGid = walletSigner_.at(walletId)->GetAddressAtPath(KEYPAIR_PATH);
  std::string url = "/v1.1/shared-wallets/wallets/" + walletGid;
  auto data = GetHttpResponseData(Get(url));
  GroupWalletConfig rs{};
  rs.set_chat_retention_days(data["wallet"]["chat_retention_days"]);
  return rs;
}

void GroupService::SetWalletConfig(const std::string& walletId,
                                   const GroupWalletConfig& config) {
  HasWallet(walletId, true);
  auto walletGid = walletSigner_.at(walletId)->GetAddressAtPath(KEYPAIR_PATH);
  std::string url = "/v1.1/shared-wallets/events/send";
  json data = {{"chat_retention_days", config.get_chat_retention_days()}};
  json postbody = {
      {"wallet_id", walletGid},
      {"type", "update_chat_config"},
      {"data", data},
  };
  std::string body = json(postbody).dump();
  GetHttpResponseData(Post(url, {body.begin(), body.end()}));
}

bool GroupService::CheckWalletExists(const Wallet& wallet) {
  auto walletGid = SoftwareSigner(wallet).GetAddressAtPath(KEYPAIR_PATH);
  std::string url = "/v1.1/shared-wallets/wallets/" + walletGid;
  try {
    auto data = GetHttpResponseData(Get(url));
    return data["wallet"]["status"] == "ACTIVE";
  } catch (GroupException& ne) {
    if (ne.code() != GroupException::WALLET_NOT_FOUND) throw;
    return false;
  }
}

void GroupService::SendMessage(const std::string& walletId,
                               const std::string& content,
                               const std::string& signer,
                               const std::string& signature) {
  std::string url = "/v1.1/shared-wallets/events/send";
  std::string body = MessageToEvent(walletId, content, signer, signature);
  GetHttpResponseData(Post(url, {body.begin(), body.end()}));
}

std::vector<GroupMessage> GroupService::GetMessages(const std::string& walletId,
                                                    int page, int pageSize,
                                                    bool latest) {
  HasWallet(walletId, true);
  auto walletGid = walletSigner_.at(walletId)->GetAddressAtPath(KEYPAIR_PATH);
  std::string url = std::string("/v1.1/shared-wallets/wallets/") + walletGid +
                    "/chat?page=" + std::to_string(page) +
                    "&page_size=" + std::to_string(pageSize) + "&sort=desc";
  json data = GetHttpResponseData(Get(url));
  json events = data["events"];
  std::vector<GroupMessage> rs{};
  for (auto&& event : events) {
    json payload = event["payload"];
    json data = payload["data"];
    auto message = ParseMessageData(event["id"], payload["wallet_id"], data);
    message.set_ts(event["timestamp_ms"].get<int64_t>() / 1000);
    message.set_sender(event["uid"]);
    rs.push_back(message);
  }
  return rs;
}

void GroupService::StartListenEvents(
    std::function<bool(const std::string&)> callback) {
  std::string auth = (std::string("Bearer ") + accessToken_);
  httplib::Headers headers = {{"Device-Token", deviceToken_},
                              {"Authorization", auth},
                              {"Accept", "text/event-stream"}};
  httplib::Client client(baseUrl_.c_str());
  client.enable_server_certificate_verification(false);
  client.set_read_timeout(std::chrono::hours(24));

  auto handle_event = [&](std::string_view event_data) {
    size_t data_pos = event_data.find("data:");
    if (data_pos == std::string::npos) return;
    size_t data_start = data_pos + 5;
    size_t data_end = event_data.find('\n', data_start);
    if (data_end == std::string::npos) data_end = event_data.size();

    std::string_view raw = event_data.substr(data_start, data_end - data_start);
    if (raw == "ping") return;

    try {
      callback({raw.begin(), raw.end()});
    } catch (...) {
      // ignore error
    }
  };

  std::string buffer;
  stop_ = false;
  client.Get("/v1.1/shared-wallets/events/sse", headers,
             [&](const char* data, size_t data_length) {
               buffer.append(data, data_length);
               size_t pos;
               while ((pos = buffer.find("\n\n")) != std::string::npos) {
                 std::string_view event_data =
                     std::string_view(buffer).substr(0, pos);
                 handle_event(event_data);
                 buffer.erase(0, pos + 2);
               }
               return !stop_;
             });
}

void GroupService::StopListenEvents() { stop_ = true; }

void GroupService::Subscribe(const std::vector<std::string>& groupIds,
                             const std::vector<std::string>& walletIds) {
  std::string url = "/v1.1/shared-wallets/events/subscribe";
  json ids = json::array();
  for (auto&& id : groupIds) {
    ids.push_back({{"group_id", id}, {"from_ts_ms", 0}});
  }
  for (auto&& id : walletIds) {
    HasWallet(id, true);
    auto gid = walletSigner_.at(id)->GetAddressAtPath(KEYPAIR_PATH);
    ids.push_back({{"wallet_id", gid}, {"from_ts_ms", 0}});
  }
  json sub = {{"sub", ids}};
  std::string body = sub.dump();
  GetHttpResponseData(Post(url, {body.begin(), body.end()}));
}

std::string GroupService::Post(const std::string& url,
                               const std::vector<unsigned char>& body) {
  std::string auth = (std::string("Bearer ") + accessToken_);
  httplib::Headers headers = {{"Device-Token", deviceToken_},
                              {"Authorization", auth}};
  httplib::Client client(baseUrl_.c_str());
  client.enable_server_certificate_verification(false);
  auto res = client.Post(url.c_str(), headers, (const char*)body.data(),
                         body.size(), MIME_TYPE.c_str());
  if (!res || res->status != 200) {
    throw GroupException(GroupException::SERVER_REQUEST_ERROR,
                         res ? res->body : "Server error");
  }
  return res->body;
}

std::string GroupService::Get(const std::string& url) {
  std::string auth = (std::string("Bearer ") + accessToken_);
  httplib::Headers headers = {{"Device-Token", deviceToken_},
                              {"Authorization", auth}};
  httplib::Client client(baseUrl_.c_str());
  client.enable_server_certificate_verification(false);
  auto res = client.Get(url.c_str(), headers);
  if (!res || res->status != 200) {
    throw GroupException(GroupException::SERVER_REQUEST_ERROR,
                         res ? res->body : "Server error");
  }
  return res->body;
}

std::string GroupService::Delete(const std::string& url) {
  std::string auth = (std::string("Bearer ") + accessToken_);
  httplib::Headers headers = {{"Device-Token", deviceToken_},
                              {"Authorization", auth}};
  httplib::Client client(baseUrl_.c_str());
  client.enable_server_certificate_verification(false);
  auto res = client.Delete(url.c_str(), headers);
  if (!res || res->status != 200) {
    throw GroupException(GroupException::SERVER_REQUEST_ERROR,
                         res ? res->body : "Server error");
  }
  return res->body;
}

bool GroupService::HasWallet(const std::string& walletId,
                             bool throwIfNotFound) {
  bool found = walletSigner_.count(walletId) == 1;
  if (!found && throwIfNotFound) {
    throw GroupException(GroupException::WALLET_NOT_FOUND, "Wallet not found");
  }
  return found;
}

std::string GroupService::GetWalletIdFromGid(const std::string& walletGid) {
  std::string walletId = walletGid2Id_[walletGid];
  if (walletId.empty()) {
    throw GroupException(GroupException::WALLET_NOT_FOUND, "Wallet not found");
  }
  return walletId;
}

std::string GroupService::GetTxIdFromGid(const std::string& walletId,
                                         const std::string& txGid) {
  HasWallet(walletId, true);
  auto walletGid = walletSigner_.at(walletId)->GetAddressAtPath(KEYPAIR_PATH);
  std::string url = std::string("/v1.1/shared-wallets/wallets/") + walletGid +
                    "/transactions/" + txGid;
  auto data = GetHttpResponseData(Get(url));
  return ParseTransactionData(walletGid, data).second;
}

std::string GroupService::GetTransaction(const std::string& walletId,
                                         const std::string& txGid) {
  HasWallet(walletId, true);
  auto walletGid = walletSigner_.at(walletId)->GetAddressAtPath(KEYPAIR_PATH);
  std::string url = std::string("/v1.1/shared-wallets/wallets/") + walletGid +
                    "/transactions/" + txGid;
  auto data = GetHttpResponseData(Get(url));
  return ParseTransactionData(walletGid, data).first;
}

void GroupService::UpdateTransaction(const std::string& walletId,
                                     const std::string& txId,
                                     const std::string& psbt) {
  HasWallet(walletId, true);
  auto walletGid = walletSigner_.at(walletId)->GetAddressAtPath(KEYPAIR_PATH);
  std::string url = std::string("/v1.1/shared-wallets/wallets/") + walletGid +
                    "/transactions";
  std::string body = TransactionToEvent(walletId, txId, psbt);
  GetHttpResponseData(Post(url, {body.begin(), body.end()}));
}

void GroupService::DeleteTransaction(const std::string& walletId,
                                     const std::string& txId) {
  HasWallet(walletId, true);
  auto walletGid = walletSigner_.at(walletId)->GetAddressAtPath(KEYPAIR_PATH);
  auto txGid = walletSigner_.at(walletId)->HashMessage(txId);
  std::string url = std::string("/v1.1/shared-wallets/wallets/") + walletGid +
                    "/transactions/" + txGid;
  GetHttpResponseData(Delete(url));
}

std::string GroupService::SetupKey(const Wallet& wallet) {
  if (!HasWallet(wallet.get_id())) {
    walletSigner_[wallet.get_id()] = std::make_shared<SoftwareSigner>(wallet);
    walletSigner_.at(wallet.get_id())->SetupBoxKey(SECRET_PATH);
  }
  auto gid = walletSigner_.at(wallet.get_id())->GetAddressAtPath(KEYPAIR_PATH);
  walletGid2Id_[gid] = wallet.get_id();
  return gid;
}

}  // namespace nunchuk
