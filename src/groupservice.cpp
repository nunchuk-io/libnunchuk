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
#include <utils/rsa.hpp>
#include <utils/stringutils.hpp>
#include <utils/enumconverter.hpp>
#include <descriptor.h>
#include <boost/algorithm/string.hpp>

using json = nlohmann::json;

namespace nunchuk {

static const std::string MIME_TYPE = "application/json";

json GetHttpResponseData(const std::string& resp) {
  // std::cout << "resp " << resp<< std::endl;
  json parsed = json::parse(resp);
  if (parsed["error"] != nullptr) {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
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
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           res ? res->body : "Server error");
  }
  auto data = GetHttpResponseData(res->body);
  deviceToken_ = data["device_token"];
  uid_ = data["uid"];
  return {deviceToken_, uid_};
}

SandboxGroup GroupService::ParseGroupData(const std::string& groupId,
                                          bool finalized,
                                          const nlohmann::json& info) {
  SandboxGroup rs(groupId);
  rs.set_finalized(finalized);
  rs.set_state_id(info["stateId"]);

  json config = nullptr;
  std::vector<std::string> keys{};
  for (auto& [key, value] : info["state"].items()) {
    if (key == ephemeralPub_) {
      if (!value.get<std::string>().empty()) {
        config = json::parse(
            rsa::EnvelopeOpen(ephemeralPub_, ephemeralPriv_, value));
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

SandboxGroup GroupService::ParseGroup(const json& group) {
  bool finalized = group["status"] == "ACTIVE";
  auto rs = ParseGroupData(group["id"], finalized,
                           finalized ? group["finalize"] : group["init"]);
  rs.set_url(group["url"]);
  return rs;
}

SandboxGroup GroupService::ParseGroupResponse(const std::string& resp) {
  json data = GetHttpResponseData(resp);
  json group = data["group"];
  return ParseGroup(group);
}

std::string GroupService::GroupToEvent(const SandboxGroup& group,
                                       const std::string& type) {
  json signers = json::array();
  for (auto&& signer : group.get_signers()) {
    signers.push_back(signer.get_descriptor());
  }
  json plaintext = {
      {"m", group.get_m()},
      {"n", group.get_n()},
      {"addressType", group.get_address_type()},
      {"signers", signers},
  };

  if (group.is_finalized()) {
    if (group.get_pubkey().empty() || group.get_wallet_id().empty()) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid wallet id");
    }
    plaintext["pubkey"] = group.get_pubkey();
    plaintext["walletId"] = group.get_wallet_id();
  }

  json state{};
  for (auto&& ephemeralKey : group.get_ephemeral_keys()) {
    state[ephemeralKey] = rsa::EnvelopeSeal(ephemeralKey, plaintext.dump());
  }
  json data = {
      {"version", 1},
      {"stateId", group.get_state_id() + 1},
      {"state", state},
  };
  json body = {
      {"group_id", group.get_id()},
      {"type", type},
      {"data", data},
  };
  return body.dump();
}

GroupMessage GroupService::ParseMessageData(const std::string& id,
                                            const std::string& groupId,
                                            const nlohmann::json& data) {
  GroupMessage rs(id, groupId);
  // TODO: decrypt data using groupId pubkey
  rs.set_content(data["msg"]);
  return rs;
}

std::string GroupService::MessageToEvent(const std::string& groupId,
                                         const std::string& msg) {
  json data = {
      {"version", 1},
      {"msg", msg},
  };
  // TODO: encrypt data using groupId pubkey
  json body = {
      {"group_id", groupId},
      {"type", "chat"},
      {"data", data},
  };
  return body.dump();
}

SandboxGroup GroupService::CreateGroup(int m, int n, AddressType addressType,
                                       const SingleSigner& signer) {
  if (m <= 0 || n <= 0 || m > n) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, "Invalid m/n");
  }
  std::string url = "/v1.1/shared-wallets/groups";
  SandboxGroup group("");
  group.set_m(m);
  group.set_n(n);
  group.set_address_type(addressType);
  if (!signer.get_master_fingerprint().empty()) group.set_signers({signer});
  group.set_ephemeral_keys({ephemeralPub_});
  std::string body = GroupToEvent(group, "init");
  std::string rs = Post(url, {body.begin(), body.end()});
  return ParseGroupResponse(rs);
}

SandboxGroup GroupService::GetGroup(const std::string& groupId) {
  std::string url = std::string("/v1.1/shared-wallets/groups/") + groupId;
  std::string rs = Get(url);
  return ParseGroupResponse(rs);
}

std::vector<SandboxGroup> GroupService::GetGroups(
    const std::vector<std::string>& groupIds) {
  std::string url =
      std::string("/v1.1/shared-wallets/groups/batch?group_ids=") +
      join(groupIds, ',');
  json data = GetHttpResponseData(Get(url));
  json groups = data["groups"];
  std::vector<SandboxGroup> rs{};
  for (auto&& group : groups) {
    rs.push_back(ParseGroup(group));
  }
  return rs;
}

SandboxGroup GroupService::JoinGroup(const std::string& groupId) {
  std::string url = std::string("/v1.1/shared-wallets/groups/") + groupId;
  json data = GetHttpResponseData(Get(url));
  json group = data["group"];
  if (group["status"] == "ACTIVE") {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           "Group finalized");
  }
  if (group["init"]["state"][ephemeralPub_] != nullptr) {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
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

SandboxGroup GroupService::UpdateGroup(const SandboxGroup& group) {
  if (group.get_m() <= 0 || group.get_n() <= 0 ||
      group.get_m() > group.get_n()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, "Invalid m/n");
  }
  if (group.is_finalized() && group.get_signers().size() != group.get_n()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid signers");
  }
  std::string url = "/v1.1/shared-wallets/events/send";
  std::string body =
      GroupToEvent(group, group.is_finalized() ? "finalize" : "init");
  GetHttpResponseData(Post(url, {body.begin(), body.end()}));
  return group;
}

void GroupService::SendMessage(const std::string& groupId,
                               const std::string& msg) {
  std::string url = "/v1.1/shared-wallets/events/send";
  std::string body = MessageToEvent(groupId, msg);
  GetHttpResponseData(Post(url, {body.begin(), body.end()}));
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
    ids.push_back({{"wallet_id", id}, {"from_ts_ms", 0}});
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
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
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
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           res ? res->body : "Server error");
  }
  return res->body;
}

}  // namespace nunchuk
