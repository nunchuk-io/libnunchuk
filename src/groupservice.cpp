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
#include <descriptor.h>
#include <boost/algorithm/string.hpp>

using json = nlohmann::json;

namespace nunchuk {

static const std::string MIME_TYPE = "application/json";

GroupService::GroupService(const std::string& baseUrl,
                const std::string& ephemeralPub,
                const std::string& ephemeralPriv,
                const std::string& deviceToken) 
  : baseUrl_(baseUrl), ephemeralPub_(ephemeralPub), ephemeralPriv_(ephemeralPriv), deviceToken_(deviceToken) {}

std::string GroupService::RegisterDevice(
  const std::string& osName,
  const std::string& osVersion,
  const std::string& appVersion,
  const std::string& deviceClass,
  const std::string& deviceId
){
  std::string url = "/v1.1/shared-wallets/devices/register";
  std::string body = "{}";
  httplib::Headers headers = {
    {"X-NC-OS-NAME", osName},
    {"X-NC-OS-VERSION", osVersion},
    {"X-NC-APP-VERSION", appVersion},
    {"X-NC-DEVICE-CLASS", deviceClass},
    {"X-NC-DEVICE-ID", deviceId},
  };
  httplib::Client client(baseUrl_.c_str());
  client.enable_server_certificate_verification(false);
  auto res = client.Post(url.c_str(), headers, (const char *)body.data(),
                         body.size(), MIME_TYPE.c_str());
  if (!res || res->status != 200) {
    throw NunchukException(
        NunchukException::SERVER_REQUEST_ERROR,
        res ? res->body : "Server error");
  }
  deviceToken_ = json::parse(res->body)["data"]["device_token"];
  return deviceToken_;
}

json GetHttpResponseData(const std::string& resp) {
  std::cout << "resp " << resp<< std::endl;
  json parsed = json::parse(resp);
  if (parsed["error"] != nullptr) {
    throw NunchukException(
        NunchukException::SERVER_REQUEST_ERROR,
        parsed["error"]["message"]); 
  }
  return parsed["data"];
}

SandboxGroup ParseGroup(const json& group, const std::string& pub, const std::string& priv) {
  SandboxGroup rs(group["id"]);
  rs.set_finalized(group["status"] == "ACTIVE");
  json info = rs.is_finalized() ? group["finalize"] : group["init"];
  rs.set_state_id(info["stateId"]);

  json config = nullptr;
  std::vector<std::string> keys{};
  for (auto& [key, value] : info["state"].items()) {
    if (key == pub) {
      if (!value.get<std::string>().empty()) {
        config = json::parse(rsa::Decrypt(priv, value));
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

SandboxGroup GroupService::ParseGroupResult(const std::string& resp) {
  json data = GetHttpResponseData(resp);
  json group = data["group"];
  return ParseGroup(group, ephemeralPub_, ephemeralPriv_);
}

std::string GroupService::GroupToEvent(const SandboxGroup& group, const std::string type) {
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
      throw NunchukException(NunchukException::INVALID_PARAMETER, "Invalid wallet id");
    }
    plaintext["pubkey"] = group.get_pubkey();
    plaintext["walletId"] = group.get_wallet_id();
  }

  json state{};
  for (auto&& ephemeralKey : group.get_ephemeral_keys()) {
    state[ephemeralKey] = rsa::Encrypt(ephemeralKey, plaintext.dump());
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

SandboxGroup GroupService::CreateGroup(int m, int n, AddressType addressType, const SingleSigner& signer) {
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
  return ParseGroupResult(rs);
}

SandboxGroup GroupService::GetGroup(const std::string& groupId) {
  std::string url = std::string("/v1.1/shared-wallets/groups/") + groupId;
  std::string rs = Get(url);
  return ParseGroupResult(rs);
}

std::vector<SandboxGroup> GroupService::GetGroups() {
  std::string url = "/v1.1/shared-wallets/groups?page=0&page_size=100";
  json data = GetHttpResponseData(Get(url));
  json groups = data["groups"];
  std::vector<SandboxGroup> rs{};
  for (auto&& group : groups) {
    rs.push_back(ParseGroup(group, ephemeralPub_, ephemeralPriv_));
  }
  return rs;
}

SandboxGroup GroupService::JoinGroup(const std::string& groupId) {
  std::string url = std::string("/v1.1/shared-wallets/groups/") + groupId;
  json data = GetHttpResponseData(Get(url));
  json group = data["group"];
  if (group["status"] == "ACTIVE") {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR, "Group finalized"); 
  }
  if (group["init"]["state"][ephemeralPub_] != nullptr) {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR, "Already joined"); 
  }
  group["init"]["state"][ephemeralPub_] = "";
  group["init"]["stateId"] = group["init"]["stateId"].get<int>() + 1;
  json event = {
    {"group_id", groupId},
    {"type", "init"},
    {"data", group["init"]},
  };
  std::string body = event.dump();
  std::string rs = Post("/v1.1/shared-wallets/groups/join", {body.begin(), body.end()});
  Post( "/v1.1/shared-wallets/events/send", {body.begin(), body.end()});
  return ParseGroupResult(rs);
}

SandboxGroup GroupService::UpdateGroup(const SandboxGroup& group) {
  if (group.get_m() <= 0 || group.get_n() <= 0 || group.get_m() > group.get_n()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, "Invalid m/n");
  }
  if (group.is_finalized() && group.get_signers().size() != group.get_n()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, "Invalid signers");
  }
  std::string url = "/v1.1/shared-wallets/events/send";
  std::string body = GroupToEvent(group, group.is_finalized() ? "finalize" : "init");
  std::string rs = Post(url, {body.begin(), body.end()});
  return group;
}

void GroupService::ListenEvents(std::function<bool(const std::string&)> callback) {
  httplib::Headers headers = {{"Device-Token", deviceToken_}};
  httplib::Client client(baseUrl_.c_str());
  client.enable_server_certificate_verification(false);
  
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
  client.Get("/v1.1/shared-wallets/events/sse", headers, 
    [&](const char* data, size_t data_length) {
      buffer.append(data, data_length);
      size_t pos;
      while ((pos = buffer.find("\n\n")) != std::string::npos) {
        std::string_view event_data = std::string_view(buffer).substr(0, pos);
        handle_event(event_data);
        buffer.erase(0, pos + 2);
      }
      return true;
    });
}

std::string GroupService::Post(const std::string &url,
                               const std::vector<unsigned char> &body) {
  httplib::Headers headers = {{"Device-Token", deviceToken_}};
  httplib::Client client(baseUrl_.c_str());
  client.enable_server_certificate_verification(false);
  auto res = client.Post(url.c_str(), headers, (const char *)body.data(),
                         body.size(), MIME_TYPE.c_str());
  if (!res || res->status != 200) {
    throw NunchukException(
        NunchukException::SERVER_REQUEST_ERROR,
        res ? res->body : "Server error");
  }
  return res->body;
}

std::string GroupService::Get(const std::string &url) {
  httplib::Headers headers = {{"Device-Token", deviceToken_}};
  httplib::Client client(baseUrl_.c_str());
  client.enable_server_certificate_verification(false);
  auto res = client.Get(url.c_str(), headers);
  if (!res || res->status != 200) {
    throw NunchukException(
        NunchukException::SERVER_REQUEST_ERROR,
        res ? res->body : "Server error");
  }
  return res->body;
}

}
