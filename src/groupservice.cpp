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
  bool finalized = group["status"] == "ACTIVE";
  json info = finalized ? group["finalize"] : group["init"];

  json config = nullptr;
  std::vector<std::string> keys{};
  for (auto& [key, value] : info["state"].items()) {
    if (key == pub) {
      config = json::parse(rsa::Decrypt(priv, value));
    }
    keys.push_back(key);
  }
  if (config == nullptr) return { group["id"] };

  std::vector<SingleSigner> signers{};
  for (auto& item : config["signers"]) {
    signers.push_back(ParseSignerString(item));
  }

  return {
    group["id"], config["m"], config["n"],
    AddressType(config["addressType"]),
    signers, finalized, keys, info["stateId"]
  };
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
  std::string url = "/v1.1/shared-wallets/groups";
  SandboxGroup group("", m, n, addressType, {signer}, false, {ephemeralPub_}, 0);
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
