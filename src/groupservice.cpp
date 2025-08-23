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
#include <chrono>
#include <iterator>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <csignal>

#include <utils/json.hpp>
#include <utils/secretbox.h>
#include <utils/stringutils.hpp>
#include <utils/enumconverter.hpp>
#include <descriptor.h>
#include <boost/algorithm/string.hpp>
#include <coreutils.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_CONNECTION_TIMEOUT_SECOND 5
#define CPPHTTPLIB_READ_TIMEOUT_SECOND 15

#ifdef MSG_NOSIGNAL
#define CPPHTTPLIB_SEND_FLAGS MSG_NOSIGNAL
#endif

#define NDEBUG
#include "utils/httplib.h"

using json = nlohmann::json;

namespace nunchuk {

static const int VERSION = 1;
static const std::string MIME_TYPE = "application/json";
static const std::string SECRET_PATH = "m/83696968'/128169'/32'/0'";
static const std::string KEYPAIR_PATH = "m/45'/0'/0'/1/0";

static json TryParse(const std::string& resp) {
  try {
    return json::parse(resp);
  } catch (json::exception& e) {
    try {
      auto pos = resp.find_last_of("}");
      if (pos != std::string::npos) return json::parse(resp.substr(0, pos + 1));
    } catch (...) {
    }
    throw GroupException(
        GroupException::SERVER_REQUEST_ERROR,
        strprintf(
            "Something went wrong. Please try again.\nError: %s\nResponse: %s",
            e.what(), resp.substr(0, 200)));
  }
}

json GetHttpResponseData(const std::string& resp) {
  // std::cout << "resp " << resp << std::endl;
  json parsed = TryParse(resp);

  if (parsed["error"] != nullptr) {
    std::string msg = parsed["error"]["message"];
    if (parsed["error"]["code"] == 5404) {
      if (msg.rfind("Group", 0) == 0) {
        throw GroupException(GroupException::GROUP_NOT_FOUND, msg);
      } else {
        throw GroupException(GroupException::WALLET_NOT_FOUND, msg);
      }
    }
    throw GroupException(GroupException::SERVER_REQUEST_ERROR, msg);
  }
  return parsed["data"];
}

std::shared_ptr<httplib::Client> MakeClient(const std::string& baseUrl) {
  auto cli = std::make_shared<httplib::Client>(baseUrl.c_str());
  cli->enable_server_certificate_verification(false);
  // cli->set_keep_alive(true);
  return cli;
}

GroupService::GroupService(const std::string& baseUrl) : baseUrl_(baseUrl) {
#ifndef _WIN32
  // `httplib::Client::stop()` may cause SIGPIPE; ignore it here.
  static std::once_flag ignore_sigpipe_flag;
  std::call_once(ignore_sigpipe_flag, [] {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));  // Zero out the struct
    sa.sa_handler = SIG_IGN;     // Ignore SIGPIPE
    sigaction(SIGPIPE, &sa, nullptr);
  });
#endif
  for (auto& cli : http_clients_) {
    cli = MakeClient(baseUrl_);
  }
}

GroupService::GroupService(const std::string& baseUrl,
                           const std::string& ephemeralPub,
                           const std::string& ephemeralPriv,
                           const std::string& deviceToken,
                           const std::string& uid)
    : baseUrl_(baseUrl),
      ephemeralPub_(ephemeralPub),
      ephemeralPriv_(ephemeralPriv),
      deviceToken_(deviceToken),
      uid_(uid) {
  for (auto& cli : http_clients_) {
    cli = MakeClient(baseUrl_);
  }
}

GroupService::~GroupService() {
  StopListenEvents();
  StopHttpClients();
}

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

std::pair<std::string, std::string> GroupService::GetDeviceInfo() {
  return {deviceToken_, uid_};
}

void GroupService::CheckVersion() {
  auto cli = GetClient();
  auto res = cli->Get("/v1.1/shared-wallets/version");
  if (!res || res->status != 200) {
    throw GroupException(GroupException::SERVER_REQUEST_ERROR,
                         res ? res->body : "Server error");
  }
  json data = GetHttpResponseData(res->body);
  int version = data["version"];
  if (version != VERSION) {
    throw GroupException(GroupException::VERSION_MISMATCH,
                         "Group wallet version mismatch. Please make sure all "
                         "devices are on the latest version of Nunchuk.");
  }
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
  rs.set_retention_days_options(data["chat_retention_days_options"]);
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
  auto cli = GetClient();
  auto res = cli->Post(url.c_str(), headers, (const char*)body.data(),
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
                                          bool finalized, const json& info) {
  GroupSandbox rs(groupId);
  rs.set_finalized(finalized);
  rs.set_state_id(info["stateId"]);
  if (auto extra = info.find("extra");
      extra != info.end() && (*extra) != nullptr) {
    rs.set_url((*extra)["url"]);
    if (auto replace_wallet_id = (*extra).find("replace_wallet_id");
        replace_wallet_id != (*extra).end() &&
        (*replace_wallet_id) != nullptr) {
      rs.set_replace_wallet_id(GetWalletIdFromGid(*replace_wallet_id));
    }
  }

  auto config = info["pubstate"];
  if (config["occupied"] != nullptr) {
    for (auto& item : config["occupied"]) {
      rs.add_occupied(item["i"], item["ts"], item["uid"]);
    }
  }
  rs.set_name(config["name"]);
  rs.set_m(config["m"]);
  rs.set_n(config["n"]);
  rs.set_address_type(AddressType(config["addressType"]));
  if (config["walletTemplate"] != nullptr) {
    rs.set_wallet_template(WalletTemplate(config["walletTemplate"]));
  }
  if (config["miniscriptTemplate"] != nullptr) {
    rs.set_miniscript_template(config["miniscriptTemplate"]);
  }

  bool need_broadcast = false;
  json state = nullptr;
  std::vector<std::string> keys{};
  for (auto& [key, value] : info["state"].items()) {
    if (key == ephemeralPub_) {
      if (!value.get<std::string>().empty()) {
        state =
            json::parse(Publicbox(ephemeralPub_, ephemeralPriv_).Open(value));
      }
    } else if (value.get<std::string>().empty()) {
      need_broadcast = true;
    }
    keys.push_back(key);
  }
  rs.set_ephemeral_keys(keys);

  if (state == nullptr) {
    std::vector<SingleSigner> signers{};
    auto mymodified = info["modified"].contains(ephemeralPub_)
                          ? info["modified"][ephemeralPub_]
                          : json::object();
    json msigners = GetModifiedSigners(mymodified, rs.get_n());
    for (auto& item : msigners) {
      std::string desc = item;
      if (desc == "[]") {  // placeholder
        signers.push_back({});
      } else {
        signers.push_back(ParseSignerString(desc));
      }
    }

    std::vector<int> added = config["added"].get<std::vector<int>>();
    for (auto&& i : added) {
      if (signers[i].get_master_fingerprint().empty()) {
        signers[i].set_name("ADDED");
      }
    }
    rs.set_signers(signers);
    return rs;
  }

  // merge modified signers
  for (auto& [key, value] : info["modified"].items()) {
    json msigners = GetModifiedSigners(value, rs.get_n());
    for (int i = 0; i < rs.get_n(); i++) {
      if (state["signers"][i].get<std::string>() == "[]" &&
          msigners[i].get<std::string>() != "[]") {
        state["signers"][i] = msigners[i];
        need_broadcast = true;
      }
    }
  }

  std::vector<SingleSigner> signers{};
  for (auto& item : state["signers"]) {
    std::string desc = item;
    if (desc == "[]") {  // placeholder
      signers.push_back({});
    } else {
      signers.push_back(ParseSignerString(desc));
    }
  }
  rs.set_signers(signers);

  if (rs.is_finalized()) {
    rs.set_pubkey(state["pubkey"]);
    rs.set_wallet_id(state["walletId"]);
  } else if (need_broadcast) {
    json newstate{};
    for (auto&& ephemeralKey : rs.get_ephemeral_keys()) {
      newstate[ephemeralKey] = Publicbox(ephemeralPub_, ephemeralPriv_)
                                   .Box(state.dump(), ephemeralKey);
    }

    config["added"] = json::array();
    for (int i = 0; i < rs.get_n(); i++) {
      if (state["signers"][i].get<std::string>() != "[]") {
        config["added"].push_back(i);
      }
    }
    json data = {
        {"version", VERSION},         {"stateId", rs.get_state_id() + 1},
        {"state", newstate},          {"pubstate", config},
        {"modified", json::object()},
    };
    json event = {
        {"group_id", groupId},
        {"type", "init"},
        {"data", data},
    };
    std::string url = "/v1.1/shared-wallets/events/send";
    std::string body = event.dump();
    GetHttpResponseData(Post(url, {body.begin(), body.end()}));
  }
  return rs;
}

GroupSandbox GroupService::ParseGroup(const json& group) {
  bool finalized = group["status"] == "ACTIVE";
  auto rs = ParseGroupData(group["id"], finalized,
                           finalized ? group["finalize"] : group["init"]);
  rs.set_url(group["url"]);
  if (auto replace_wallet_id = group.find("replace_wallet_id");
      replace_wallet_id != group.end() && (*replace_wallet_id) != nullptr) {
    rs.set_replace_wallet_id(GetWalletIdFromGid(*replace_wallet_id));
  }
  return rs;
}

std::string GroupService::GroupToEvent(const GroupSandbox& group) {
  json signers = json::array();
  for (auto&& signer : group.get_signers()) {
    signers.push_back(signer.get_descriptor());
  }
  json occupied = json::array();
  for (auto&& [i, v] : group.get_occupied()) {
    occupied.push_back({{"i", i}, {"uid", v.second}, {"ts", v.first}});
  }
  json plaintext = {{"signers", signers}};
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
  json added = json::array();
  for (int i = 0; i < group.get_n(); i++) {
    if (!group.get_signers()[i].get_master_fingerprint().empty()) {
      added.push_back(i);
    }
  }
  json pubstate = {
      {"m", group.get_m()},
      {"n", group.get_n()},
      {"addressType", group.get_address_type()},
      {"walletTemplate", group.get_wallet_template()},
      {"miniscriptTemplate", group.get_miniscript_template()},
      {"name", group.get_name()},
      {"occupied", occupied},
      {"added", added},
  };
  json modified = json::object();
  json data = {
      {"version", VERSION},   {"stateId", group.get_state_id() + 1},
      {"state", state},       {"pubstate", pubstate},
      {"modified", modified},
  };
  if (group.is_finalized()) {
    // we use pubkey as server wallet id
    data["wallet_id"] = group.get_pubkey();
  }
  json body = {
      {"group_id", group.get_id()},
      {"type", group.is_finalized() ? "finalize" : "init"},
      {"data", data},
  };
  return body.dump();
}

GroupMessage GroupService::ParseMessageData(const std::string& id,
                                            const std::string& walletGid,
                                            const json& data) {
  auto [walletSigner, walletId] = GetWalletSignerAndWalletIdFromGid(walletGid);
  GroupMessage rs(id, walletId);
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
  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  json plaintext = {
      {"content", content},
      {"signer", signer},
      {"signature", signature},
  };
  auto msg = walletSigner->EncryptMessage(plaintext.dump());
  auto sig = walletSigner->SignMessage(msg, KEYPAIR_PATH);
  auto wallet_gid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);

  json data = {
      {"version", VERSION},
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
    const std::string& walletGid, const json& data) {
  auto [walletSigner, walletId] = GetWalletSignerAndWalletIdFromGid(walletGid);

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
  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  json plaintext = {{"psbt", psbt}, {"txId", txId}};
  auto msg = walletSigner->EncryptMessage(plaintext.dump());
  auto sig = walletSigner->SignMessage(msg, KEYPAIR_PATH);
  auto tx_gid = walletSigner->HashMessage(txId);

  json data = {
      {"version", VERSION},
      {"msg", msg},
      {"sig", sig},
  };
  json body = {
      {"id", tx_gid},
      {"data", data},
  };
  return body.dump();
}

GroupSandbox GroupService::CreateGroup(const std::string& name, int m, int n,
                                       const std::string& script_tmpl,
                                       AddressType addressType) {
  if (!script_tmpl.empty()) {
    n = Utils::ParseSignerNames(script_tmpl, m).size();
  } else if (m <= 0 || n <= 1 || m > n) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid m/n");
  }
  std::vector<SingleSigner> signers(n);

  std::string url = "/v1.1/shared-wallets/groups";
  GroupSandbox group("");
  group.set_name(name);
  group.set_m(m);
  group.set_n(n);
  group.set_address_type(addressType);
  group.set_signers(signers);
  group.set_ephemeral_keys({ephemeralPub_});
  group.set_miniscript_template(script_tmpl);
  std::string body = GroupToEvent(group);
  std::string rs = Post(url, {body.begin(), body.end()});
  return ParseGroup(GetHttpResponseData(rs)["group"]);
}

GroupSandbox GroupService::CreateReplaceGroup(
    const std::string& name, int m, int n, const std::string& script_tmpl,
    AddressType addressType, const std::vector<SingleSigner>& signers,
    const std::string& walletId) {
  if (!script_tmpl.empty()) {
    n = Utils::ParseSignerNames(script_tmpl, m).size();
  } else if (m <= 0 || n <= 1 || m > n) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid m/n");
  }

  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  auto walletGid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);
  std::string url =
      std::string("/v1.1/shared-wallets/wallets/") + walletGid + "/replace";

  GroupSandbox group("");
  group.set_name(name);
  group.set_m(m);
  group.set_n(n);
  group.set_address_type(addressType);
  group.set_signers(signers);
  group.set_ephemeral_keys({ephemeralPub_});
  group.set_miniscript_template(script_tmpl);
  std::string body = GroupToEvent(group);
  std::string rs = Post(url, {body.begin(), body.end()});
  return ParseGroup(GetHttpResponseData(rs)["group"]);
}

std::map<std::string, std::string> GroupService::GetReplaceStatus(
    const std::string& walletId) {
  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  auto walletGid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);
  std::string url = "/v1.1/shared-wallets/wallets/" + walletGid;
  auto wallet = GetHttpResponseData(Get(url))["wallet"];
  std::map<std::string, std::string> rs{};
  if (!wallet.contains("replace_statuses") ||
      wallet["replace_statuses"] == nullptr) {
    return rs;
  }
  for (auto&& item : wallet["replace_statuses"]) {
    rs[item["group_id"]] = item["uid"];
  }
  return rs;
}

GroupSandbox GroupService::GetGroup(const std::string& groupId) {
  return ParseGroup(GetGroupJson(groupId));
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

GroupSandbox GroupService::JoinGroup(const std::string& groupId,
                                     const std::vector<SingleSigner>& signers) {
  json group = CheckGroupSandboxJson(GetGroupJson(groupId), false);
  group["init"]["state"][ephemeralPub_] = "";
  if (!signers.empty()) {
    int n = group["init"]["pubstate"]["n"];
    json jsigners = json::array();
    for (int i = 0; i < n && i < signers.size(); i++) {
      jsigners.push_back(signers[i].get_descriptor());
    }
    json plaintext = {{"signers", jsigners}};
    json modified{};
    for (auto& [key, value] : group["init"]["state"].items()) {
      modified[key] =
          Publicbox(ephemeralPub_, ephemeralPriv_).Box(plaintext.dump(), key);
    }
    group["init"]["modified"][ephemeralPub_] = modified;
  }
  return SendGroupEvent(groupId, group, true);
}

GroupSandbox GroupService::SetOccupied(const std::string& groupId, int index,
                                       bool value) {
  json group = CheckGroupSandboxJson(GetGroupJson(groupId), true, index);
  group["init"]["pubstate"]["occupied"] =
      UpdateOccupiedJson(group["init"]["pubstate"]["occupied"], value, index);
  return SendGroupEvent(groupId, group);
}

GroupSandbox GroupService::SetSigner(const std::string& groupId,
                                     const SingleSigner& signer, int index) {
  json group = CheckGroupSandboxJson(GetGroupJson(groupId), true, index);
  int n = group["init"]["pubstate"]["n"];
  std::string ciphertext = group["init"]["state"][ephemeralPub_];
  if (!ciphertext.empty()) {
    json signers = json::parse(
        Publicbox(ephemeralPub_, ephemeralPriv_).Open(ciphertext))["signers"];

    // merge modified signers
    for (auto& [key, value] : group["init"]["modified"].items()) {
      json msigners = GetModifiedSigners(value, n);
      for (int i = 0; i < n; i++) {
        if (signers[i].get<std::string>() == "[]" &&
            msigners[i].get<std::string>() != "[]") {
          signers[i] = msigners[i];
        }
      }
    }
    group["init"]["modified"] = json::object();

    json plaintext = {
        {"signers", UpdateSignersJson(signers, signer, index, n)}};
    for (auto& [key, value] : group["init"]["state"].items()) {
      group["init"]["state"][key] =
          Publicbox(ephemeralPub_, ephemeralPriv_).Box(plaintext.dump(), key);
    }

    group["init"]["pubstate"]["added"] = json::array();
    for (int i = 0; i < n; i++) {
      if (plaintext["signers"][i].get<std::string>() != "[]") {
        group["init"]["pubstate"]["added"].push_back(i);
      }
    }
  } else {
    json mymodified = group["init"]["modified"].contains(ephemeralPub_)
                          ? group["init"]["modified"][ephemeralPub_]
                          : json::object();
    json signers = GetModifiedSigners(mymodified, n);
    json plaintext = {
        {"signers", UpdateSignersJson(signers, signer, index, n)}};
    json modified{};
    for (auto& [key, value] : group["init"]["state"].items()) {
      modified[key] =
          Publicbox(ephemeralPub_, ephemeralPriv_).Box(plaintext.dump(), key);
    }
    group["init"]["modified"][ephemeralPub_] = modified;
  }
  group["init"]["pubstate"]["occupied"] =
      UpdateOccupiedJson(group["init"]["pubstate"]["occupied"], false, index);
  return SendGroupEvent(groupId, group);
}

GroupSandbox GroupService::UpdateGroup(const std::string& groupId,
                                       const std::string& name, int m, int n,
                                       const std::string& script_tmpl,
                                       AddressType addressType) {
  if (!script_tmpl.empty()) {
    n = Utils::ParseSignerNames(script_tmpl, m).size();
  } else if (m <= 0 || n <= 1 || m > n) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid m/n");
  }
  json group = CheckGroupSandboxJson(GetGroupJson(groupId), true);

  auto curAt = AddressType(group["init"]["pubstate"]["addressType"]);
  auto curScriptTmpl = group["init"]["pubstate"]["miniscriptTemplate"];
  int curN = group["init"]["pubstate"]["n"];
  std::string ciphertext = group["init"]["state"][ephemeralPub_];

  bool shouldClearSigners =
      (curAt != addressType && (curAt == AddressType::TAPROOT ||
                                addressType == AddressType::TAPROOT)) ||
      (curScriptTmpl != script_tmpl);
  if (shouldClearSigners) {
    json signers = json::array();
    for (int i = 0; i < n; i++) {
      signers.push_back("[]");
    }
    json plaintext = {{"signers", signers}};
    for (auto& [key, value] : group["init"]["state"].items()) {
      group["init"]["state"][key] =
          Publicbox(ephemeralPub_, ephemeralPriv_).Box(plaintext.dump(), key);
    }
    group["init"]["modified"] = json::object();
    group["init"]["pubstate"]["added"] = json::array();
  } else if (!ciphertext.empty()) {
    json signers = json::parse(
        Publicbox(ephemeralPub_, ephemeralPriv_).Open(ciphertext))["signers"];

    // merge modified signers
    for (auto& [key, value] : group["init"]["modified"].items()) {
      json msigners = GetModifiedSigners(value, n);
      for (int i = 0; i < curN; i++) {
        if (signers[i].get<std::string>() == "[]" &&
            msigners[i].get<std::string>() != "[]") {
          signers[i] = msigners[i];
        }
      }
    }
    group["init"]["modified"] = json::object();

    // update signers size to n
    json plaintext = {{"signers", UpdateSignersJson(signers, {}, -1, n)}};
    for (auto& [key, value] : group["init"]["state"].items()) {
      group["init"]["state"][key] =
          Publicbox(ephemeralPub_, ephemeralPriv_).Box(plaintext.dump(), key);
    }

    group["init"]["pubstate"]["added"] = json::array();
    for (int i = 0; i < n; i++) {
      if (plaintext["signers"][i].get<std::string>() != "[]") {
        group["init"]["pubstate"]["added"].push_back(i);
      }
    }
  } else {
    json mymodified = group["init"]["modified"].contains(ephemeralPub_)
                          ? group["init"]["modified"][ephemeralPub_]
                          : json::object();
    json signers = GetModifiedSigners(mymodified, n);
    json plaintext = {{"signers", UpdateSignersJson(signers, {}, -1, n)}};
    for (auto& [key, value] : group["init"]["state"].items()) {
      group["init"]["state"][key] =
          Publicbox(ephemeralPub_, ephemeralPriv_).Box(plaintext.dump(), key);
    }
    group["init"]["modified"] = json::object();
    group["init"]["pubstate"]["added"] = json::array();
    for (int i = 0; i < n; i++) {
      if (plaintext["signers"][i].get<std::string>() != "[]") {
        group["init"]["pubstate"]["added"].push_back(i);
      }
    }
  }

  group["init"]["pubstate"]["m"] = m;
  group["init"]["pubstate"]["n"] = n;
  group["init"]["pubstate"]["addressType"] = addressType;
  group["init"]["pubstate"]["miniscriptTemplate"] = script_tmpl;
  group["init"]["pubstate"]["name"] = name;
  return SendGroupEvent(groupId, group);
}

GroupSandbox GroupService::FinalizeGroup(const GroupSandbox& group) {
  if (group.get_wallet_type() != WalletType::MINISCRIPT &&
      (group.get_m() <= 0 || group.get_n() <= 1 ||
       group.get_m() > group.get_n())) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid m/n");
  }
  if (group.get_signers().size() != group.get_n()) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid signers");
  }
  if (!group.is_finalized()) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid state");
  }
  std::string url = "/v1.1/shared-wallets/events/send";
  auto body = GroupToEvent(group);
  GetHttpResponseData(Post(url, {body.begin(), body.end()}));
  return group;
}

void GroupService::DeleteGroup(const std::string& groupId) {
  std::string url = std::string("/v1.1/shared-wallets/groups/") + groupId;
  GetHttpResponseData(Delete(url));
}

GroupWalletConfig GroupService::GetWalletConfig(const std::string& walletId) {
  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  auto walletGid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);
  std::string url = "/v1.1/shared-wallets/wallets/" + walletGid;
  auto wallet = GetHttpResponseData(Get(url))["wallet"];
  GroupWalletConfig rs{};
  rs.set_chat_retention_days(wallet["chat_retention_days"]);
  return rs;
}

void GroupService::SetWalletConfig(const std::string& walletId,
                                   const GroupWalletConfig& config) {
  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  auto walletGid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);
  std::string url = "/v1.1/shared-wallets/events/send";

  json plaintext = {{"ts", std::time(0)},
                    {"chat_retention_days", config.get_chat_retention_days()}};
  auto msg = plaintext.dump();
  auto sig = walletSigner->SignMessage(msg, KEYPAIR_PATH);
  json data = {
      {"version", VERSION},
      {"msg", msg},
      {"sig", sig},
      {"chat_retention_days", config.get_chat_retention_days()},
  };
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

void GroupService::SendChatMessage(const std::string& walletId,
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
  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  auto walletGid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);
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
    std::function<bool(const nlohmann::json&)> callback) {
  auto handle_event = [callback =
                           std::move(callback)](std::string_view event_data) {
    size_t data_pos = event_data.find("data:");
    if (data_pos == std::string::npos) return;
    size_t data_start = data_pos + 5;
    size_t data_end = event_data.find('\n', data_start);
    if (data_end == std::string::npos) data_end = event_data.size();

    std::string_view raw = event_data.substr(data_start, data_end - data_start);
    if (raw == "ping") return;

    try {
      callback(json::parse(raw));
    } catch (...) {
      // ignore error
    }
  };

  if (!stop_) {
    StopListenEvents();
  }

  sse_thread_ = std::thread([&, handle_event = std::move(handle_event)] {
    std::string auth = (std::string("Bearer ") + accessToken_);
    httplib::Headers headers = {{"Device-Token", deviceToken_},
                                {"Authorization", auth},
                                {"Accept", "text/event-stream"}};
    sse_client_ = std::make_unique<httplib::Client>(baseUrl_.c_str());
    sse_client_->enable_server_certificate_verification(false);
    sse_client_->set_read_timeout(std::chrono::hours(24));
    sse_client_->set_keep_alive(true);
    stop_ = false;
    while (!stop_) {
      std::string buffer;
      sse_client_->Get(
          "/v1.1/shared-wallets/events/sse", headers,
          [&](const char* data, size_t data_length) {
            buffer.append(data, data_length);
            size_t pos;
            while ((pos = buffer.find("\n\n")) != std::string::npos) {
              std::string_view event_data =
                  std::string_view(buffer).substr(0, pos);
              if (stop_) break;
              handle_event(event_data);
              buffer.erase(0, pos + 2);
            }
            return !stop_;
          });
      if (stop_) break;
      std::this_thread::sleep_for(std::chrono::seconds(3));
    }
  });
}

void GroupService::StopListenEvents() {
  stop_ = true;
  if (sse_client_) {
    sse_client_->stop();
  }
  if (sse_thread_.joinable()) sse_thread_.join();
  if (sse_client_) {
    sse_client_.reset();
  }
}

void GroupService::StopHttpClients() {
  for (auto& cli : http_clients_) {
    cli->stop();
  }
}

bool GroupService::HasWallet(const std::string& walletId) {
  return GetWalletSignerFromWalletId(walletId, false) != nullptr;
}

std::pair<std::vector<std::string>, std::vector<std::string>>
GroupService::Subscribe(const std::vector<std::string>& groupIds,
                        const std::vector<std::string>& walletIds, bool sync) {
  std::string url = "/v1.1/shared-wallets/events/subscribe";
  json ids = json::array();
  for (auto&& id : groupIds) {
    ids.push_back({{"group_id", id}, {"from_ts_ms", 0}});
  }
  for (auto&& id : walletIds) {
    auto walletSigner = GetWalletSignerFromWalletId(id, false);
    if (walletSigner == nullptr) continue;
    auto gid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);
    ids.push_back({{"wallet_id", gid}, {"from_ts_ms", 0}});
  }
  json sub = {{"sub", ids}, {"sync", sync}};
  std::string body = sub.dump();
  json data = GetHttpResponseData(Post(url, {body.begin(), body.end()}));
  std::vector<std::string> rejectedGroupIds{};
  if (data["rejected_group_ids"] != nullptr) {
    for (auto&& id : data["rejected_group_ids"]) {
      rejectedGroupIds.push_back(id);
    }
  }
  std::vector<std::string> rejectedWalletIds{};
  if (data["rejected_wallet_ids"] != nullptr) {
    for (auto&& gid : data["rejected_wallet_ids"]) {
      auto walletId = GetWalletIdFromGid(gid);
      if (!walletId.empty()) rejectedWalletIds.push_back(walletId);
    }
  }
  return {rejectedGroupIds, rejectedWalletIds};
}

std::string GroupService::Post(const std::string& url,
                               const std::vector<unsigned char>& body) {
  std::string auth = (std::string("Bearer ") + accessToken_);
  httplib::Headers headers = {{"Device-Token", deviceToken_},
                              {"Authorization", auth}};
  auto cli = GetClient();
  auto res = cli->Post(url.c_str(), headers, (const char*)body.data(),
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
  auto cli = GetClient();
  auto res = cli->Get(url.c_str(), headers);
  if (!res || res->status != 200) {
    throw GroupException(GroupException::SERVER_REQUEST_ERROR,
                         res ? res->body : "Server error");
  }
  return res->body;
}

std::string GroupService::Delete(const std::string& url,
                                 const std::vector<unsigned char>& body) {
  std::string auth = (std::string("Bearer ") + accessToken_);
  httplib::Headers headers = {{"Device-Token", deviceToken_},
                              {"Authorization", auth}};
  auto cli = GetClient();
  auto res = body.empty()
                 ? cli->Delete(url.c_str(), headers)
                 : cli->Delete(url.c_str(), headers, (const char*)body.data(),
                               body.size(), MIME_TYPE.c_str());
  if (!res || res->status != 200) {
    throw GroupException(GroupException::SERVER_REQUEST_ERROR,
                         res ? res->body : "Server error");
  }
  return res->body;
}

void GroupService::RecoverWallet(const std::string& walletId) {
  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  auto walletGid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);
  std::string url =
      std::string("/v1.1/shared-wallets/wallets/") + walletGid + "/recover";
  std::string body = "{}";
  GetHttpResponseData(Post(url, {body.begin(), body.end()}));
}

void GroupService::DeleteWallet(const std::string& walletId) {
  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  auto walletGid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);
  std::string url = std::string("/v1.1/shared-wallets/wallets/") + walletGid;
  GetHttpResponseData(Delete(url));
}

std::string GroupService::GetWalletIdFromGid(const std::string& walletGid,
                                             bool throwIfNotFound) {
  std::shared_lock<std::shared_mutex> lock(walletMutex_);
  auto it = walletGid2Id_.find(walletGid);
  if (it != walletGid2Id_.end()) {
    return it->second;
  }
  if (throwIfNotFound) {
    throw GroupException(GroupException::WALLET_NOT_FOUND, "Wallet not found");
  }
  return std::string{};
}

std::string GroupService::GetTxIdFromGid(const std::string& walletId,
                                         const std::string& txGid,
                                         const std::vector<Transaction>& txs) {
  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  for (auto&& tx : txs) {
    if (walletSigner->HashMessage(tx.get_txid()) == txGid) {
      return tx.get_txid();
    }
  }
  return {};
}

std::pair<std::string, std::string> GroupService::GetTransaction(
    const std::string& walletId, const std::string& txGid) {
  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  auto walletGid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);
  std::string url = std::string("/v1.1/shared-wallets/wallets/") + walletGid +
                    "/transactions/" + txGid;
  auto data = GetHttpResponseData(Get(url));
  return ParseTransactionData(walletGid, data["transaction"]["data"]);
}

std::map<std::string, std::string> GroupService::GetTransactions(
    const std::string& walletId, int page, int pageSize, bool latest) {
  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  auto walletGid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);
  std::string url = std::string("/v1.1/shared-wallets/wallets/") + walletGid +
                    "/transactions?page=" + std::to_string(page) +
                    "&page_size=" + std::to_string(pageSize) + "&sort=desc";
  json data = GetHttpResponseData(Get(url));
  json txs = data["transactions"];
  std::map<std::string, std::string> rs{};
  for (auto&& tx : txs) {
    json data = tx["data"];
    auto parsed = ParseTransactionData(walletGid, data);
    rs[parsed.second] = parsed.first;
  }
  return rs;
}

void GroupService::UpdateTransaction(const std::string& walletId,
                                     const std::string& txId,
                                     const std::string& psbt) {
  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  auto walletGid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);
  std::string url = std::string("/v1.1/shared-wallets/wallets/") + walletGid +
                    "/transactions";
  std::string body = TransactionToEvent(walletId, txId, psbt);
  GetHttpResponseData(Post(url, {body.begin(), body.end()}));
}

void GroupService::DeleteTransaction(const std::string& walletId,
                                     const std::string& txId) {
  auto walletSigner = GetWalletSignerFromWalletId(walletId, true);
  auto walletGid = walletSigner->GetAddressAtPath(KEYPAIR_PATH);
  auto txGid = walletSigner->HashMessage(txId);
  std::string url = std::string("/v1.1/shared-wallets/wallets/") + walletGid +
                    "/transactions";
  auto tx_gid = walletSigner->HashMessage(txId);
  json plaintext = {{"ts", std::time(0)}, {"txGid", tx_gid}};
  auto msg = plaintext.dump();
  auto sig = walletSigner->SignMessage(msg, KEYPAIR_PATH);
  json data = {
      {"version", VERSION},
      {"msg", msg},
      {"sig", sig},
  };
  json jbody = {
      {"id", tx_gid},
      {"data", data},
  };
  std::string body = jbody.dump();
  GetHttpResponseData(Delete(url, {body.begin(), body.end()}));
}

std::string GroupService::SetupKey(const Wallet& wallet) {
  std::unique_lock<std::shared_mutex> lock(walletMutex_);
  auto it = walletSigner_.find(wallet.get_id());
  if (it == walletSigner_.end()) {
    auto& ss = walletSigner_[wallet.get_id()] =
        std::make_shared<SoftwareSigner>(wallet);
    ss->SetupBoxKey(SECRET_PATH);
  }

  auto gid = walletSigner_.at(wallet.get_id())->GetAddressAtPath(KEYPAIR_PATH);
  walletGid2Id_[gid] = wallet.get_id();
  return gid;
}

int GroupService::GetSignerIndex(const std::string& groupId,
                                 const std::string& name) {
  auto groupJson = GetGroupJson(groupId);
  auto script_tmpl = groupJson["init"]["pubstate"]["miniscriptTemplate"];
  int keypath_m = 0;
  auto names = Utils::ParseSignerNames(script_tmpl, keypath_m);
  for (int i = 0; i < names.size(); i++) {
    if (names[i] == name) return i;
  }
  throw GroupException(GroupException::INVALID_PARAMETER, "Key name not found");
}

json GroupService::GetGroupJson(const std::string& groupId) {
  std::string url = std::string("/v1.1/shared-wallets/groups/") + groupId;
  return GetHttpResponseData(Get(url))["group"];
}

json GroupService::CheckGroupSandboxJson(const json& group, bool joined,
                                         int index) {
  if (group["status"].get<std::string>() == "ACTIVE") {
    throw GroupException(GroupException::SANDBOX_FINALIZED, "Group finalized");
  }
  if (joined && !group["init"]["state"].contains(ephemeralPub_)) {
    throw GroupException(GroupException::GROUP_NOT_JOINED, "Not joined group");
  } else if (!joined && group["init"]["state"].contains(ephemeralPub_)) {
    throw GroupException(GroupException::GROUP_JOINED, "Already joined");
  }
  int n = group["init"]["pubstate"]["n"];
  if (index >= n) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid index");
  }
  return group;
}

json GroupService::UpdateSignersJson(const json& jsigners, SingleSigner signer,
                                     int index, int n) {
  std::vector<SingleSigner> signers{};
  auto newdesc = signer.get_descriptor();
  for (auto& item : jsigners) {
    std::string desc = item;
    if (desc == "[]") {  // placeholder
      signers.push_back({});
    } else {
      if (desc == newdesc) {
        throw GroupException(GroupException::SIGNER_EXISTS, "Signer exists");
      }
      signers.push_back(ParseSignerString(desc));
    }
  }
  if (index >= 0) signers[index] = signer;
  signers.resize(n);
  json rs = json::array();
  for (auto&& signer : signers) {
    rs.push_back(signer.get_descriptor());
  }
  return rs;
}

json GroupService::UpdateOccupiedJson(const json& joccupied, bool value,
                                      int index) {
  std::map<int, std::pair<time_t, std::string>> occupied{};
  for (auto& item : joccupied) {
    occupied[item["i"]] = {item["ts"], item["uid"]};
  }
  if (value) {
    auto uid = GetDeviceInfo().second;
    occupied[index] = {std::time(0), uid};
  } else {
    occupied.erase(index);
  }
  json rs = json::array();
  for (auto&& [i, v] : occupied) {
    rs.push_back({{"i", i}, {"ts", v.first}, {"uid", v.second}});
  }
  return rs;
}

GroupSandbox GroupService::SendGroupEvent(const std::string& groupId,
                                          json& group, bool join) {
  group["init"]["stateId"] = group["init"]["stateId"].get<int>() + 1;
  json event = {
      {"group_id", groupId},
      {"type", "init"},
      {"data", group["init"]},
  };
  std::string url = join ? "/v1.1/shared-wallets/groups/join"
                         : "/v1.1/shared-wallets/events/send";
  std::string body = event.dump();
  GetHttpResponseData(Post(url, {body.begin(), body.end()}));
  return ParseGroup(group);
}

json GroupService::GetModifiedSigners(const json& modified, int n) {
  json signers{};
  if (modified.contains(ephemeralPub_)) {
    std::string ciphertext = modified[ephemeralPub_];
    signers = json::parse(
        Publicbox(ephemeralPub_, ephemeralPriv_).Open(ciphertext))["signers"];
  } else {
    for (int i = 0; i < n; i++) {
      signers.push_back("[]");
    }
  }
  return signers;
}

std::pair<std::shared_ptr<SoftwareSigner>, std::string>
GroupService::GetWalletSignerAndWalletIdFromGid(const std::string& walletGid) {
  std::shared_lock<std::shared_mutex> lock(walletMutex_);
  std::string walletId = walletGid2Id_.at(walletGid);
  return {walletSigner_.at(walletId), walletId};
}

std::shared_ptr<SoftwareSigner> GroupService::GetWalletSignerFromWalletId(
    const std::string& walletId, bool throwIfNotFound) {
  std::shared_lock<std::shared_mutex> lock(walletMutex_);
  auto it = walletSigner_.find(walletId);
  if (it != walletSigner_.end()) {
    return it->second;
  }
  if (throwIfNotFound) {
    throw GroupException(GroupException::WALLET_NOT_FOUND, "Wallet not found");
  }
  return nullptr;
}

std::shared_ptr<httplib::Client> GroupService::GetClient() {
  return http_clients_[client_idx_++ % CLIENT_COUNT];
}

}  // namespace nunchuk
