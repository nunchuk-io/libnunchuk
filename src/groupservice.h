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

#ifndef NUNCHUK_GROUPSERVICE_H
#define NUNCHUK_GROUPSERVICE_H

#include <nunchuk.h>
#include <vector>
#include <string>
#include <utils/json.hpp>

namespace nunchuk {

class GroupService {
 public:
  GroupService(const std::string& baseUrl);
  GroupService(const std::string& baseUrl, const std::string& ephemeralPub_,
               const std::string& ephemeralPriv_,
               const std::string& deviceToken_ = {});

  void SetEphemeralKey(const std::string& pub, const std::string priv);
  void SetDeviceToken(const std::string& token);
  void SetAccessToken(const std::string& token);

  std::string RegisterDevice(const std::string& osName,
                             const std::string& osVersion,
                             const std::string& appVersion,
                             const std::string& deviceClass,
                             const std::string& deviceId);

  SandboxGroup CreateGroup(int m, int n, AddressType addressType,
                           const SingleSigner& signer);
  SandboxGroup GetGroup(const std::string& groupId);
  std::vector<SandboxGroup> GetGroups(const std::vector<std::string>& groupIds);
  SandboxGroup JoinGroup(const std::string& groupId);
  SandboxGroup UpdateGroup(const SandboxGroup& group);
  void SendMessage(const std::string& groupId, const std::string& msg);
  void StartListenEvents(std::function<bool(const std::string&)> callback);
  void StopListenEvents();
  void Subscribe(const std::vector<std::string>& groupIds,
                 const std::vector<std::string>& walletIds);

  // Parse event data
  SandboxGroup ParseGroupData(const std::string& groupId, bool finalized,
                              const nlohmann::json& data);
  GroupMessage ParseMessageData(const std::string& id,
                                const std::string& groupId,
                                const nlohmann::json& data);

 private:
  std::string Get(const std::string& url);
  std::string Post(const std::string& url,
                   const std::vector<unsigned char>& body);

  SandboxGroup ParseGroupResponse(const std::string& resp);
  SandboxGroup ParseGroup(const nlohmann::json& group);
  std::string GroupToEvent(const SandboxGroup& group, const std::string& type);
  std::string MessageToEvent(const std::string& groupId,
                             const std::string& msg);

  bool stop_{false};
  std::string baseUrl_;
  std::string deviceToken_;
  std::string ephemeralPub_;
  std::string ephemeralPriv_;
  std::string accessToken_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_GROUPSERVICE_H
