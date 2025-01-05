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

namespace nunchuk {

class GroupService {
public:
  GroupService(const std::string& baseUrl,
                const std::string& ephemeralPub_,
                const std::string& ephemeralPriv_,
                const std::string& deviceToken_ = {});

  std::string RegisterDevice(
                const std::string& osName,
                const std::string& osVersion,
                const std::string& appVersion,
                const std::string& deviceClass,
                const std::string& deviceId);
  std::string GroupToEvent(const SandboxGroup& group, const std::string type);
  SandboxGroup ParseGroupResult(const std::string& data);
  SandboxGroup CreateGroup(int m, int n, AddressType addressType, const SingleSigner& signer);
  SandboxGroup GetGroup(const std::string& groupId);
  std::vector<SandboxGroup> GetGroups();
  SandboxGroup JoinGroup(const std::string& groupId);
  SandboxGroup UpdateGroup(const SandboxGroup& group);
  void ListenEvents(std::function<bool(const std::string&)> callback);

private:
  std::string Get(const std::string &url);
  std::string Post(const std::string &url, const std::vector<unsigned char> &body);

  std::string baseUrl_;
  std::string deviceToken_;
  std::string ephemeralPub_;
  std::string ephemeralPriv_;
};

}  // namespace nunchuk

#endif // NUNCHUK_GROUPSERVICE_H
