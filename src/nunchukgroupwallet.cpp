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

#include "nunchukimpl.h"

#include <groupservice.h>
#include <utils/json.hpp>
#include <utils/loguru.hpp>
#include <utils/rsa.hpp>

using json = nlohmann::json;

namespace nunchuk {

void NunchukImpl::EnableGroupWallet(const std::string& osName,
                                    const std::string& osVersion,
                                    const std::string& appVersion,
                                    const std::string& deviceClass,
                                    const std::string& deviceId,
                                    const std::string& accessToken) {
  group_wallet_enable_ = true;
  auto keypair = storage_->GetGroupEphemeralKey(chain_);
  if (keypair.first.empty() || keypair.second.empty()) {
    keypair = rsa::GenerateKeypair();
    storage_->SetGroupEphemeralKey(chain_, keypair.first, keypair.second);
  }
  group_service_.SetEphemeralKey(keypair.first, keypair.second);
  std::string deviceToken = storage_->GetGroupDeviceToken(chain_);
  if (deviceToken.empty()) {
    deviceToken = group_service_.RegisterDevice(
        osName, osVersion, appVersion, deviceClass, deviceId, accessToken);
    storage_->SetGroupDeviceToken(chain_, deviceToken);
  } else {
    group_service_.SetDeviceToken(deviceToken);
  }
}

void NunchukImpl::StartConsumeGroupEvent() {}
void NunchukImpl::StopConsumeGroupEvent() {}

SandboxGroup NunchukImpl::CreateGroup(int m, int n, AddressType addressType,
                                      const SingleSigner& signer) {
  return group_service_.CreateGroup(m, n, addressType, signer);
}

SandboxGroup NunchukImpl::GetGroup(const std::string& groupId) {
  return group_service_.GetGroup(groupId);
}

std::vector<SandboxGroup> NunchukImpl::GetGroups() {
  return group_service_.GetGroups();
}

SandboxGroup NunchukImpl::JoinGroup(const std::string& groupId) {
  return group_service_.JoinGroup(groupId);
}

SandboxGroup NunchukImpl::AddSignerToGroup(const std::string& groupId,
                                           const SingleSigner& signer) {
  auto group = group_service_.GetGroup(groupId);
  auto signers = group.get_signers();
  signers.push_back(signer);
  group.set_signers(signers);
  return group_service_.UpdateGroup(group);
}

SandboxGroup NunchukImpl::UpdateGroup(const std::string& groupId, int m, int n,
                                      AddressType addressType,
                                      const SingleSigner& signer) {
  auto group = group_service_.GetGroup(groupId);
  group.set_m(m);
  group.set_n(n);
  group.set_address_type(addressType);
  group.set_signers({signer});
  return group_service_.UpdateGroup(group);
}

SandboxGroup NunchukImpl::FinalizeGroup(const std::string& groupId) {
  auto group = group_service_.GetGroup(groupId);
  group.set_finalized(true);
  return group_service_.UpdateGroup(group);
}

void NunchukImpl::AddGroupUpdateListener(
    std::function<void(const SandboxGroup& state)> listener) {
  group_wallet_listener_.connect(listener);
}

}  // namespace nunchuk
