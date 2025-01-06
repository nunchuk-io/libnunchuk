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
  group_service_.SetAccessToken(accessToken);
  auto keypair = storage_->GetGroupEphemeralKey(chain_);
  if (keypair.first.empty() || keypair.second.empty()) {
    keypair = rsa::GenerateKeypair();
    storage_->SetGroupEphemeralKey(chain_, keypair.first, keypair.second);
  }
  group_service_.SetEphemeralKey(keypair.first, keypair.second);
  std::string deviceToken = storage_->GetGroupDeviceToken(chain_);
  if (deviceToken.empty()) {
    deviceToken = group_service_.RegisterDevice(osName, osVersion, appVersion,
                                                deviceClass, deviceId);
    storage_->SetGroupDeviceToken(chain_, deviceToken);
  } else {
    group_service_.SetDeviceToken(deviceToken);
  }
}

void NunchukImpl::StartConsumeGroupEvent() {
  auto groupIds = storage_->GetGroupSandboxIds(chain_);
  auto walletIds = storage_->GetGroupWalletIds(chain_);
  group_service_.Subscribe(groupIds, walletIds);
  group_service_.StartListenEvents([&](const std::string& e) {
    json event = json::parse(e);
    time_t ts = event["timestamp_ms"];
    std::string id = event["id"];
    json payload = event["payload"];
    std::string type = payload["type"];
    std::string groupId = payload["group_id"];
    json data = payload["data"];

    if (type == "init") {
      auto group = group_service_.ParseGroupData(groupId, false, data);
      if (group.need_broadcast()) {
        group_service_.UpdateGroup(group);
      }
      group_wallet_listener_(group);
    } else if (type == "finalize") {
      auto group = group_service_.ParseGroupData(groupId, true, data);
      if (!storage_->HasWallet(chain_, group.get_wallet_id())) {
        auto wallet = CreateWallet(
            group.get_id(), group.get_m(), group.get_n(), group.get_signers(),
            group.get_address_type(), false, {}, true, {});
      }
      group_wallet_listener_(group);
    } else if (type == "chat") {
      auto message = group_service_.ParseMessageData(id, groupId, data);
      message.set_ts(ts);
      group_message_listener_(message);
    }
    return true;
  });
}

void NunchukImpl::StopConsumeGroupEvent() { group_service_.StopListenEvents(); }

SandboxGroup NunchukImpl::CreateGroup(int m, int n, AddressType addressType,
                                      const SingleSigner& signer) {
  return group_service_.CreateGroup(m, n, addressType, signer);
}

SandboxGroup NunchukImpl::GetGroup(const std::string& groupId) {
  return group_service_.GetGroup(groupId);
}

std::vector<SandboxGroup> NunchukImpl::GetGroups() {
  auto groupIds = storage_->GetGroupSandboxIds(chain_);
  return group_service_.GetGroups(groupIds);
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
  auto wallet = CreateWallet(group.get_id(), group.get_m(), group.get_n(),
                             group.get_signers(), group.get_address_type(),
                             false, {}, true, {});
  group.set_finalized(true);
  group.set_wallet_id(wallet.get_id());
  // TODO: set group pubkey
  return group_service_.UpdateGroup(group);
}

void NunchukImpl::SendGroupMessage(const std::string& walletId,
                                   const std::string& msg) {
  group_service_.SendMessage(walletId, msg);
}

void NunchukImpl::AddGroupUpdateListener(
    std::function<void(const SandboxGroup& state)> listener) {
  group_wallet_listener_.connect(listener);
}

void NunchukImpl::AddGroupMessageListener(
    std::function<void(const GroupMessage& msg)> listener) {
  group_message_listener_.connect(listener);
}

}  // namespace nunchuk
