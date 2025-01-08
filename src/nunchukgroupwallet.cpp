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

void ThrowIfNotEnable(bool value) {
  if (!value) {
    throw GroupException(GroupException::NOT_ENABLED, "Group is not enabled");
  }
}

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
  auto deviceInfo = storage_->GetGroupDeviceInfo(chain_);
  if (deviceInfo.first.empty() || deviceInfo.second.empty()) {
    deviceInfo = group_service_.RegisterDevice(osName, osVersion, appVersion,
                                               deviceClass, deviceId);
    storage_->SetGroupDeviceInfo(chain_, deviceInfo.first, deviceInfo.second);
  } else {
    group_service_.SetDeviceInfo(deviceInfo.first, deviceInfo.second);
  }
}

std::pair<std::string, std::string> NunchukImpl::ParseGroupUrl(
    const std::string& url) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.ParseUrl(url);
}

GroupConfig NunchukImpl::GetGroupConfig() {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.GetConfig();
}

void NunchukImpl::StartConsumeGroupEvent() {
  ThrowIfNotEnable(group_wallet_enable_);
  auto groupIds = storage_->GetGroupSandboxIds(chain_);
  auto walletIds = storage_->GetGroupWalletIds(chain_);
  group_service_.Subscribe(groupIds, walletIds);
  group_service_.StartListenEvents([&](const std::string& e) {
    json event = json::parse(e);
    time_t ts = event["timestamp_ms"].get<int64_t>() / 1000;
    std::string eid = event["id"];
    std::string uid = event["uid"];
    json payload = event["payload"];
    std::string type = payload["type"];
    json data = payload["data"];

    if (type == "init") {
      auto group =
          group_service_.ParseGroupData(payload["group_id"], false, data);
      if (group.need_broadcast()) {
        group_service_.UpdateGroup(group);
      }
      group_wallet_listener_(group);
    } else if (type == "finalize") {
      auto group =
          group_service_.ParseGroupData(payload["group_id"], true, data);
      if (!storage_->HasWallet(chain_, group.get_wallet_id())) {
        auto wallet = CreateWallet(
            group.get_id(), group.get_m(), group.get_n(), group.get_signers(),
            group.get_address_type(), false, {}, true, {});
        group_service_.SetupKey(wallet);
      }
      group_wallet_listener_(group);
    } else if (type == "chat") {
      auto message =
          group_service_.ParseMessageData(eid, payload["wallet_id"], data);
      message.set_ts(ts);
      message.set_sender(uid);
      group_message_listener_(message);
    }
    return true;
  });
}

void NunchukImpl::StopConsumeGroupEvent() {
  ThrowIfNotEnable(group_wallet_enable_);
  group_service_.StopListenEvents();
}

GroupSandbox NunchukImpl::CreateGroup(int m, int n, AddressType addressType,
                                      const SingleSigner& signer) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.CreateGroup(m, n, addressType, signer);
}

GroupSandbox NunchukImpl::GetGroup(const std::string& groupId) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.GetGroup(groupId);
}

std::vector<GroupSandbox> NunchukImpl::GetGroups() {
  ThrowIfNotEnable(group_wallet_enable_);
  auto groupIds = storage_->GetGroupSandboxIds(chain_);
  return group_service_.GetGroups(groupIds);
}

GroupSandbox NunchukImpl::JoinGroup(const std::string& groupId) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.JoinGroup(groupId);
}

GroupSandbox NunchukImpl::AddSignerToGroup(const std::string& groupId,
                                           const SingleSigner& signer) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto group = group_service_.GetGroup(groupId);
  auto signers = group.get_signers();
  if (signers.size() == group.get_n()) {
    throw GroupException(GroupException::TOO_MANY_SIGNER, "Too many signer");
  }
  auto desc = signer.get_descriptor();
  for (auto&& s : signers) {
    if (s.get_descriptor() == desc) {
      throw GroupException(GroupException::SIGNER_EXISTS, "Signer exists");
    }
  }
  signers.push_back(signer);
  group.set_signers(signers);
  return group_service_.UpdateGroup(group);
}

GroupSandbox NunchukImpl::RemoveSignerFromGroup(const std::string& groupId,
                                                const SingleSigner& signer) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto group = group_service_.GetGroup(groupId);
  auto signers = group.get_signers();
  auto desc = signer.get_descriptor();
  signers.erase(std::remove_if(signers.begin(), signers.end(),
                               [&](const SingleSigner& s) {
                                 return s.get_descriptor() == desc;
                               }),
                signers.end());
  group.set_signers(signers);
  return group_service_.UpdateGroup(group);
}

GroupSandbox NunchukImpl::UpdateGroup(const std::string& groupId, int m, int n,
                                      AddressType addressType,
                                      const SingleSigner& signer) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto group = group_service_.GetGroup(groupId);
  group.set_m(m);
  group.set_n(n);
  group.set_address_type(addressType);
  group.set_signers({signer});
  return group_service_.UpdateGroup(group);
}

GroupSandbox NunchukImpl::FinalizeGroup(const std::string& groupId) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto group = group_service_.GetGroup(groupId);
  auto wallet = CreateWallet(group.get_id(), group.get_m(), group.get_n(),
                             group.get_signers(), group.get_address_type(),
                             false, {}, true, {});
  group.set_finalized(true);
  group.set_wallet_id(wallet.get_id());
  group.set_pubkey(group_service_.SetupKey(wallet));
  return group_service_.UpdateGroup(group);
}

bool NunchukImpl::CheckGroupWalletExists(const Wallet& wallet) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.CheckWalletExists(wallet);
}

void NunchukImpl::SendGroupMessage(const std::string& walletId,
                                   const std::string& msg,
                                   const SingleSigner& signer) {
  ThrowIfNotEnable(group_wallet_enable_);
  std::string signature = {};  // TODO: sign the msg with signature
  group_service_.SendMessage(walletId, msg, signer.get_master_fingerprint(),
                             signature);
}

std::vector<GroupMessage> NunchukImpl::GetGroupMessages(
    const std::string& walletId, int page, int pageSize, bool latest) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.GetMessages(walletId, page, pageSize, latest);
}

void NunchukImpl::AddGroupUpdateListener(
    std::function<void(const GroupSandbox& state)> listener) {
  group_wallet_listener_.connect(listener);
}

void NunchukImpl::AddGroupMessageListener(
    std::function<void(const GroupMessage& msg)> listener) {
  group_message_listener_.connect(listener);
}

}  // namespace nunchuk
