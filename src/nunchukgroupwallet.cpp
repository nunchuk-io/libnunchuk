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
#include <utils/secretbox.h>

using json = nlohmann::json;

namespace nunchuk {

void ThrowIfNotEnable(bool value) {
  if (!value) {
    throw GroupException(GroupException::NOT_ENABLED, "Group is not enabled");
  }
}

bool NunchukImpl::CreateGroupWallet(const GroupSandbox& group) {
  if (!group.is_finalized() || group.get_wallet_id().empty()) return false;
  if (storage_->HasWallet(chain_, group.get_wallet_id())) return true;

  bool hasSigner = false;
  for (auto&& signer : group.get_signers()) {
    if (storage_->HasSigner(chain_, signer)) {
      hasSigner = true;
      break;
    }
  }
  if (!hasSigner) return false;
  auto wallet = CreateWallet(group.get_name(), group.get_m(), group.get_n(),
                             group.get_signers(), group.get_address_type(),
                             false, {}, true, {});
  group_service_.SetupKey(wallet);

  return true;
}

void NunchukImpl::EnableGroupWallet(const std::string& osName,
                                    const std::string& osVersion,
                                    const std::string& appVersion,
                                    const std::string& deviceClass,
                                    const std::string& deviceId,
                                    const std::string& accessToken) {
  group_service_.CheckVersion();
  group_wallet_enable_ = true;
  group_service_.SetAccessToken(accessToken);
  auto keypair = storage_->GetGroupEphemeralKey(chain_);
  if (keypair.first.empty() || keypair.second.empty()) {
    keypair = Publicbox::GenerateKeyPair();
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

  auto groups = GetGroups();
  for (auto&& group : groups) {
    if (group.is_finalized()) {
      if (CreateGroupWallet(group)) {
        storage_->AddGroupWalletId(chain_, group.get_wallet_id());
      }
      storage_->RemoveGroupSandboxId(chain_, group.get_id());
    }
  }

  auto walletIds = storage_->GetGroupWalletIds(chain_);
  for (auto&& walletId : walletIds) {
    try {
      auto wallet = storage_->GetWallet(chain_, walletId, false, false);
      group_service_.SetupKey(wallet);
    } catch (...) {
    }
  }

  StartListenEvents();
}

void NunchukImpl::StartListenEvents() {
  group_service_.Subscribe(storage_->GetGroupSandboxIds(chain_),
                           storage_->GetGroupWalletIds(chain_));
  group_service_.StartListenEvents([&](const nlohmann::json& event) {
    time_t ts = event["timestamp_ms"].get<int64_t>() / 1000;
    std::string eid = event["id"];
    json payload = event["payload"];
    std::string type = payload["type"];
    json data = payload["data"];
    if (payload["type"] == "online") {
      std::string groupId = payload["group_id"];
      auto count = payload["data"]["members"].size();
      {
        std::unique_lock<std::shared_mutex> lock(cache_access_);
        group_online_cache_[groupId] = count;
      }
      group_online_listener_(groupId, count);
    } else if (type == "init") {
      auto g = group_service_.ParseGroupData(payload["group_id"], false, data);
      group_wallet_listener_(g);
    } else if (type == "finalize") {
      auto g = group_service_.ParseGroupData(payload["group_id"], true, data);
      if (CreateGroupWallet(g)) {
        auto walletIds = storage_->AddGroupWalletId(chain_, g.get_wallet_id());
        auto groupIds = storage_->RemoveGroupSandboxId(chain_, g.get_id());
        group_service_.Subscribe(groupIds, walletIds);
      } else {
        auto walletIds = storage_->GetGroupWalletIds(chain_);
        auto groupIds = storage_->RemoveGroupSandboxId(chain_, g.get_id());
        group_service_.Subscribe(groupIds, walletIds);
      }
      group_wallet_listener_(g);
    } else if (type == "group_deleted") {
      std::string groupId = payload["group_id"];
      auto walletIds = storage_->GetGroupWalletIds(chain_);
      auto groupIds = storage_->RemoveGroupSandboxId(chain_, groupId);
      group_service_.Subscribe(groupIds, walletIds);
      group_delete_listener_(groupId);
    } else if (type == "chat") {
      auto m = group_service_.ParseMessageData(eid, payload["wallet_id"], data);
      m.set_ts(ts);
      m.set_sender(event["uid"]);
      group_message_listener_(m);
    } else if (type == "transaction_updated") {
      auto txGid = data["transaction_id"];
      auto walletId = group_service_.GetWalletIdFromGid(payload["wallet_id"]);
      auto txpair = group_service_.GetTransaction(walletId, txGid);
      TransactionStatus status = TransactionStatus::DELETED;
      if (txpair.first.empty()) {
        DeleteTransaction(walletId, txpair.second, false);
      } else {
        auto tx = ImportPsbt(walletId, txpair.first, false, false);
        status = tx.get_status();
      }
      synchronizer_->NotifyTransactionUpdate(walletId, txpair.second, status);
    } else if (type == "transaction_deleted") {
      // Do nothing, broadcast transactions will be deleted from server and
      // synced through synchronizer
    }
    return true;
  });
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

std::string NunchukImpl::GetGroupDeviceUID() {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.GetDeviceInfo().second;
}

void NunchukImpl::StartConsumeGroupEvent() {
  ThrowIfNotEnable(group_wallet_enable_);
}

void NunchukImpl::StopConsumeGroupEvent() {
  ThrowIfNotEnable(group_wallet_enable_);
}

GroupSandbox NunchukImpl::CreateGroup(const std::string& name, int m, int n,
                                      AddressType addressType) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto group = group_service_.CreateGroup(name, m, n, addressType);
  storage_->AddGroupSandboxId(chain_, group.get_id());
  // BE auto subcribe new groupId for creator, don't need to call Subscribe
  // here
  return group;
}

GroupSandbox NunchukImpl::GetGroup(const std::string& groupId) {
  ThrowIfNotEnable(group_wallet_enable_);
  try {
    return group_service_.GetGroup(groupId);
  } catch (GroupException& ne) {
    if (ne.code() == GroupException::GROUP_NOT_FOUND) {
      storage_->RemoveGroupSandboxId(chain_, groupId);
    }
    throw;
  }
}

int NunchukImpl::GetGroupOnline(const std::string& groupId) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_online_cache_.at(groupId);
}

std::vector<GroupSandbox> NunchukImpl::GetGroups() {
  ThrowIfNotEnable(group_wallet_enable_);
  auto groupIds = storage_->GetGroupSandboxIds(chain_);
  auto groups = group_service_.GetGroups(groupIds);
  for (auto&& groupId : groupIds) {
    bool found = false;
    for (auto&& group : groups) {
      if (group.get_id() == groupId) {
        found = true;
        break;
      }
    }
    if (!found) storage_->RemoveGroupSandboxId(chain_, groupId);
  }
  return groups;
}

GroupSandbox NunchukImpl::JoinGroup(const std::string& groupId) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto group = group_service_.JoinGroup(groupId);
  storage_->AddGroupSandboxId(chain_, groupId);
  // BE auto subcribe groupId, don't need to call Subscribe here
  return group;
}

GroupSandbox NunchukImpl::CreateReplaceGroup(const std::string& walletId) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto wallet = GetWallet(walletId);
  std::vector<SingleSigner> signers{};
  for (auto&& signer : wallet.get_signers()) {
    if (HasSigner(signer)) {
      signers.push_back(signer);
    } else {
      signers.push_back({});
    }
  }
  auto group = group_service_.CreateReplaceGroup(
      wallet.get_name(), wallet.get_m(), wallet.get_n(),
      wallet.get_address_type(), signers, walletId);
  storage_->AddGroupSandboxId(chain_, group.get_id());
  // BE auto subcribe new groupId for creator, don't need to call Subscribe
  // here
  return group;
}

std::map<std::string, bool> NunchukImpl::GetReplaceGroups(
    const std::string& walletId) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto replaces = group_service_.GetReplaceStatus(walletId);
  auto localStatus = storage_->GetGroupReplaceStatus(chain_);
  auto deviceUid = group_service_.GetDeviceInfo().second;
  std::map<std::string, bool> rs{};
  for (auto&& [gid, uid] : replaces) {
    if (deviceUid == uid) {
      // User is creator
      rs[gid] = true;
    } else if (localStatus[gid] == 1) {
      // User accepted
      rs[gid] = true;
    } else if (localStatus[gid] == -1) {
      // User declined
    } else {
      // User not decided yet
      rs[gid] = false;
    }
  }
  return rs;
}

GroupSandbox NunchukImpl::AcceptReplaceGroup(const std::string& walletId,
                                             const std::string& groupId) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto wallet = GetWallet(walletId);
  std::vector<SingleSigner> signers{};
  for (auto&& signer : wallet.get_signers()) {
    if (HasSigner(signer)) {
      signers.push_back(signer);
    } else {
      signers.push_back({});
    }
  }
  auto group = group_service_.JoinGroup(groupId, signers);
  storage_->AddGroupSandboxId(chain_, groupId);
  storage_->SetGroupReplaceStatus(chain_, groupId, true);
  // BE auto subcribe groupId, don't need to call Subscribe here
  return group;
}

void NunchukImpl::DeclineReplaceGroup(const std::string& walletId,
                                      const std::string& groupId) {
  ThrowIfNotEnable(group_wallet_enable_);
  storage_->SetGroupReplaceStatus(chain_, groupId, false);
}

GroupSandbox NunchukImpl::SetSlotOccupied(const std::string& groupId, int index,
                                          bool value) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.SetOccupied(groupId, index, value);
}

GroupSandbox NunchukImpl::AddSignerToGroup(const std::string& groupId,
                                           const SingleSigner& signer,
                                           int index) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.SetSigner(groupId, signer, index);
}

GroupSandbox NunchukImpl::RemoveSignerFromGroup(const std::string& groupId,
                                                int index) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.SetSigner(groupId, {}, index);
}

GroupSandbox NunchukImpl::UpdateGroup(const std::string& groupId,
                                      const std::string& name, int m, int n,
                                      AddressType addressType) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.UpdateGroup(groupId, name, m, n, addressType);
}

GroupSandbox NunchukImpl::FinalizeGroup(const std::string& groupId,
                                        const std::set<size_t>& valueKeyset) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto group = group_service_.GetGroup(groupId);
  if (group.get_m() <= 0 || group.get_n() <= 1 ||
      group.get_m() > group.get_n()) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid m/n");
  }
  if (group.is_finalized()) {
    if (CreateGroupWallet(group)) {
      storage_->AddGroupWalletId(chain_, group.get_wallet_id());
    }
    group_service_.Subscribe(
        storage_->RemoveGroupSandboxId(chain_, group.get_id()),
        storage_->GetGroupWalletIds(chain_));

    throw GroupException(GroupException::SANDBOX_FINALIZED, "Group finalized");
  }
  if (group.get_address_type() == AddressType::TAPROOT &&
      valueKeyset.size() != group.get_m()) {
    throw GroupException(GroupException::INVALID_PARAMETER, "Invalid keyset");
  }
  std::vector<SingleSigner> signers{};
  for (auto&& index : valueKeyset) {
    if (index >= group.get_signers().size()) {
      throw GroupException(GroupException::INVALID_PARAMETER, "Invalid index");
    }
    signers.push_back(group.get_signers()[index]);
  }
  for (int index = 0; index < group.get_signers().size(); index++) {
    auto signer = group.get_signers()[index];
    if (signer.get_master_fingerprint().empty()) {
      throw GroupException(GroupException::INVALID_PARAMETER,
                           "Invalid signers");
    }
    if (valueKeyset.find(index) == valueKeyset.end()) {
      signers.push_back(signer);
    }
  }
  signers.resize(group.get_n());
  auto wallet =
      CreateWallet(group.get_name(), group.get_m(), group.get_n(), signers,
                   group.get_address_type(), false, {}, true, {});
  group.set_signers(signers);
  group.set_finalized(true);
  group.set_wallet_id(wallet.get_id());
  group.set_pubkey(group_service_.SetupKey(wallet));
  auto rs = group_service_.FinalizeGroup(group);
  auto walletIds = storage_->AddGroupWalletId(chain_, wallet.get_id());
  auto groupIds = storage_->RemoveGroupSandboxId(chain_, groupId);
  group_service_.Subscribe(groupIds, walletIds);
  return rs;
}

void NunchukImpl::DeleteGroup(const std::string& groupId) {
  ThrowIfNotEnable(group_wallet_enable_);
  group_service_.DeleteGroup(groupId);
  storage_->RemoveGroupSandboxId(chain_, groupId);
}

std::vector<Wallet> NunchukImpl::GetGroupWallets() {
  auto walletIds = storage_->GetGroupWalletIds(chain_);
  std::vector<Wallet> rs{};
  for (auto&& walletId : walletIds) {
    try {
      auto wallet = GetWallet(walletId);
      rs.push_back(wallet);
    } catch (...) {
    }
  }
  return rs;
}

GroupWalletConfig NunchukImpl::GetGroupWalletConfig(
    const std::string& walletId) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.GetWalletConfig(walletId);
}

void NunchukImpl::SetGroupWalletConfig(const std::string& walletId,
                                       const GroupWalletConfig& config) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.SetWalletConfig(walletId, config);
}

bool NunchukImpl::CheckGroupWalletExists(const Wallet& wallet) {
  ThrowIfNotEnable(group_wallet_enable_);
  return group_service_.CheckWalletExists(wallet);
}

void NunchukImpl::RecoverGroupWallet(const std::string& walletId) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto wallet = GetWallet(walletId);
  if (!group_service_.CheckWalletExists(wallet)) {
    throw GroupException(GroupException::WALLET_NOT_FOUND, "Wallet not found");
  }
  group_service_.SetupKey(wallet);
  group_service_.RecoverWallet(walletId);
  storage_->AddGroupWalletId(chain_, walletId);
}

void NunchukImpl::SendGroupMessage(const std::string& walletId,
                                   const std::string& msg,
                                   const SingleSigner& signer) {
  ThrowIfNotEnable(group_wallet_enable_);
  if (!storage_->HasSigner(chain_, signer)) {
    throw GroupException(GroupException::SIGNER_NOT_FOUND, "Signer not found");
  }
  std::string signature = {};  // TODO: sign the message
  group_service_.SendChatMessage(walletId, msg, signer.get_master_fingerprint(),
                                 signature);
}

void NunchukImpl::SetLastReadMessage(const std::string& walletId,
                                     const std::string& messageId) {
  ThrowIfNotEnable(group_wallet_enable_);
  storage_->SetReadEvent(chain_, walletId, messageId);
}

int NunchukImpl::GetUnreadMessagesCount(const std::string& walletId) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto lastEvent = storage_->GetLastEvent(chain_, walletId);
  int count = 0;
  auto messages = group_service_.GetMessages(walletId, 0, 100, true);
  for (int i = 0; i < messages.size(); i++) {
    if (messages[i].get_id() == lastEvent) break;
    count++;
  }
  return count;
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

void NunchukImpl::AddGroupOnlineListener(
    std::function<void(const std::string& groupId, int online)> listener) {
  group_online_listener_.connect(listener);
}

void NunchukImpl::AddGroupDeleteListener(
    std::function<void(const std::string& groupId)> listener) {
  group_delete_listener_.connect(listener);
}

void NunchukImpl::SyncGroupTransactions(const std::string& walletId) {
  ThrowIfNotEnable(group_wallet_enable_);
  auto data = group_service_.GetTransactions(walletId, 0, 100, true);
  for (auto&& [txid, tx] : data) {
    try {
      if (tx.empty()) {
        DeleteTransaction(walletId, txid, false);
      } else {
        ImportPsbt(walletId, tx, false, false);
      }
    } catch (...) {
    }
  }
}

}  // namespace nunchuk
