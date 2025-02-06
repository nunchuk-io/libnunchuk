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
#include <softwaresigner.h>

namespace nunchuk {

class GroupService {
 public:
  GroupService(const std::string& baseUrl);
  GroupService(const std::string& baseUrl, const std::string& ephemeralPub_,
               const std::string& ephemeralPriv_,
               const std::string& deviceToken_ = {},
               const std::string& uid_ = {});
  ~GroupService();

  void SetEphemeralKey(const std::string& pub, const std::string priv);
  void SetDeviceInfo(const std::string& token, const std::string uid);
  void SetAccessToken(const std::string& token);
  void CheckVersion();
  std::pair<std::string, std::string> GetDeviceInfo();

  std::pair<std::string, std::string> ParseUrl(const std::string& url);
  GroupConfig GetConfig();
  std::pair<std::string, std::string> RegisterDevice(
      const std::string& osName, const std::string& osVersion,
      const std::string& appVersion, const std::string& deviceClass,
      const std::string& deviceId);

  GroupSandbox CreateGroup(const std::string& name, int m, int n,
                           AddressType addressType);
  GroupSandbox GetGroup(const std::string& groupId);
  std::vector<GroupSandbox> GetGroups(const std::vector<std::string>& groupIds);
  GroupSandbox JoinGroup(const std::string& groupId);
  GroupSandbox SetOccupied(const std::string& groupId, int index, bool value);
  GroupSandbox SetSigner(const std::string& groupId, const SingleSigner& signer,
                         int index);
  GroupSandbox UpdateGroup(const std::string& groupId, const std::string& name,
                           int m, int n, AddressType addressType);
  GroupSandbox FinalizeGroup(const GroupSandbox& group);
  void DeleteGroup(const std::string& groupId);
  GroupWalletConfig GetWalletConfig(const std::string& walletId);
  void SetWalletConfig(const std::string& walletId,
                       const GroupWalletConfig& config);
  bool CheckWalletExists(const Wallet& wallet);
  void SendChatMessage(const std::string& walletId, const std::string& content,
                       const std::string& signer, const std::string& signature);
  std::vector<GroupMessage> GetMessages(const std::string& walletId, int page,
                                        int pageSize, bool latest);
  void StartListenEvents(std::function<bool(const std::string&)> callback);
  void StopListenEvents();
  void Subscribe(const std::vector<std::string>& groupIds,
                 const std::vector<std::string>& walletIds);
  bool HasWallet(const std::string& walletId, bool throwIfNotFound = false);
  void RecoverWallet(const std::string& walletId);
  void DeleteWallet(const std::string& walletId);
  std::string GetWalletIdFromGid(const std::string& walletGid);
  std::string GetTxIdFromGid(const std::string& walletId,
                             const std::string& txGid,
                             const std::vector<Transaction>& txs);
  std::pair<std::string, std::string> GetTransaction(
      const std::string& walletId, const std::string& txGid);
  std::map<std::string, std::string> GetTransactions(
      const std::string& walletId, int page, int pageSize, bool latest);
  void UpdateTransaction(const std::string& walletId, const std::string& txId,
                         const std::string& psbt);
  void DeleteTransaction(const std::string& walletId, const std::string& txId);
  std::string SetupKey(const Wallet& wallet);

  // Parse event data
  GroupSandbox ParseGroupData(const std::string& groupId, bool finalized,
                              const nlohmann::json& data);
  GroupMessage ParseMessageData(const std::string& id,
                                const std::string& walletGid,
                                const nlohmann::json& data);
  std::pair<std::string, std::string> ParseTransactionData(
      const std::string& walletGid, const nlohmann::json& data);

 private:
  std::string Get(const std::string& url);
  std::string Post(const std::string& url,
                   const std::vector<unsigned char>& body);
  std::string Delete(const std::string& url,
                     const std::vector<unsigned char>& body = {});

  GroupSandbox ParseGroup(const nlohmann::json& group);
  std::string GroupToEvent(const GroupSandbox& group);
  std::string MessageToEvent(const std::string& walletId,
                             const std::string& content,
                             const std::string& signer,
                             const std::string& signature);
  std::string TransactionToEvent(const std::string& walletId,
                                 const std::string& txId,
                                 const std::string& psbt);

  json GetGroupJson(const std::string& groupId);
  json GetModifiedSigners(const json& modified, int n);
  json CheckGroupJson(const json& group, bool joined, bool finalized,
                      int index = -1);
  json UpdateSignersJson(const json& signers, SingleSigner signer, int index);
  json UpdateOccupiedJson(const json& occupied, bool value, int index);
  GroupSandbox SendGroupEvent(const std::string& groupId, json& group,
                              bool join = false);

  bool stop_{false};
  std::string baseUrl_;
  std::string deviceToken_;
  std::string uid_;
  std::string ephemeralPub_;
  std::string ephemeralPriv_;
  std::string accessToken_;
  std::map<std::string, std::shared_ptr<SoftwareSigner>> walletSigner_{};
  std::map<std::string, std::string> walletGid2Id_{};
};

}  // namespace nunchuk

#endif  // NUNCHUK_GROUPSERVICE_H
