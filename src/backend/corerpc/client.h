// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_CORERPC_CLIENT_H
#define NUNCHUK_CORERPC_CLIENT_H

#include <nunchuk.h>
#include <utils/json.hpp>

namespace nunchuk {

class CoreRpcClient {
 public:
  CoreRpcClient(const nunchuk::AppSettings &appsettings);
  ~CoreRpcClient();

  void Broadcast(const std::string &raw_tx);
  Amount EstimateFee(int conf_target);
  Amount RelayFee();

  // Creates and loads a new wallet.
  void ImportDescriptors(const std::string &descriptors);
  void CreateWallet();
  void LoadWallet();
  void RescanBlockchain(int start_height, int stop_height = -1);
  nlohmann::json GetBlockchainInfo();
  nlohmann::json GetWalletInfo();
  nlohmann::json GetAddressInfo(const std::string &address);
  nlohmann::json ListTransactions();
  nlohmann::json ListUnspent();
  nlohmann::json GetTransaction(const std::string &tx_id);

 private:
  std::string SendRequest(const std::string &path, const std::string &body);

  std::string host_;
  int port_;
  std::string user_;
  std::string pw_;
  std::string name_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_CORERPC_CLIENT_H
