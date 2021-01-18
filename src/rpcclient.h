// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_RPC_CLIENT_H
#define NUNCHUK_RPC_CLIENT_H

#include <nunchuk.h>

namespace nunchuk {

class RpcClient {
 public:
  RpcClient(const nunchuk::AppSettings &appsettings);
  ~RpcClient();

  void Broadcast(const std::string &raw_tx);
  Amount EstimateFee(int conf_target);
  Amount RelayFee();
  int GetChainTip();

  // Creates and loads a new wallet.
  void ImportDescriptors(const std::string &descriptors);
  void CreateWallet();
  void LoadWallet();
  void GetWalletInfo();
  void ListTransactions();
  void ListUnspent();
  void GetTransaction(const std::string &tx_id);

 private:
  std::string SendRequest(const std::string &path, const std::string &body);

  std::string host_;
  int port_;
  std::string user_;
  std::string pw_;
  std::string name_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_RPC_CLIENT_H
