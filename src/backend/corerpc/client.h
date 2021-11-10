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
