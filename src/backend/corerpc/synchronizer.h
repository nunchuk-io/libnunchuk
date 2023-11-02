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

#ifndef NUNCHUK_CORERPC_SYNCHRONIZER_H
#define NUNCHUK_CORERPC_SYNCHRONIZER_H

#include <boost/asio.hpp>
#include <backend/synchronizer.h>
#include <backend/corerpc/client.h>

namespace nunchuk {

class CoreRpcSynchronizer : public Synchronizer {
 public:
  CoreRpcSynchronizer(const AppSettings& app_settings,
                      const std::string& account);
  CoreRpcSynchronizer(const CoreRpcSynchronizer&) = delete;
  CoreRpcSynchronizer& operator=(const CoreRpcSynchronizer&) = delete;
  ~CoreRpcSynchronizer() override;

  void Broadcast(const std::string& raw_tx) override;
  Amount EstimateFee(int conf_target) override;
  Amount RelayFee() override;
  bool LookAhead(Chain chain, const std::string& wallet_id,
                 const std::string& address, int index, bool internal) override;
  bool SupportBatchLookAhead() override;
  int BatchLookAhead(Chain chain, const std::string& wallet_id,
                     const std::vector<std::string>& addresses,
                     const std::vector<int>& indexes, bool internal) override;
  void RescanBlockchain(int start_height, int stop_height) override;
  std::vector<UnspentOutput> ListUnspent(const std::string& address) override;
  std::string GetRawTx(const std::string& tx_id) override;
  Transaction GetTransaction(const std::string& tx_id) override;

  void Run() override;

 private:
  bool IsRpcReady();
  void CreateOrLoadWallet();
  void BlockchainSync(const boost::system::error_code& error);

  std::unique_ptr<CoreRpcClient> client_;
  boost::posix_time::seconds interval_;
  boost::asio::deadline_timer timer_;
  bool stopped = false;
};

}  // namespace nunchuk

#endif  // NUNCHUK_CORERPC_SYNCHRONIZER_H
