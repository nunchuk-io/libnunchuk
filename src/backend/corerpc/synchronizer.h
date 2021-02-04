// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_CORERPC_SYNCHRONIZER_H
#define NUNCHUK_CORERPC_SYNCHRONIZER_H

#include <boost/asio.hpp>
#include <backend/synchronizer.h>
#include <backend/corerpc/client.h>

namespace nunchuk {

class CoreRpcSynchronizer : public Synchronizer {
 public:
  using Synchronizer::Synchronizer;
  CoreRpcSynchronizer(const CoreRpcSynchronizer&) = delete;
  CoreRpcSynchronizer& operator=(const CoreRpcSynchronizer&) = delete;
  ~CoreRpcSynchronizer() override;

  void Broadcast(const std::string& raw_tx) override;
  Amount EstimateFee(int conf_target) override;
  Amount RelayFee() override;
  bool LookAhead(Chain chain, const std::string& wallet_id,
                 const std::string& address, int index, bool internal) override;
  void RescanBlockchain(int start_height, int stop_height) override;

  void Run() override;

 private:
  bool IsRpcReady();
  void CreateOrLoadWallet();
  void BlockchainSync(const boost::system::error_code& error);

  std::unique_ptr<CoreRpcClient> client_;
  boost::posix_time::seconds interval_{300};  // 5 minutes
  boost::asio::deadline_timer timer_{io_service_, boost::posix_time::seconds(10)};
  bool stopped = false;
};

}  // namespace nunchuk

#endif  // NUNCHUK_CORERPC_SYNCHRONIZER_H
