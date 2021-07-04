// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_SYNCHRONIZER_H
#define NUNCHUK_SYNCHRONIZER_H

#include <nunchuk.h>
#include <storage/storage.h>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/signals2.hpp>

namespace nunchuk {

class Synchronizer {
 public:
  Synchronizer(const AppSettings& app_settings, NunchukStorage* storage);
  Synchronizer(const Synchronizer&) = delete;
  Synchronizer() = delete;
  Synchronizer& operator=(const Synchronizer&) = delete;
  virtual ~Synchronizer();

  bool NeedRecreate(const AppSettings& app_settings);
  int GetChainTip();

  void AddBalanceListener(std::function<void(std::string, Amount)> listener);
  void AddBlockListener(std::function<void(int, std::string)> listener);
  void AddTransactionListener(
      std::function<void(std::string, TransactionStatus)> listener);
  void AddBlockchainConnectionListener(
      std::function<void(ConnectionStatus, int)> listener);

  virtual void Broadcast(const std::string& raw_tx) = 0;
  virtual Amount EstimateFee(int conf_target) = 0;
  virtual Amount RelayFee() = 0;
  virtual bool LookAhead(Chain chain, const std::string& wallet_id,
                         const std::string& address, int index,
                         bool internal) = 0;
  virtual void RescanBlockchain(int start_height, int stop_height) = 0;

  virtual void Run(){};

 protected:
  AppSettings app_settings_;
  NunchukStorage* storage_;

  std::thread sync_thread_;
  boost::asio::io_service io_service_;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type>
      sync_worker_;

  // Cache
  std::atomic<int> chain_tip_;

  // Listener
  boost::signals2::signal<void(std::string, Amount)> balance_listener_;
  boost::signals2::signal<void(int, std::string)> block_listener_;
  boost::signals2::signal<void(std::string, TransactionStatus)>
      transaction_listener_;
  boost::signals2::signal<void(ConnectionStatus, int)> connection_listener_;
};

std::unique_ptr<Synchronizer> MakeSynchronizer(const AppSettings& app_settings,
                                               NunchukStorage* storage);

}  // namespace nunchuk

#endif  // NUNCHUK_SYNCHRONIZER_H
