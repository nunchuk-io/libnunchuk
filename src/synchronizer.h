// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_SYNCHRONIZER_H
#define NUNCHUK_SYNCHRONIZER_H

#include <descriptor.h>
#include <hwiservice.h>
#include <nunchuk.h>
#include <coreutils.h>
#include <storage.h>
#include <electrumclient.h>
#include <atomic>
#include <condition_variable>
#include <boost/asio.hpp>
#include <boost/signals2.hpp>

namespace nunchuk {

const int ESTIMATE_FEE_CACHE_SIZE = 3;

class BlockSynchronizer {
 public:
  BlockSynchronizer(NunchukStorage* storage);
  BlockSynchronizer(const BlockSynchronizer&) = delete;
  BlockSynchronizer& operator=(const BlockSynchronizer&) = delete;
  ~BlockSynchronizer();

  void Broadcast(const std::string& raw_tx);
  Amount EstimateFee(int conf_target);
  Amount RelayFee();
  int GetChainTip();

  void Run(const AppSettings& appsettings);
  std::string SubscribeAddress(const std::string& wallet_id,
                               const std::string& address);

  void AddBalanceListener(std::function<void(std::string, Amount)> listener);
  void AddBlockListener(std::function<void(int, std::string)> listener);
  void AddTransactionListener(
      std::function<void(std::string, TransactionStatus)> listener);
  void AddBlockchainConnectionListener(
      std::function<void(ConnectionStatus)> listener);

 private:
  enum class Status {
    UNINITIALIZED,
    CONNECTING,
    SYNCING,
    READY,
    STOPPED,
  };

  bool NeedUpdateClient(const AppSettings& appsettings);
  void UpdateTransactions(Chain chain, const std::string& wallet_id,
                          const json& history);
  void OnScripthashStatusChange(Chain chain, const json& notification);
  void BlockchainSync(Chain chain);
  void Connect();
  void WaitForReady();

  AppSettings app_settings_;
  NunchukStorage* storage_;
  std::unique_ptr<ElectrumClient> client_;

  Status status_ = Status::UNINITIALIZED;
  std::mutex status_mutex_;
  std::condition_variable status_cv_;

  std::thread sync_thread_;
  boost::asio::io_service io_service_;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type>
      sync_worker_;

  // Listener
  boost::signals2::signal<void(std::string, Amount)> balance_listener_;
  boost::signals2::signal<void(int, std::string)> block_listener_;
  boost::signals2::signal<void(std::string, TransactionStatus)>
      transaction_listener_;
  boost::signals2::signal<void(ConnectionStatus)> connection_listener_;

  // Cache
  bool first_run_ = true;
  std::atomic<int> chain_tip_;
  time_t estimate_fee_cached_time_[ESTIMATE_FEE_CACHE_SIZE];
  Amount estimate_fee_cached_value_[ESTIMATE_FEE_CACHE_SIZE];
  std::map<std::string, std::pair<std::string, std::string>>
      scripthash_to_wallet_address_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_SYNCHRONIZER_H
