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
#include <backend/electrum/electrumclient.h>
#include <atomic>
#include <condition_variable>
#include <boost/asio.hpp>
#include <boost/signals2.hpp>
#include <backend/corerpc/corerpcclient.h>

namespace nunchuk {

const int ESTIMATE_FEE_CACHE_SIZE = 3;

class Synchronizer {
 public:
  Synchronizer(NunchukStorage* storage);
  Synchronizer(const Synchronizer&) = delete;
  Synchronizer& operator=(const Synchronizer&) = delete;
  ~Synchronizer();

  virtual void Broadcast(const std::string& raw_tx) = 0;
  virtual Amount EstimateFee(int conf_target) = 0;
  virtual Amount RelayFee() = 0;
  virtual int GetChainTip() = 0;
  virtual bool LookAhead(Chain chain, const std::string& wallet_id,
                         const std::string& address, int index,
                         bool internal) = 0;

  virtual void Run(const AppSettings& appsettings) = 0;

  void AddBalanceListener(std::function<void(std::string, Amount)> listener);
  void AddBlockListener(std::function<void(int, std::string)> listener);
  void AddTransactionListener(
      std::function<void(std::string, TransactionStatus)> listener);
  void AddBlockchainConnectionListener(
      std::function<void(ConnectionStatus)> listener);

 protected:
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
  boost::signals2::signal<void(ConnectionStatus)> connection_listener_;
};

class RpcSynchronizer : public Synchronizer {
 public:
  using Synchronizer::Synchronizer;
  RpcSynchronizer(const RpcSynchronizer&) = delete;
  RpcSynchronizer& operator=(const RpcSynchronizer&) = delete;
  ~RpcSynchronizer();

  void Broadcast(const std::string& raw_tx);
  Amount EstimateFee(int conf_target);
  Amount RelayFee();
  int GetChainTip();
  bool LookAhead(Chain chain, const std::string& wallet_id,
                 const std::string& address, int index, bool internal);

  void Run(const AppSettings& appsettings);

 private:
  bool IsRpcReady();
  void CreateOrLoadWallet();

  void BlockchainSync(const boost::system::error_code& error);

  AppSettings app_settings_;
  std::unique_ptr<CoreRpcClient> client_;
  boost::posix_time::seconds interval_{10};
  boost::asio::deadline_timer timer_{io_service_, interval_};
};

class BlockSynchronizer : public Synchronizer {
 public:
  using Synchronizer::Synchronizer;
  BlockSynchronizer(const BlockSynchronizer&) = delete;
  BlockSynchronizer& operator=(const BlockSynchronizer&) = delete;
  ~BlockSynchronizer();

  void Broadcast(const std::string& raw_tx);
  Amount EstimateFee(int conf_target);
  Amount RelayFee();
  int GetChainTip();
  bool LookAhead(Chain chain, const std::string& wallet_id,
                 const std::string& address, int index, bool internal);

  void Run(const AppSettings& appsettings);

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
  std::string SubscribeAddress(const std::string& wallet_id,
                               const std::string& address);
  void BlockchainSync(Chain chain);
  void Connect();
  void WaitForReady();

  AppSettings app_settings_;
  std::unique_ptr<ElectrumClient> client_;

  Status status_ = Status::UNINITIALIZED;
  std::mutex status_mutex_;
  std::condition_variable status_cv_;

  // Cache
  bool first_run_ = true;
  time_t estimate_fee_cached_time_[ESTIMATE_FEE_CACHE_SIZE];
  Amount estimate_fee_cached_value_[ESTIMATE_FEE_CACHE_SIZE];
  std::map<std::string, std::pair<std::string, std::string>>
      scripthash_to_wallet_address_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_SYNCHRONIZER_H
