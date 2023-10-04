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
  Synchronizer(const AppSettings& appsettings, const std::string& account);
  Synchronizer(const Synchronizer&) = delete;
  Synchronizer() = delete;
  Synchronizer& operator=(const Synchronizer&) = delete;
  virtual ~Synchronizer();

  bool NeedRecreate(const AppSettings& appsettings);
  int GetChainTip();

  void AddBalanceListener(std::function<void(std::string, Amount)> listener);
  void AddBalancesListener(
      std::function<void(std::string, Amount, Amount)> listener);
  void AddBlockListener(std::function<void(int, std::string)> listener);
  void AddTransactionListener(
      std::function<void(std::string, TransactionStatus, std::string)>
          listener);
  void AddBlockchainConnectionListener(
      std::function<void(ConnectionStatus, int)> listener);

  virtual void Broadcast(const std::string& raw_tx) = 0;
  virtual Amount EstimateFee(int conf_target) = 0;
  virtual Amount RelayFee() = 0;
  virtual bool LookAhead(Chain chain, const std::string& wallet_id,
                         const std::string& address, int index,
                         bool internal) = 0;
  virtual bool SupportBatchLookAhead() = 0;
  virtual int BatchLookAhead(Chain chain, const std::string& wallet_id,
                             const std::vector<std::string>& addresses,
                             const std::vector<int>& indexes,
                             bool internal) = 0;
  virtual void RescanBlockchain(int start_height, int stop_height) = 0;
  virtual std::vector<UnspentOutput> ListUnspent(
      const std::string& address) = 0;
  virtual std::string GetRawTx(const std::string& tx_id) = 0;
  virtual Transaction GetTransaction(const std::string& tx_id) = 0;

  virtual void Run(){};

 protected:
  AppSettings app_settings_;
  std::shared_ptr<NunchukStorage> storage_;

  std::thread sync_thread_;
  boost::asio::io_service io_service_;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type>
      sync_worker_;

  // Cache
  std::atomic<int> chain_tip_;

  // Listener
  boost::signals2::signal<void(std::string, Amount)> balance_listener_;
  boost::signals2::signal<void(std::string, Amount, Amount)> balances_listener_;
  boost::signals2::signal<void(int, std::string)> block_listener_;
  boost::signals2::signal<void(std::string, TransactionStatus, std::string)>
      transaction_listener_;
  boost::signals2::signal<void(ConnectionStatus, int)> connection_listener_;
};

std::unique_ptr<Synchronizer> MakeSynchronizer(const AppSettings& appsettings,
                                               const std::string& account);

}  // namespace nunchuk

#endif  // NUNCHUK_SYNCHRONIZER_H
