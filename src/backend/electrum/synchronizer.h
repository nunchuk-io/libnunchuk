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

#ifndef NUNCHUK_ELECTRUM_SYNCHRONIZER_H
#define NUNCHUK_ELECTRUM_SYNCHRONIZER_H

#include <backend/synchronizer.h>
#include <backend/electrum/client.h>
#include <condition_variable>
#include <thread>

namespace nunchuk {

class ElectrumSynchronizer : public Synchronizer {
 public:
  using Synchronizer::Synchronizer;
  ElectrumSynchronizer(const ElectrumSynchronizer&) = delete;
  ElectrumSynchronizer& operator=(const ElectrumSynchronizer&) = delete;
  ~ElectrumSynchronizer();

  void Broadcast(const std::string& raw_tx);
  Amount EstimateFee(int conf_target);
  Amount RelayFee();
  bool LookAhead(Chain chain, const std::string& wallet_id,
                 const std::string& address, int index, bool internal);
  void RescanBlockchain(int start_height, int stop_height);
  std::vector<UnspentOutput> ListUnspent(const std::string& address) override;
  std::string GetRawTx(const std::string& tx_id) override;

  void Run();

 private:
  enum class Status {
    UNINITIALIZED,
    CONNECTING,
    SYNCING,
    READY,
    STOPPED,
  };

  void UpdateTransactions(Chain chain, const std::string& wallet_id,
                          const json& history);
  void UpdateScripthashStatus(Chain chain, const std::string& scripthash,
                              const std::string& status,
                              bool check_balance = true);
  void OnScripthashStatusChange(Chain chain, const json& notification);
  std::pair<std::string, std::string> SubscribeAddress(
      const std::string& wallet_id, const std::string& address);
  void BlockchainSync(Chain chain);
  void WaitForReady();

  std::unique_ptr<ElectrumClient> client_;

  Status status_ = Status::UNINITIALIZED;
  std::mutex status_mutex_;
  std::condition_variable status_cv_;

  // Cache
  std::map<std::string, std::pair<std::string, std::string>>
      scripthash_to_wallet_address_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_ELECTRUM_SYNCHRONIZER_H
