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
  std::map<std::string, std::string> GetRawTxs(
      const std::vector<std::string> tx_ids) override;
  Transaction GetTransaction(const std::string& tx_id) override;

  void Run() override;

 private:
  enum class Status {
    UNINITIALIZED,
    CONNECTING,
    SYNCING,
    READY,
    STOPPED,
  };

  bool UpdateTransactions(Chain chain, const std::string& wallet_id,
                          const json& history);
  bool UpdateTransactions(Chain chain, const std::string& wallet_id,
                          const json& history,
                          const std::map<std::string, std::string>& rawtx,
                          const std::map<int, std::string>& rawheader);
  void UpdateScripthashStatus(Chain chain, const std::string& scripthash,
                              const std::string& status,
                              bool check_balance = true);
  void UpdateScripthashesStatus(Chain chain,
                                const std::vector<std::string>& scripthashes,
                                const std::vector<std::string>& status);
  void OnScripthashStatusChange(Chain chain, const json& notification);
  std::pair<std::string, std::string> SubscribeAddress(
      const std::string& wallet_id, const std::string& address);
  std::map<std::string, std::string> SubscribeAddresses(
      const std::string& wallet_id, const std::vector<std::string>& addresses);
  void BlockchainSync(Chain chain);
  void WaitForReady();

  std::unique_ptr<ElectrumClient> client_;

  Status status_ = Status::UNINITIALIZED;
  std::mutex status_mutex_;
  std::condition_variable status_cv_;

  // Cache
  std::map<std::string, std::pair<std::string, std::string>>
      scripthash_to_wallet_address_;
  std::map<std::string, std::string> raw_tx_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_ELECTRUM_SYNCHRONIZER_H
