// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_ELECTRUM_SYNCHRONIZER_H
#define NUNCHUK_ELECTRUM_SYNCHRONIZER_H

#include <backend/synchronizer.h>
#include <backend/electrum/client.h>
#include <condition_variable>

namespace nunchuk {

const int ESTIMATE_FEE_CACHE_SIZE = 3;

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
  void OnScripthashStatusChange(Chain chain, const json& notification);
  std::string SubscribeAddress(const std::string& wallet_id,
                               const std::string& address);
  void BlockchainSync(Chain chain);
  void WaitForReady();

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

#endif  // NUNCHUK_ELECTRUM_SYNCHRONIZER_H
