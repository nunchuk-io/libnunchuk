// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "synchronizer.h"
#include <utils/addressutils.hpp>

using namespace boost::asio;

namespace nunchuk {

static int CACHE_SECOND = 600;  // 10 minutes
static int RECONNECT_DELAY_SECOND = 3;
static long long SUBCRIBE_DELAY_MS = 100;

BlockSynchronizer::BlockSynchronizer(NunchukStorage* storage)
    : storage_(storage),
      sync_thread_(),
      sync_worker_(make_work_guard(io_service_)) {
  sync_thread_ = std::thread([&]() { io_service_.run(); });
}

BlockSynchronizer::~BlockSynchronizer() {
  {
    std::lock_guard<std::mutex> guard(status_mutex_);
    status_ = Status::STOPPED;
    status_cv_.notify_all();
  }
  sync_worker_.reset();
  sync_thread_.join();
}

bool BlockSynchronizer::NeedUpdateClient(const AppSettings& new_settings) {
  if (first_run_) {
    first_run_ = false;
    return true;
  }
  if (app_settings_.get_chain() != new_settings.get_chain()) return true;
  if (app_settings_.use_proxy() != new_settings.use_proxy()) return true;
  if (new_settings.use_proxy()) {
    if (app_settings_.get_proxy_host() != new_settings.get_proxy_host())
      return true;
    if (app_settings_.get_proxy_port() != new_settings.get_proxy_port())
      return true;
    if (app_settings_.get_proxy_password() != new_settings.get_proxy_password())
      return true;
    if (app_settings_.get_proxy_username() != new_settings.get_proxy_username())
      return true;
  }
  if (new_settings.get_chain() == Chain::TESTNET &&
      app_settings_.get_testnet_servers() != new_settings.get_testnet_servers())
    return true;
  if (new_settings.get_chain() == Chain::MAIN &&
      app_settings_.get_mainnet_servers() != new_settings.get_mainnet_servers())
    return true;
  return false;
}

void BlockSynchronizer::Run(const AppSettings& appsettings) {
  if (!NeedUpdateClient(appsettings)) {
    app_settings_ = appsettings;
    return;
  }
  app_settings_ = appsettings;
  Connect();
  WaitForReady();
}

void BlockSynchronizer::WaitForReady() {
  std::unique_lock<std::mutex> lock_(status_mutex_);
  status_cv_.wait(lock_, [&]() {
    return status_ == Status::READY || status_ == Status::SYNCING;
  });
}

void BlockSynchronizer::Connect() {
  {
    std::unique_lock<std::mutex> lock_(status_mutex_);
    status_cv_.wait(lock_, [&]() {
      return status_ == Status::UNINITIALIZED || status_ == Status::READY ||
             status_ == Status::STOPPED;
    });
    if (status_ == Status::STOPPED) return;
    status_ = Status::CONNECTING;
  }
  // Clear cache
  chain_tip_ = 0;
  scripthash_to_wallet_address_.clear();
  std::fill(estimate_fee_cached_time_, estimate_fee_cached_time_ + 3, 0);
  std::fill(estimate_fee_cached_value_, estimate_fee_cached_value_ + 3, 0);

  io_service_.post([&]() {
    try {
      client_ = std::unique_ptr<ElectrumClient>(
          new ElectrumClient(app_settings_, [&]() {
            io_service_.post([&]() {
              std::this_thread::sleep_for(
                  std::chrono::seconds(RECONNECT_DELAY_SECOND));
              Connect();
            });
          }));
    } catch (...) {
      std::lock_guard<std::mutex> guard(status_mutex_);
      status_ = Status::UNINITIALIZED;
      status_cv_.notify_all();
      return;
    }
    {
      std::lock_guard<std::mutex> guard(status_mutex_);
      status_ = Status::SYNCING;
      status_cv_.notify_all();
    }
    try {
      BlockchainSync(app_settings_.get_chain());
    } catch (...) {
      // TODO(Bakaoh): more elegant exeption handling
      // storage and CoreUtils chain-switch may cause exeption here
    }
    std::lock_guard<std::mutex> guard(status_mutex_);
    status_ = Status::READY;
    status_cv_.notify_all();
  });
}

void BlockSynchronizer::UpdateTransactions(Chain chain,
                                           const std::string& wallet_id,
                                           const json& history) {
  if (!history.is_array()) return;
  for (auto it = history.begin(); it != history.end(); ++it) {
    json item = it.value();
    std::string tx_id = item["tx_hash"];
    int height = item["height"];
    try {
      // TODO(Bakaoh): [optimize] use GetTransactions
      Transaction tx = storage_->GetTransaction(chain, wallet_id, tx_id);
      if (tx.get_status() != TransactionStatus::CONFIRMED && height > 0) {
        auto tx = client_.get()->blockchain_transaction_get(tx_id);
        storage_->UpdateTransaction(chain, wallet_id, tx["hex"], height,
                                    tx["blocktime"]);
        transaction_listener_(tx_id, TransactionStatus::CONFIRMED);
      }
    } catch (StorageException& se) {
      if (se.code() == StorageException::TX_NOT_FOUND) {
        auto tx = client_.get()->blockchain_transaction_get(tx_id);
        time_t time = tx["blocktime"] == nullptr ? 0 : time_t(tx["blocktime"]);
        Amount fee = 0;
        if (height <= 0) {
          height = 0;
          fee = Amount(item["fee"]);
        }
        storage_->InsertTransaction(chain, wallet_id, tx["hex"], height, time,
                                    fee);
        auto status = height <= 0 ? TransactionStatus::PENDING_CONFIRMATION
                                  : TransactionStatus::CONFIRMED;
        transaction_listener_(tx_id, status);
      }
    }
  }
}

void BlockSynchronizer::OnScripthashStatusChange(Chain chain,
                                                 const json& notification) {
  std::string scripthash = notification[0];
  if (scripthash_to_wallet_address_.count(scripthash) == 0) return;
  std::string wallet_id = scripthash_to_wallet_address_.at(scripthash).first;
  std::string address = scripthash_to_wallet_address_.at(scripthash).second;
  json utxo = client_.get()->blockchain_scripthash_listunspent(scripthash);
  storage_->SetUtxos(chain, wallet_id, address, utxo.dump());
  json history = client_.get()->blockchain_scripthash_get_history(scripthash);
  UpdateTransactions(chain, wallet_id, history);
  Amount balance = storage_->GetBalance(chain, wallet_id);
  balance_listener_(wallet_id, balance);
}

std::string BlockSynchronizer::SubscribeAddress(const std::string& wallet_id,
                                                const std::string& address) {
  std::string scripthash = AddressToScriptHash(address);
  scripthash_to_wallet_address_[scripthash] = {wallet_id, address};
  client_.get()->blockchain_scripthash_subscribe(scripthash);
  return scripthash;
}

void BlockSynchronizer::BlockchainSync(Chain chain) {
  connection_listener_(ConnectionStatus::OFFLINE);
  {
    std::unique_lock<std::mutex> lock_(status_mutex_);
    if (status_ != Status::READY && status_ != Status::SYNCING) return;
    auto header = client_.get()->blockchain_headers_subscribe([&](json rs) {
      chain_tip_ = rs[0]["height"];
      storage_->SetChainTip(app_settings_.get_chain(), chain_tip_);
      block_listener_(rs[0]["height"], rs[0]["hex"]);
    });
    connection_listener_(ConnectionStatus::SYNCING);
    chain_tip_ = header["height"];
    storage_->SetChainTip(chain, header["height"]);
    block_listener_(header["height"], header["hex"]);
    client_.get()->scripthash_add_listener([&](json notification) {
      OnScripthashStatusChange(app_settings_.get_chain(), notification);
    });
  }
  auto wallet_ids = storage_->ListWallets(chain);
  for (auto i = wallet_ids.rbegin(); i != wallet_ids.rend(); ++i) {
    auto wallet_id = *i;
    auto addresses = storage_->GetAllAddresses(chain, wallet_id);
    for (auto a = addresses.rbegin(); a != addresses.rend(); ++a) {
      std::unique_lock<std::mutex> lock_(status_mutex_);
      if (status_ != Status::READY && status_ != Status::SYNCING) return;
      auto address = *a;
      auto scripthash = SubscribeAddress(wallet_id, address);
      json utxo = client_.get()->blockchain_scripthash_listunspent(scripthash);
      storage_->SetUtxos(chain, wallet_id, address, utxo.dump());
      json history =
          client_.get()->blockchain_scripthash_get_history(scripthash);
      UpdateTransactions(chain, wallet_id, history);
      std::this_thread::sleep_for(std::chrono::milliseconds(SUBCRIBE_DELAY_MS));
    }
    Amount balance = storage_->GetBalance(chain, wallet_id);
    balance_listener_(wallet_id, balance);
  }
  connection_listener_(ConnectionStatus::ONLINE);
}

void BlockSynchronizer::Broadcast(const std::string& raw_tx) {
  std::unique_lock<std::mutex> lock_(status_mutex_);
  if (status_ != Status::READY && status_ != Status::SYNCING) {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           "Disconnected");
  }
  client_.get()->blockchain_transaction_broadcast(raw_tx);
}

Amount BlockSynchronizer::EstimateFee(int conf_target) {
  auto current_time = std::time(0);
  int cached_index = -1;
  switch (conf_target) {
    case CONF_TARGET_PRIORITY:
      cached_index = 0;
      break;
    case CONF_TARGET_STANDARD:
      cached_index = 1;
      break;
    case CONF_TARGET_ECONOMICAL:
      cached_index = 2;
      break;
  }
  if (cached_index >= 0 &&
      current_time - estimate_fee_cached_time_[cached_index] <= CACHE_SECOND) {
    return estimate_fee_cached_value_[cached_index];
  }
  std::unique_lock<std::mutex> lock_(status_mutex_);
  if (status_ != Status::READY && status_ != Status::SYNCING) {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           "Disconnected");
  }
  Amount rs = Utils::AmountFromValue(
      client_.get()->blockchain_estimatefee(conf_target).dump());
  if (cached_index >= 0) {
    estimate_fee_cached_value_[cached_index] = rs;
    estimate_fee_cached_time_[cached_index] = current_time;
  }
  return rs;
}

Amount BlockSynchronizer::RelayFee() {
  std::unique_lock<std::mutex> lock_(status_mutex_);
  if (status_ != Status::READY && status_ != Status::SYNCING) {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           "Disconnected");
  }
  return Utils::AmountFromValue(client_.get()->blockchain_relayfee().dump());
}

int BlockSynchronizer::GetChainTip() {
  int rs = chain_tip_;
  if (rs <= 0) rs = storage_->GetChainTip(app_settings_.get_chain());
  return rs;
}

void BlockSynchronizer::AddBalanceListener(
    std::function<void(std::string, Amount)> listener) {
  balance_listener_.connect(listener);
}

void BlockSynchronizer::AddBlockListener(
    std::function<void(int, std::string)> listener) {
  block_listener_.connect(listener);
}

void BlockSynchronizer::AddTransactionListener(
    std::function<void(std::string, TransactionStatus)> listener) {
  transaction_listener_.connect(listener);
}

void BlockSynchronizer::AddBlockchainConnectionListener(
    std::function<void(ConnectionStatus)> listener) {
  connection_listener_.connect(listener);
}

}  // namespace nunchuk