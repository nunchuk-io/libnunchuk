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

#include <backend/corerpc/synchronizer.h>

using namespace boost::asio;
using json = nlohmann::json;

namespace nunchuk {

CoreRpcSynchronizer::CoreRpcSynchronizer(const AppSettings& app_settings,
                                         const std::string& account)
    : Synchronizer(app_settings, account),
      interval_(60),
      timer_(io_service_, boost::posix_time::seconds(10)) {}

CoreRpcSynchronizer::~CoreRpcSynchronizer() {
  stopped = true;
  timer_.cancel();
  sync_worker_.reset();
  sync_thread_.join();
}

void CoreRpcSynchronizer::Run() {
  connection_listener_(ConnectionStatus::OFFLINE, 0);
  client_ = std::unique_ptr<CoreRpcClient>(new CoreRpcClient(app_settings_));
  timer_.async_wait(boost::bind(&CoreRpcSynchronizer::BlockchainSync, this,
                                placeholders::error));
}

void CoreRpcSynchronizer::Broadcast(const std::string& raw_tx) {
  if (stopped)
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           "Disconnected");
  client_->Broadcast(raw_tx);
}

Amount CoreRpcSynchronizer::EstimateFee(int conf_target) {
  if (stopped)
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           "Disconnected");
  return client_->EstimateFee(conf_target);
}

Amount CoreRpcSynchronizer::RelayFee() {
  if (stopped)
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           "Disconnected");
  return client_->RelayFee();
}

bool CoreRpcSynchronizer::LookAhead(Chain chain, const std::string& wallet_id,
                                    const std::string& address, int index,
                                    bool internal) {
  if (stopped) return false;
  json all_txs = client_->ListTransactions();
  for (auto it = all_txs.begin(); it != all_txs.end(); ++it) {
    json item = it.value();
    if (item["address"].get<std::string>() == address) {
      storage_->AddAddress(chain, wallet_id, address, index, internal);

      json utxos;
      auto all_utxos = client_->ListUnspent();
      for (auto&& utxo : all_utxos) {
        if (utxo["address"].get<std::string>() == address) {
          utxos.push_back(utxo);
        }
      }
      storage_->SetUtxos(chain, wallet_id, address, utxos.dump());
      return true;
    }
  }
  return false;
}

void CoreRpcSynchronizer::RescanBlockchain(int start_height, int stop_height) {
  if (stopped) return;
  connection_listener_(ConnectionStatus::SYNCING, 0);
  client_->RescanBlockchain(start_height, stop_height);
}

bool CoreRpcSynchronizer::IsRpcReady() {
  try {
    if (stopped) return false;
    auto info = client_->GetWalletInfo();
    if (info["scanning"].is_boolean() && !info["scanning"].get<bool>()) {
      return true;
    } else {
      int progress = info["scanning"]["progress"].get<double>() * 100;
      connection_listener_(ConnectionStatus::SYNCING, progress);
      return false;
    }
  } catch (RPCException& re) {
    if (re.code() != RPCException::RPC_WALLET_NOT_FOUND) {
      if (re.code() == RPCException::RPC_REQUEST_ERROR) {
        connection_listener_(ConnectionStatus::OFFLINE, 0);
      }
      throw;
    }
    CreateOrLoadWallet();
    return IsRpcReady();
  }
}

void CoreRpcSynchronizer::CreateOrLoadWallet() {
  try {
    client_->CreateWallet();
  } catch (RPCException& re) {
    if (re.code() != RPCException::RPC_WALLET_EXISTS) throw;
    client_->LoadWallet();
  }
}

void CoreRpcSynchronizer::BlockchainSync(
    const boost::system::error_code& error) {
  if (stopped) return;
  timer_.expires_at(timer_.expires_at() + interval_);
  timer_.async_wait(boost::bind(&CoreRpcSynchronizer::BlockchainSync, this,
                                placeholders::error));

  if (!IsRpcReady()) return;

  auto chain = app_settings_.get_chain();
  auto blockchain_info = client_->GetBlockchainInfo();
  if (chain_tip_ != blockchain_info["blocks"].get<int>()) {
    chain_tip_ = blockchain_info["blocks"].get<int>();
    storage_->SetChainTip(chain, chain_tip_);
    block_listener_(chain_tip_, blockchain_info["bestblockhash"]);
  }

  auto wallet_ids = storage_->ListWallets(chain);
  auto all_utxos = client_->ListUnspent();
  auto all_txs = client_->ListTransactions();
  json descriptors;
  for (auto&& wallet_id : wallet_ids) {
    if (stopped) return;
    auto addresses = storage_->GetAllAddresses(chain, wallet_id);
    if (addresses.empty()) continue;

    // check if wallet descriptor is imported
    auto address_info = client_->GetAddressInfo(addresses[0]);
    if (!address_info["solvable"].get<bool>()) {
      auto wallet = storage_->GetWallet(chain, wallet_id);
      if (wallet.is_escrow()) {
        descriptors.push_back(
            {{"desc", wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL)},
             {"active", true},
             {"timestamp", wallet.get_create_date()},
             {"internal", false},
             {"watchonly", true}});
      } else {
        descriptors.push_back(
            {{"desc", wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL)},
             {"active", true},
             {"range", 1000},
             {"timestamp", wallet.get_create_date()},
             {"internal", false},
             {"watchonly", true}});
        descriptors.push_back(
            {{"desc", wallet.get_descriptor(DescriptorPath::INTERNAL_ALL)},
             {"active", true},
             {"range", 1000},
             {"timestamp", wallet.get_create_date()},
             {"internal", true},
             {"watchonly", true}});
      }
    }

    auto txs = storage_->GetTransactions(chain, wallet_id, 1000, 0);
    for (auto a = addresses.rbegin(); a != addresses.rend(); ++a) {
      if (stopped) return;
      auto address = *a;
      json utxos;
      for (auto&& utxo : all_utxos) {
        if (utxo["address"].get<std::string>() == address) {
          utxos.push_back(utxo);
        }
      }
      storage_->SetUtxos(chain, wallet_id, address, utxos.dump());

      for (auto it = all_txs.begin(); it != all_txs.end(); ++it) {
        json item = it.value();
        std::string tx_id = item["txid"];
        int height = item.value("blockheight", 0);

        bool found = false;
        for (auto&& tx : txs) {
          if (stopped) return;
          if (tx.get_txid() == tx_id) {
            if (tx.get_status() != TransactionStatus::CONFIRMED && height > 0) {
              auto tx = client_->GetTransaction(tx_id);
              storage_->UpdateTransaction(chain, wallet_id, tx["hex"], height,
                                          tx["blocktime"]);
              transaction_listener_(tx_id, TransactionStatus::CONFIRMED,
                                    wallet_id);
            }
            found = true;
            break;
          }
        }
        if (!found && item["address"].get<std::string>() == address) {
          auto tx = client_->GetTransaction(tx_id);
          time_t time =
              tx["blocktime"] == nullptr ? 0 : time_t(tx["blocktime"]);
          storage_->InsertTransaction(chain, wallet_id, tx["hex"], height,
                                      time);
          auto status = height <= 0 ? TransactionStatus::PENDING_CONFIRMATION
                                    : TransactionStatus::CONFIRMED;
          transaction_listener_(tx_id, status, wallet_id);
        }
      }
    }

    Amount balance = storage_->GetBalance(chain, wallet_id);
    balance_listener_(wallet_id, balance);
  }

  if (stopped) return;
  if (!descriptors.empty()) {
    connection_listener_(ConnectionStatus::SYNCING, 0);
    client_->ImportDescriptors(descriptors.dump());
  } else {
    connection_listener_(ConnectionStatus::ONLINE, 100);
  }
}

std::vector<UnspentOutput> CoreRpcSynchronizer::ListUnspent(
    const std::string& address) {
  throw NunchukException(NunchukException::VERSION_NOT_SUPPORTED,
                         "Not support for core rpc");
}

std::string CoreRpcSynchronizer::GetRawTx(const std::string& tx_id) {
  throw NunchukException(NunchukException::VERSION_NOT_SUPPORTED,
                         "Not support for core rpc");
}

Transaction CoreRpcSynchronizer::GetTransaction(const std::string& tx_id) {
  throw NunchukException(NunchukException::VERSION_NOT_SUPPORTED,
                         "Not support for core rpc");
}
}  // namespace nunchuk
