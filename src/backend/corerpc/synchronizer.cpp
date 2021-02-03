// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <backend/corerpc/synchronizer.h>

using namespace boost::asio;
using json = nlohmann::json;

namespace nunchuk {

CoreRpcSynchronizer::~CoreRpcSynchronizer() { stopped = true; }

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
    if (re.code() != RPCException::RPC_WALLET_NOT_FOUND) throw;
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
  for (auto i = wallet_ids.rbegin(); i != wallet_ids.rend(); ++i) {
    auto wallet_id = *i;
    auto addresses = storage_->GetAllAddresses(chain, wallet_id);
    if (addresses.empty()) continue;

    // check if wallet descriptor is imported
    auto address_info = client_->GetAddressInfo(addresses[0]);
    if (!address_info["solvable"].get<bool>()) {
      auto wallet = storage_->GetWallet(chain, wallet_id);
      if (wallet.is_escrow()) {
        descriptors.push_back({{"desc", wallet.get_descriptor(false)},
                               {"active", true},
                               {"timestamp", 0},
                               {"internal", false},
                               {"watchonly", true}});
      } else {
        descriptors.push_back({{"desc", wallet.get_descriptor(false)},
                               {"active", true},
                               {"range", 1000},
                               {"timestamp", 0},
                               {"internal", false},
                               {"watchonly", true}});
        descriptors.push_back({{"desc", wallet.get_descriptor(true)},
                               {"active", true},
                               {"range", 1000},
                               {"timestamp", 0},
                               {"internal", true},
                               {"watchonly", true}});
      }
    }

    for (auto a = addresses.rbegin(); a != addresses.rend(); ++a) {
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
        if (item["address"].get<std::string>() != address) {
          continue;
        }
        std::string tx_id = item["txid"];
        int height = item["blockheight"];
        try {
          Transaction tx = storage_->GetTransaction(chain, wallet_id, tx_id);
          if (tx.get_status() != TransactionStatus::CONFIRMED && height > 0) {
            auto tx = client_->GetTransaction(tx_id);
            storage_->UpdateTransaction(chain, wallet_id, tx["hex"], height,
                                        tx["blocktime"]);
            transaction_listener_(tx_id, TransactionStatus::CONFIRMED);
          }
        } catch (StorageException& se) {
          if (se.code() == StorageException::TX_NOT_FOUND) {
            auto tx = client_->GetTransaction(tx_id);
            time_t time =
                tx["blocktime"] == nullptr ? 0 : time_t(tx["blocktime"]);
            storage_->InsertTransaction(chain, wallet_id, tx["hex"], height,
                                        time);
            auto status = height <= 0 ? TransactionStatus::PENDING_CONFIRMATION
                                      : TransactionStatus::CONFIRMED;
            transaction_listener_(tx_id, status);
          }
        }
      }
    }

    Amount balance = storage_->GetBalance(chain, wallet_id);
    balance_listener_(wallet_id, balance);
  }

  if (!descriptors.empty()) {
    connection_listener_(ConnectionStatus::SYNCING, 0);
    client_->ImportDescriptors(descriptors.dump());
  } else {
    connection_listener_(ConnectionStatus::ONLINE, 100);
  }
}

}  // namespace nunchuk