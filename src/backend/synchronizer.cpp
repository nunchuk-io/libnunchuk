// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <backend/electrum/synchronizer.h>
#include <backend/corerpc/synchronizer.h>

using namespace boost::asio;

namespace nunchuk {

std::unique_ptr<Synchronizer> MakeSynchronizer(const AppSettings& app_settings,
                                               NunchukStorage* storage) {
  if (app_settings.get_backend_type() == BackendType::CORERPC) {
    return std::unique_ptr<CoreRpcSynchronizer>(
        new CoreRpcSynchronizer(app_settings, storage));
  } else {
    return std::unique_ptr<ElectrumSynchronizer>(
        new ElectrumSynchronizer(app_settings, storage));
  }
}

Synchronizer::Synchronizer(const AppSettings& app_settings,
                           NunchukStorage* storage)
    : app_settings_(app_settings),
      storage_(storage),
      sync_thread_(),
      sync_worker_(make_work_guard(io_service_)) {
  sync_thread_ = std::thread([&]() {
    for (;;) {
      try {
        io_service_.run();
        break;  // exited normally
      } catch (...) {
      }
    }
  });
}

Synchronizer::~Synchronizer() {
  sync_worker_.reset();
  sync_thread_.join();
}

bool Synchronizer::NeedRecreate(const AppSettings& new_settings) {
  if (app_settings_.get_backend_type() != new_settings.get_backend_type() ||
      app_settings_.get_chain() != new_settings.get_chain())
    throw NunchukException(NunchukException::APP_RESTART_REQUIRED,
                           "app restart required");

  if (app_settings_.use_proxy() != new_settings.use_proxy()) return true;
  if (new_settings.use_proxy() &&
      (app_settings_.get_proxy_host() != new_settings.get_proxy_host() ||
       app_settings_.get_proxy_port() != new_settings.get_proxy_port() ||
       app_settings_.get_proxy_username() !=
           new_settings.get_proxy_username() ||
       app_settings_.get_proxy_password() != new_settings.get_proxy_password()))
    return true;

  if (new_settings.get_backend_type() == BackendType::CORERPC) {
    if (app_settings_.get_corerpc_host() != new_settings.get_corerpc_host() ||
        app_settings_.get_corerpc_port() != new_settings.get_corerpc_port() ||
        app_settings_.get_corerpc_username() !=
            new_settings.get_corerpc_username() ||
        app_settings_.get_corerpc_password() !=
            new_settings.get_corerpc_password())
      return true;
  } else {
    if ((new_settings.get_chain() == Chain::TESTNET &&
         app_settings_.get_testnet_servers() !=
             new_settings.get_testnet_servers()) ||
        (new_settings.get_chain() == Chain::MAIN &&
         app_settings_.get_mainnet_servers() !=
             new_settings.get_mainnet_servers()))
      return true;
  }
  return false;
}

void Synchronizer::AddBalanceListener(
    std::function<void(std::string, Amount)> listener) {
  balance_listener_.connect(listener);
}

void Synchronizer::AddBlockListener(
    std::function<void(int, std::string)> listener) {
  block_listener_.connect(listener);
}

void Synchronizer::AddTransactionListener(
    std::function<void(std::string, TransactionStatus)> listener) {
  transaction_listener_.connect(listener);
}

void Synchronizer::AddBlockchainConnectionListener(
    std::function<void(ConnectionStatus)> listener) {
  connection_listener_.connect(listener);
}

int Synchronizer::GetChainTip() {
  int rs = chain_tip_;
  if (rs <= 0) rs = storage_->GetChainTip(app_settings_.get_chain());
  return rs;
}

}  // namespace nunchuk