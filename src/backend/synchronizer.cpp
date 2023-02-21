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

#include <backend/electrum/synchronizer.h>
#include <backend/corerpc/synchronizer.h>

using namespace boost::asio;

namespace nunchuk {

std::unique_ptr<Synchronizer> MakeSynchronizer(const AppSettings& appsettings,
                                               const std::string& account) {
  if (appsettings.get_backend_type() == BackendType::CORERPC) {
    return std::unique_ptr<CoreRpcSynchronizer>(
        new CoreRpcSynchronizer(appsettings, account));
  } else {
    return std::unique_ptr<ElectrumSynchronizer>(
        new ElectrumSynchronizer(appsettings, account));
  }
}

Synchronizer::Synchronizer(const AppSettings& appsettings,
                           const std::string& account)
    : app_settings_(appsettings),
      storage_(NunchukStorage::get(account)),
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

Synchronizer::~Synchronizer() {}

bool Synchronizer::NeedRecreate(const AppSettings& new_settings) {
  if (app_settings_.get_backend_type() != new_settings.get_backend_type() ||
      app_settings_.get_chain() != new_settings.get_chain())
    throw NunchukException(NunchukException::APP_RESTART_REQUIRED,
                           "App restart required");

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
             new_settings.get_mainnet_servers()) ||
        (new_settings.get_chain() == Chain::SIGNET &&
         app_settings_.get_signet_servers() !=
             new_settings.get_signet_servers()))
      return true;
  }
  return false;
}

void Synchronizer::AddBalanceListener(
    std::function<void(std::string, Amount)> listener) {
  balance_listener_.connect(listener);
}

void Synchronizer::AddBalancesListener(
    std::function<void(std::string, Amount, Amount)> listener) {
  balances_listener_.connect(listener);
}

void Synchronizer::AddBlockListener(
    std::function<void(int, std::string)> listener) {
  block_listener_.connect(listener);
}

void Synchronizer::AddTransactionListener(
    std::function<void(std::string, TransactionStatus, std::string)> listener) {
  transaction_listener_.connect(listener);
}

void Synchronizer::AddBlockchainConnectionListener(
    std::function<void(ConnectionStatus, int)> listener) {
  connection_listener_.connect(listener);
}

int Synchronizer::GetChainTip() {
  int rs = chain_tip_;
  if (rs <= 0) rs = storage_->GetChainTip(app_settings_.get_chain());
  return rs;
}

}  // namespace nunchuk
