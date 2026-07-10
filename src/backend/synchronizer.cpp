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
#include <coreutils.h>
#include <utils/addressutils.hpp>

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
    if (app_settings_.get_electrum_servers() !=
            new_settings.get_electrum_servers() ||
        app_settings_.get_liquid_servers() != new_settings.get_liquid_servers())
      return true;
  }
  return false;
}

void Synchronizer::AddBalancesListener(
    std::function<void(std::string, Amount, Amount,
                       const std::map<AssetId, Amount>&)>
        listener) {
  balances_listener_.connect(MakeSafeSlot(listener));
}

void Synchronizer::AddBlockListener(
    std::function<void(int, std::string, bool)> listener) {
  block_listener_.connect(MakeSafeSlot(listener));
}

void Synchronizer::AddTransactionListener(
    std::function<void(std::string, TransactionStatus, std::string)> listener) {
  transaction_listener_.connect(MakeSafeSlot(listener));
}

void Synchronizer::AddBlockchainConnectionListener(
    std::function<void(ConnectionStatus, int, bool)> listener) {
  connection_listener_.connect(MakeSafeSlot(listener));
}

void Synchronizer::NotifyTransactionUpdate(const std::string& wallet_id,
                                           const std::string& tx_id,
                                           TransactionStatus status) {
  transaction_listener_(tx_id, status, wallet_id);
}

void Synchronizer::NotifyBalancesUpdate(Chain chain,
                                        const std::string& wallet_id) {
  auto balances = storage_->GetBalances(chain, wallet_id);
  balances_listener_(wallet_id, balances.balance, balances.unconfirmed_balance,
                     balances.asset_balances);
}

int Synchronizer::GetChainTip(bool liquid) {
  int rs = liquid ? liquid_chain_tip_ : chain_tip_;
  if (rs <= 0) rs = storage_->GetChainTip(app_settings_.get_chain(), liquid);
  return rs;
}

std::string Synchronizer::NewAddress(Chain chain, const std::string& wallet_id,
                                     bool internal) {
  auto wallet = storage_->GetWallet(chain, wallet_id, false, false);
  int index =
      wallet.is_escrow()
          ? -1
          : storage_->GetCurrentAddressIndex(chain, wallet_id, internal) + 1;
  std::string descriptor;
  std::shared_ptr<wally::WallySigner> signer;
  std::string path;
  if (wallet.get_wallet_type() != WalletType::LIQUID) {
    descriptor = wallet.get_descriptor(internal ? DescriptorPath::INTERNAL_ALL
                                                : DescriptorPath::EXTERNAL_ALL);
  } else {
    signer = storage_->GetWallySignerForWallet(chain, wallet_id);
    path = wallet.get_signers()[0].get_derivation_path();
  }

  if (SupportBatchLookAhead()) {
    while (true) {
      std::vector<std::string> addresses;
      std::vector<int> indexes;
      for (int i = index; i < index + wallet.get_gap_limit(); i++) {
        addresses.push_back(
            DeriveAddress(descriptor, signer, path, i, internal));
        indexes.push_back(i);
      }
      int last = BatchLookAhead(chain, wallet_id, addresses, indexes, internal);
      if (last < wallet.get_gap_limit() - 1) {
        index = index + last + 1;
        auto address = DeriveAddress(descriptor, signer, path, index, internal);
        storage_->AddAddress(chain, wallet_id, address, index, internal);
        return address;
      }
      index = index + wallet.get_gap_limit();
    }
  }

  while (true) {
    auto address = DeriveAddress(descriptor, signer, path, index, internal);
    if (!LookAhead(chain, wallet_id, address, index, internal)) {
      storage_->AddAddress(chain, wallet_id, address, index, internal);
      return address;
    }
    index++;
  }
}

}  // namespace nunchuk
