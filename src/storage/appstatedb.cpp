// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "appstatedb.h"

namespace nunchuk {

void NunchukAppStateDb::Init() { CreateTable(); }

int NunchukAppStateDb::GetChainTip() const { return GetInt(DbKeys::CHAIN_TIP); }

bool NunchukAppStateDb::SetChainTip(int value) {
  return PutInt(DbKeys::CHAIN_TIP, value);
}

std::string NunchukAppStateDb::GetSelectedWallet() const {
  return GetString(DbKeys::SELECTED_WALLET);
}

bool NunchukAppStateDb::SetSelectedWallet(const std::string& value) {
  return PutString(DbKeys::SELECTED_WALLET, value);
}

int64_t NunchukAppStateDb::GetStorageVersion() const {
  return GetInt(DbKeys::VERSION);
}

bool NunchukAppStateDb::SetStorageVersion(int64_t value) {
  return PutInt(DbKeys::VERSION, value);
}

}  // namespace nunchuk