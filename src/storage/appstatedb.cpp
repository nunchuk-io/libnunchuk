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

#include "appstatedb.h"
#include <utils/stringutils.hpp>
#include <algorithm>
#include <iostream>

namespace nunchuk {

void NunchukAppStateDb::Init() { CreateTable(); }

int NunchukAppStateDb::GetChainTip() const { return GetInt(DbKeys::CHAIN_TIP); }

bool NunchukAppStateDb::SetChainTip(int value) {
  return PutInt(DbKeys::CHAIN_TIP, value);
}

std::string NunchukAppStateDb::GetSelectedWallet() const {
  return GetString(DbKeys::SELECTED_WALLET);
}

bool NunchukAppStateDb::SetSelectedWallet(const std::string &value) {
  return PutString(DbKeys::SELECTED_WALLET, value);
}

int64_t NunchukAppStateDb::GetStorageVersion() const {
  return GetInt(DbKeys::VERSION);
}

bool NunchukAppStateDb::SetStorageVersion(int64_t value) {
  return PutInt(DbKeys::VERSION, value);
}

time_t NunchukAppStateDb::GetLastSyncTs() const {
  return GetInt(DbKeys::SYNC_TS);
}

bool NunchukAppStateDb::SetLastSyncTs(time_t value) {
  return PutInt(DbKeys::SYNC_TS, value);
}

time_t NunchukAppStateDb::GetLastExportTs() const {
  return GetInt(DbKeys::EXPORT_TS);
}

bool NunchukAppStateDb::SetLastExportTs(time_t value) {
  return PutInt(DbKeys::EXPORT_TS, value);
}

std::vector<std::string> NunchukAppStateDb::GetDeletedSigners() const {
  auto str = GetString(DbKeys::DELETED_SIGNERS);
  return split(str, ',');
}

bool NunchukAppStateDb::AddDeletedSigners(const std::string &id) {
  auto ids = GetDeletedSigners();
  if (std::find(ids.begin(), ids.end(), id) != ids.end()) return false;
  ids.push_back(id);
  return PutString(DbKeys::DELETED_SIGNERS, join(ids, ','));
}

std::vector<std::string> NunchukAppStateDb::GetDeletedWallets() const {
  auto str = GetString(DbKeys::DELETED_WALLETS);
  return split(str, ',');
}

bool NunchukAppStateDb::AddDeletedWallets(const std::string &id) {
  auto ids = GetDeletedWallets();
  if (std::find(ids.begin(), ids.end(), id) != ids.end()) return false;
  ids.push_back(id);
  return PutString(DbKeys::DELETED_WALLETS, join(ids, ','));
}

}  // namespace nunchuk