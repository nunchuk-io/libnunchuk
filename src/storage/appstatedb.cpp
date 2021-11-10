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

time_t NunchukAppStateDb::GetLastSyncTs() const {
  return GetInt(DbKeys::SYNC_TS);
}

bool NunchukAppStateDb::SetLastSyncTs(time_t value) {
  return PutInt(DbKeys::SYNC_TS, value);
}

}  // namespace nunchuk