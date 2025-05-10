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

#include <nunchuk.h>
#include <vector>

namespace nunchuk {

UnspentOutput::UnspentOutput() {
  status_ = CoinStatus::INCOMING_PENDING_CONFIRMATION;
  schedule_time_ = -1;
}

std::string UnspentOutput::get_txid() const { return txid_; }
int UnspentOutput::get_vout() const { return vout_; }
std::string UnspentOutput::get_address() const { return address_; }
Amount UnspentOutput::get_amount() const { return amount_; }
int UnspentOutput::get_height() const { return height_; }
std::string UnspentOutput::get_memo() const { return memo_; }
bool UnspentOutput::is_change() const { return change_; }
bool UnspentOutput::is_locked() const { return locked_; }
std::vector<int> const& UnspentOutput::get_tags() const { return tags_; }
std::vector<int> const& UnspentOutput::get_collections() const {
  return collections_;
}
time_t UnspentOutput::get_blocktime() const { return blocktime_; }
time_t UnspentOutput::get_schedule_time() const { return schedule_time_; }
CoinStatus UnspentOutput::get_status() const { return status_; }
std::vector<int64_t> const& UnspentOutput::get_timelocks() const {
  return timelocks_;
}
Timelock::Based UnspentOutput::get_lock_based() const {
  if (timelocks_.empty()) return Timelock::Based::NONE;
  return timelocks_[0] < 500000000 ? Timelock::Based::HEIGHT_LOCK
                                   : Timelock::Based::TIME_LOCK;
}

void UnspentOutput::set_txid(const std::string& value) { txid_ = value; }
void UnspentOutput::set_vout(int value) { vout_ = value; }
void UnspentOutput::set_address(const std::string& value) { address_ = value; }
void UnspentOutput::set_amount(const Amount& value) { amount_ = value; }
void UnspentOutput::set_height(int value) { height_ = value; }
void UnspentOutput::set_memo(const std::string& value) { memo_ = value; }
void UnspentOutput::set_change(bool value) { change_ = value; }
void UnspentOutput::set_locked(bool value) { locked_ = value; }
void UnspentOutput::set_tags(std::vector<int> value) {
  tags_ = std::move(value);
}
void UnspentOutput::set_collections(std::vector<int> value) {
  collections_ = std::move(value);
}
void UnspentOutput::set_blocktime(time_t value) { blocktime_ = value; }
void UnspentOutput::set_schedule_time(time_t value) { schedule_time_ = value; }
void UnspentOutput::set_status(CoinStatus value) { status_ = value; }
void UnspentOutput::set_timelocks(std::vector<int64_t> value) {
  timelocks_ = std::move(value);
}

}  // namespace nunchuk