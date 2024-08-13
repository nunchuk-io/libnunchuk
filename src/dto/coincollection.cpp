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

CoinCollection::CoinCollection(int id, const std::string& name)
    : id_(id), name_(name) {}

int CoinCollection::get_id() const { return id_; }
std::string CoinCollection::get_name() const { return name_; }
bool CoinCollection::is_add_new_coin() const { return add_new_coin_; }
bool CoinCollection::is_auto_lock() const { return auto_lock_; }
std::vector<int> const& CoinCollection::get_add_coins_with_tag() const {
  return add_tags_;
}

void CoinCollection::set_add_new_coin(bool value) { add_new_coin_ = value; }
void CoinCollection::set_auto_lock(bool value) { auto_lock_ = value; }
void CoinCollection::set_add_coins_with_tag(std::vector<int> value) {
  add_tags_ = std::move(value);
}

}  // namespace nunchuk