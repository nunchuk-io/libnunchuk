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
#include <descriptor.h>

namespace nunchuk {

GroupConfig::GroupConfig() {}

int GroupConfig::get_total() const { return total_; }
int GroupConfig::get_remain() const { return remain_; }
int GroupConfig::get_max_keys(AddressType address_type) const {
  return address_key_limits_.at(address_type);
}

void GroupConfig::set_total(int value) { total_ = value; }
void GroupConfig::set_remain(int value) { remain_ = value; }
void GroupConfig::set_max_keys(AddressType address_type, int value) {
  address_key_limits_[address_type] = value;
}

}  // namespace nunchuk
