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

PrimaryKey::PrimaryKey() {}
PrimaryKey::PrimaryKey(const std::string& name,
                       const std::string& master_fingerprint,
                       const std::string& account, const std::string& address)
    : name_(name),
      master_fingerprint_(master_fingerprint),
      account_(account),
      address_(address) {}

std::string PrimaryKey::get_name() const { return name_; }
std::string PrimaryKey::get_master_fingerprint() const {
  return master_fingerprint_;
}
std::string PrimaryKey::get_account() const { return account_; }
std::string PrimaryKey::get_address() const { return address_; }
std::string PrimaryKey::get_decoy_pin() const { return decoy_pin_; }

void PrimaryKey::set_name(const std::string& value) { name_ = value; }
void PrimaryKey::set_decoy_pin(const std::string& value) { decoy_pin_ = value; }

}  // namespace nunchuk