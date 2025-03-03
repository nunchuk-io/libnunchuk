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

GroupSandbox::GroupSandbox(const std::string& id) : id_(id){};

std::string GroupSandbox::get_id() const { return id_; }
std::string GroupSandbox::get_name() const { return name_; }
std::string GroupSandbox::get_url() const { return url_; }
int GroupSandbox::get_m() const { return m_; }
int GroupSandbox::get_n() const { return n_; }
const std::vector<SingleSigner>& GroupSandbox::get_signers() const {
  return signers_;
}
AddressType GroupSandbox::get_address_type() const { return address_type_; }
WalletTemplate GroupSandbox::get_wallet_template() const {
  return wallet_template_;
}
bool GroupSandbox::is_finalized() const { return finalized_; }
int GroupSandbox::get_state_id() const { return state_id_; }
const std::vector<std::string>& GroupSandbox::get_ephemeral_keys() const {
  return keys_;
}
std::string GroupSandbox::get_wallet_id() const { return wallet_id_; }
std::string GroupSandbox::get_pubkey() const { return pubkey_; }
const std::map<int, std::pair<time_t, std::string>>&
GroupSandbox::get_occupied() const {
  return occupied_;
}
std::string GroupSandbox::get_replace_wallet_id() const {
  return replace_wallet_id_;
}

void GroupSandbox::set_name(const std::string& value) { name_ = value; }
void GroupSandbox::set_url(const std::string& value) { url_ = value; }
void GroupSandbox::set_n(int n) { n_ = n; }
void GroupSandbox::set_m(int m) { m_ = m; }
void GroupSandbox::set_signers(std::vector<SingleSigner> signers) {
  signers_ = std::move(signers);
}
void GroupSandbox::set_address_type(AddressType value) {
  address_type_ = value;
}
void GroupSandbox::set_wallet_template(WalletTemplate value) {
  wallet_template_ = value;
}
void GroupSandbox::set_finalized(bool value) { finalized_ = value; }
void GroupSandbox::set_ephemeral_keys(std::vector<std::string> keys) {
  keys_ = std::move(keys);
}
void GroupSandbox::set_state_id(int value) { state_id_ = value; }
void GroupSandbox::set_wallet_id(const std::string& value) {
  wallet_id_ = value;
}
void GroupSandbox::set_pubkey(const std::string& value) { pubkey_ = value; }
void GroupSandbox::add_occupied(int index, time_t ts, const std::string& uid) {
  occupied_[index] = {ts, uid};
}
void GroupSandbox::remove_occupied(int index) { occupied_.erase(index); }
void GroupSandbox::set_replace_wallet_id(const std::string& value) {
  replace_wallet_id_ = value;
}
}  // namespace nunchuk
