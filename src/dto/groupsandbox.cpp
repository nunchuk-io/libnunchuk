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

GroupSandbox::GroupSandbox(const std::string& id) : id_(id) {};

std::string GroupSandbox::get_id() const { return id_; }
std::string GroupSandbox::get_name() const { return name_; }
std::string GroupSandbox::get_url() const { return url_; }
int GroupSandbox::get_m() const { return m_; }
int GroupSandbox::get_n() const { return n_; }
const std::vector<SingleSigner>& GroupSandbox::get_signers() const {
  return signers_;
}
AddressType GroupSandbox::get_address_type() const { return address_type_; }
WalletType GroupSandbox::get_wallet_type() const {
  return miniscript_template_.empty() ? WalletType::MULTI_SIG
                                      : WalletType::MINISCRIPT;
}
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
std::string GroupSandbox::get_miniscript_template() const {
  return miniscript_template_;
}
const std::optional<GroupPlatformKey>& GroupSandbox::get_platform_key() const {
  return platform_key_;
}
std::optional<int> GroupSandbox::get_platform_key_index() const {
  if (!platform_key_.has_value() || get_wallet_type() != WalletType::MULTI_SIG) {
    return std::nullopt;
  }
  return n_ > 0 ? std::make_optional(n_ - 1) : std::nullopt;
}
const std::vector<std::string>& GroupSandbox::get_platform_key_slots() const {
  return platform_key_slots_;
}
std::map<std::string, SingleSigner> GroupSandbox::get_named_signers() const {
  if (miniscript_template_.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Miniscript group only");
  }
  std::map<std::string, SingleSigner> rs{};
  int keypath_m = 0;
  auto names = Utils::ParseSignerNames(miniscript_template_, keypath_m);
  for (int i = 0; i < names.size(); i++) {
    if (i < signers_.size()) {
      rs[names[i]] = signers_[i];
    } else {
      rs[names[i]] = SingleSigner();
    }
  }
  return rs;
}
std::map<std::string, std::pair<time_t, std::string>>
GroupSandbox::get_named_occupied() const {
  if (miniscript_template_.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Miniscript group only");
  }
  std::map<std::string, std::pair<time_t, std::string>> rs{};
  int keypath_m = 0;
  auto names = Utils::ParseSignerNames(miniscript_template_, keypath_m);
  for (int i = 0; i < names.size(); i++) {
    if (occupied_.contains(i)) {
      rs[names[i]] = occupied_.at(i);
    }
  }
  return rs;
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
void GroupSandbox::set_miniscript_template(const std::string& value) {
  miniscript_template_ = value;
}
void GroupSandbox::set_platform_key(std::optional<GroupPlatformKey> value) {
  platform_key_ = std::move(value);
}
void GroupSandbox::set_platform_key_slots(std::vector<std::string> value) {
  platform_key_slots_ = std::move(value);
}
}  // namespace nunchuk
