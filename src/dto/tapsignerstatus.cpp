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

#include "nunchuk.h"
namespace nunchuk {

TapsignerStatus::TapsignerStatus() {}
const std::string& TapsignerStatus::get_card_ident() const {
  return card_ident_;
}
int TapsignerStatus::get_birth_height() const { return birth_height_; }
int TapsignerStatus::get_number_of_backup() const { return number_of_backup_; }
std::string TapsignerStatus::get_current_derivation() const {
  return current_derivation_.value_or(std::string{});
}
const std::string& TapsignerStatus::get_version() const { return version_; }
const std::vector<unsigned char>& TapsignerStatus::get_backup_data() const {
  return backup_data_;
}
const std::string& TapsignerStatus::get_master_signer_id() const {
  return master_signer_id_;
}
bool TapsignerStatus::is_testnet() const { return is_testnet_; }
int TapsignerStatus::get_auth_delay() const { return auth_delay_; }
bool TapsignerStatus::need_setup() const {
  return !current_derivation_.has_value();
}
bool TapsignerStatus::is_master_signer() const {
  return !master_signer_id_.empty();
}
void TapsignerStatus::set_card_ident(const std::string& card_ident) {
  card_ident_ = card_ident;
}

void TapsignerStatus::set_number_of_backup(int number_of_backup) {
  number_of_backup_ = number_of_backup;
}
void TapsignerStatus::set_current_derivation(
    const std::string& current_derivation) {
  current_derivation_ = current_derivation;
}
void TapsignerStatus::set_birth_height(int birth_height) {
  birth_height_ = birth_height;
}
void TapsignerStatus::set_version(const std::string& version) {
  version_ = version;
}
void TapsignerStatus::set_testnet(bool is_testnet) { is_testnet_ = is_testnet; }
void TapsignerStatus::set_auth_delay(int auth_delay) {
  auth_delay_ = auth_delay;
}
void TapsignerStatus::set_backup_data(
    const std::vector<unsigned char>& backup_data) {
  backup_data_ = backup_data;
}
void TapsignerStatus::set_master_signer_id(
    const std::string& master_signer_id) {
  master_signer_id_ = master_signer_id;
}

TapsignerStatus::TapsignerStatus(
    const std::string& card_ident, int birth_height, int number_of_backup,
    const std::string& version,
    const std::optional<std::string>& current_derivation, bool is_testnet,
    int auth_delay, const std::string& master_signer_id,
    const std::vector<unsigned char>& backup_data)
    : card_ident_(card_ident),
      birth_height_(birth_height),
      number_of_backup_(number_of_backup),
      current_derivation_(current_derivation),
      version_(version),
      is_testnet_(is_testnet),
      auth_delay_(auth_delay),
      master_signer_id_(master_signer_id),
      backup_data_(backup_data) {}

}  // namespace nunchuk
