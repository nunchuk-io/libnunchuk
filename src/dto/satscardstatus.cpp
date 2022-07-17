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
SatscardStatus::SatscardStatus() {}
SatscardStatus::SatscardStatus(const std::string& card_ident, int birth_height,
                               const std::string& version, bool is_testnet,
                               int auth_delay, int active_slot_index,
                               int num_slot, std::vector<SatscardSlot> slots)
    : card_ident_(card_ident),
      birth_height_(birth_height),
      version_(version),
      is_testnet_(is_testnet),
      auth_delay_(auth_delay),
      active_slot_index_(active_slot_index),
      num_slot_(num_slot),
      slots_(std::move(slots)) {}

const std::string& SatscardStatus::get_card_ident() const {
  return card_ident_;
}
const std::string& SatscardStatus::get_version() const { return version_; }
int SatscardStatus::get_birth_height() const { return birth_height_; }
int SatscardStatus::get_auth_delay() const { return auth_delay_; }
bool SatscardStatus::is_testnet() const { return is_testnet_; }
bool SatscardStatus::need_setup() const {
  return get_active_slot().get_status() == SatscardSlot::Status::UNUSED;
}
bool SatscardStatus::is_used_up() const {
  return get_active_slot_index() == get_number_of_slots() ||
         (get_active_slot_index() == get_number_of_slots() - 1 &&
          get_active_slot().get_status() == SatscardSlot::Status::UNSEALED);
}
int SatscardStatus::get_active_slot_index() const { return active_slot_index_; }
int SatscardStatus::get_number_of_slots() const { return num_slot_; }
const SatscardSlot& SatscardStatus::get_active_slot() const {
  return slots_[active_slot_index_];
}
const std::vector<SatscardSlot>& SatscardStatus::get_slots() const {
  return slots_;
}
void SatscardStatus::set_card_ident(const std::string& card_ident) {
  card_ident_ = card_ident;
}
void SatscardStatus::set_birth_height(int birth_height) {
  birth_height_ = birth_height;
}
void SatscardStatus::set_version(const std::string& version) {
  version_ = version;
}
void SatscardStatus::set_testnet(bool is_testnet) { is_testnet_ = is_testnet; }
void SatscardStatus::set_auth_delay(int auth_delay) {
  auth_delay_ = auth_delay;
}
void SatscardStatus::set_active_slot_index(int index) {
  active_slot_index_ = index;
}
void SatscardStatus::set_number_of_slots(int index) {
  active_slot_index_ = index;
}
void SatscardStatus::set_slots(std::vector<SatscardSlot> slots) {
  slots = std::move(slots);
}

SatscardSlot::SatscardSlot() {}

SatscardSlot::SatscardSlot(int index, Status status, const std::string& address)
    : index_(index), status_(status), address_(address) {}

SatscardSlot::SatscardSlot(int index, Status status, const std::string& address,
                           std::vector<unsigned char> privkey,
                           std::vector<unsigned char> pubkey,
                           std::vector<unsigned char> chain_code,
                           std::vector<unsigned char> master_privkey)
    : index_(index),
      status_(status),
      address_(address),
      privkey_(std::move(privkey)),
      pubkey_(std::move(pubkey)),
      chain_code_(std::move(chain_code)),
      master_privkey_(std::move(master_privkey)) {}

int SatscardSlot::get_index() const { return index_; }
SatscardSlot::Status SatscardSlot::get_status() const { return status_; }
const std::string& SatscardSlot::get_address() const { return address_; }
Amount SatscardSlot::get_balance() const { return balance_; }

bool SatscardSlot::is_confirmed() const { return confirmed_; }
const std::vector<UnspentOutput>& SatscardSlot::get_utxos() const {
  return utxos_;
}

const std::vector<unsigned char>& SatscardSlot::get_privkey() const {
  return privkey_;
}
const std::vector<unsigned char>& SatscardSlot::get_pubkey() const {
  return pubkey_;
}
const std::vector<unsigned char>& SatscardSlot::get_chain_code() const {
  return chain_code_;
}
const std::vector<unsigned char>& SatscardSlot::get_master_privkey() const {
  return master_privkey_;
}

void SatscardSlot::set_index(int index) { index_ = index; }
void SatscardSlot::set_status(Status status) { status_ = status; }
void SatscardSlot::set_address(const std::string& address) {
  address_ = address;
}
void SatscardSlot::set_balance(const Amount& value) { balance_ = value; }
void SatscardSlot::set_confirmed(bool confirmed) { confirmed_ = confirmed; }
void SatscardSlot::set_utxos(std::vector<UnspentOutput> utxos) {
  utxos_ = std::move(utxos);
}
void SatscardSlot::set_privkey(std::vector<unsigned char> privkey) {
  privkey_ = std::move(privkey);
}
void SatscardSlot::set_pubkey(std::vector<unsigned char> pubkey) {
  pubkey_ = std::move(pubkey);
}
void SatscardSlot::set_chain_code(std::vector<unsigned char> chain_code) {
  chain_code_ = std::move(chain_code);
}
void SatscardSlot::set_master_privkey(
    std::vector<unsigned char> master_privkey) {
  master_privkey_ = std::move(master_privkey);
}

}  // namespace nunchuk
