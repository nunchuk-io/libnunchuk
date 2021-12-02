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

#include <nunchukmatrix.h>

namespace nunchuk {

RoomTransaction::RoomTransaction() {}

std::string RoomTransaction::get_room_id() const { return room_id_; }
std::string RoomTransaction::get_tx_id() const { return tx_id_; }
std::string RoomTransaction::get_wallet_id() const { return wallet_id_; }
std::string RoomTransaction::get_init_event_id() const {
  return init_event_id_;
}
std::vector<std::string> RoomTransaction::get_sign_event_ids() const {
  return sign_event_ids_;
}
std::vector<std::string> RoomTransaction::get_reject_event_ids() const {
  return reject_event_ids_;
}
std::string RoomTransaction::get_broadcast_event_id() const {
  return broadcast_event_id_;
}
std::string RoomTransaction::get_cancel_event_id() const {
  return cancel_event_id_;
}
std::string RoomTransaction::get_ready_event_id() const {
  return ready_event_id_;
}
Transaction RoomTransaction::get_tx() const { return tx_; }

void RoomTransaction::set_room_id(const std::string& value) {
  room_id_ = value;
}
void RoomTransaction::set_tx_id(const std::string& value) { tx_id_ = value; }
void RoomTransaction::set_wallet_id(const std::string& value) {
  wallet_id_ = value;
}
void RoomTransaction::set_init_event_id(const std::string& value) {
  init_event_id_ = value;
}
void RoomTransaction::set_sign_event_ids(
    const std::vector<std::string>& value) {
  sign_event_ids_ = value;
}
void RoomTransaction::set_reject_event_ids(
    const std::vector<std::string>& value) {
  reject_event_ids_ = value;
}
void RoomTransaction::add_sign_event_id(const std::string& value) {
  sign_event_ids_.push_back(value);
}
void RoomTransaction::add_reject_event_id(const std::string& value) {
  reject_event_ids_.push_back(value);
}
void RoomTransaction::set_broadcast_event_id(const std::string& value) {
  broadcast_event_id_ = value;
}
void RoomTransaction::set_cancel_event_id(const std::string& value) {
  cancel_event_id_ = value;
}
void RoomTransaction::set_ready_event_id(const std::string& value) {
  ready_event_id_ = value;
}
void RoomTransaction::set_tx(const Transaction& value) { tx_ = value; }

}  // namespace nunchuk