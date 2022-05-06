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
#include <utils/json.hpp>

using json = nlohmann::json;

namespace nunchuk {

RoomWallet::RoomWallet() {}
RoomWallet::RoomWallet(const std::string& from_json) {
  json value = json::parse(from_json);
  set_room_id(value["room_id"]);
  set_wallet_id(value["wallet_id"]);
  set_init_event_id(value["init_event_id"]);
  set_join_event_ids(value["join_event_ids"]);
  set_leave_event_ids(value["leave_event_ids"]);
  set_finalize_event_id(value["finalize_event_id"]);
  set_cancel_event_id(value["cancel_event_id"]);
  set_delete_event_id(value["delete_event_id"]);
  if (value["ready_event_id"] != nullptr) {
    set_ready_event_id(value["ready_event_id"]);
  }
}
std::string RoomWallet::to_json() const {
  json value{};
  value["room_id"] = get_room_id();
  value["wallet_id"] = get_wallet_id();
  value["init_event_id"] = get_init_event_id();
  value["join_event_ids"] = get_join_event_ids();
  value["leave_event_ids"] = get_leave_event_ids();
  value["finalize_event_id"] = get_finalize_event_id();
  value["cancel_event_id"] = get_cancel_event_id();
  value["delete_event_id"] = get_delete_event_id();
  value["ready_event_id"] = get_ready_event_id();
  return value.dump();
}
void RoomWallet::merge(const RoomWallet& w) {
  if (!w.wallet_id_.empty()) wallet_id_ = w.wallet_id_;
  if (!w.join_event_ids_.empty()) join_event_ids_ = w.join_event_ids_;
  if (!w.leave_event_ids_.empty()) leave_event_ids_ = w.leave_event_ids_;
  if (!w.finalize_event_id_.empty()) finalize_event_id_ = w.finalize_event_id_;
  if (!w.cancel_event_id_.empty()) cancel_event_id_ = w.cancel_event_id_;
  if (!w.delete_event_id_.empty()) delete_event_id_ = w.delete_event_id_;
  if (!w.ready_event_id_.empty()) ready_event_id_ = w.ready_event_id_;
}

std::string RoomWallet::get_room_id() const { return room_id_; }
std::string RoomWallet::get_wallet_id() const { return wallet_id_; }
std::string RoomWallet::get_init_event_id() const { return init_event_id_; }
std::vector<std::string> RoomWallet::get_join_event_ids() const {
  return join_event_ids_;
}
std::vector<std::string> RoomWallet::get_leave_event_ids() const {
  return leave_event_ids_;
}
std::string RoomWallet::get_finalize_event_id() const {
  return finalize_event_id_;
}
std::string RoomWallet::get_cancel_event_id() const { return cancel_event_id_; }
std::string RoomWallet::get_ready_event_id() const { return ready_event_id_; }
std::string RoomWallet::get_delete_event_id() const { return delete_event_id_; }
std::string RoomWallet::get_json_content() const { return json_content_; }
Chain RoomWallet::get_chain() const { return chain_; }

void RoomWallet::set_room_id(const std::string& value) { room_id_ = value; }
void RoomWallet::set_wallet_id(const std::string& value) { wallet_id_ = value; }
void RoomWallet::set_init_event_id(const std::string& value) {
  init_event_id_ = value;
}
void RoomWallet::set_join_event_ids(const std::vector<std::string>& value) {
  join_event_ids_ = value;
}
void RoomWallet::set_leave_event_ids(const std::vector<std::string>& value) {
  leave_event_ids_ = value;
}
void RoomWallet::add_join_event_id(const std::string& value) {
  join_event_ids_.push_back(value);
}
void RoomWallet::add_leave_event_id(const std::string& value) {
  leave_event_ids_.push_back(value);
}
void RoomWallet::set_finalize_event_id(const std::string& value) {
  finalize_event_id_ = value;
}
void RoomWallet::set_cancel_event_id(const std::string& value) {
  cancel_event_id_ = value;
}
void RoomWallet::set_ready_event_id(const std::string& value) {
  ready_event_id_ = value;
}
void RoomWallet::set_delete_event_id(const std::string& value) {
  delete_event_id_ = value;
}
void RoomWallet::set_json_content(const std::string& value) {
  json_content_ = value;
}
void RoomWallet::set_chain(const Chain& value) { chain_ = value; }

}  // namespace nunchuk