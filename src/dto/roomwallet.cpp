// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nunchukmatrix.h>

namespace nunchuk {

RoomWallet::RoomWallet() {}

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

}  // namespace nunchuk