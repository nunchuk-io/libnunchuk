// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nunchukmatrix.h>

namespace nunchuk {

RoomWallet::RoomWallet() {}

std::string RoomWallet::get_wallet_id() const { return wallet_id_; }
std::string RoomWallet::get_init_id() const { return init_id_; }
std::vector<std::string> RoomWallet::get_join_ids() const {
  return join_ids_;
}
std::vector<std::string> RoomWallet::get_leave_ids() const {
  return leave_ids_;
}
std::string RoomWallet::get_finalize_id() const { return finalize_id_; }
std::string RoomWallet::get_cancel_id() const { return cancel_id_; }
std::string RoomWallet::get_pin_data() const { return pin_data_; }

void RoomWallet::set_wallet_id(const std::string& value) {
  wallet_id_ = value;
}
void RoomWallet::set_init_id(const std::string& value) {
  init_id_ = value;
}
void RoomWallet::add_join_id(const std::string& value) {
  join_ids_.push_back(value);
}
void RoomWallet::add_leave_id(const std::string& value) {
  leave_ids_.push_back(value);
}
void RoomWallet::set_finalize_id(const std::string& value) {
  finalize_id_ = value;
}
void RoomWallet::set_cancel_id(const std::string& value) {
  cancel_id_ = value;
}

}  // namespace nunchuk