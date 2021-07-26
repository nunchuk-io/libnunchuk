// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nunchukmatrix.h>

namespace nunchuk {

RoomSharedWallet::RoomSharedWallet() {}

std::string RoomSharedWallet::get_wallet_id() const { return wallet_id_; }
std::string RoomSharedWallet::get_init_id() const { return init_id_; }
std::vector<std::string> RoomSharedWallet::get_join_ids() const {
  return join_ids_;
}
std::vector<std::string> RoomSharedWallet::get_leave_ids() const {
  return leave_ids_;
}
std::string RoomSharedWallet::get_finalize_id() const { return finalize_id_; }
std::string RoomSharedWallet::get_cancel_id() const { return cancel_id_; }
std::string RoomSharedWallet::get_pin_data() const { return pin_data_; }

void RoomSharedWallet::set_wallet_id(const std::string& value) {
  wallet_id_ = value;
}
void RoomSharedWallet::set_init_id(const std::string& value) {
  init_id_ = value;
}
void RoomSharedWallet::add_join_id(const std::string& value) {
  join_ids_.push_back(value);
}
void RoomSharedWallet::add_leave_id(const std::string& value) {
  leave_ids_.push_back(value);
}
void RoomSharedWallet::set_finalize_id(const std::string& value) {
  finalize_id_ = value;
}
void RoomSharedWallet::set_cancel_id(const std::string& value) {
  cancel_id_ = value;
}

}  // namespace nunchuk