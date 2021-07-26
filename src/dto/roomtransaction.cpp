// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nunchukmatrix.h>

namespace nunchuk {

RoomTransaction::RoomTransaction() {}

std::string RoomTransaction::get_tx_id() const { return tx_id_; }
std::string RoomTransaction::get_wallet_id() const { return wallet_id_; }
std::string RoomTransaction::get_init_id() const { return init_id_; }
std::vector<std::string> RoomTransaction::get_sign_ids() const {
  return sign_ids_;
}
std::vector<std::string> RoomTransaction::get_reject_ids() const {
  return reject_ids_;
}
std::string RoomTransaction::get_broadcast_id() const {
  return broadcast_id_;
}
std::string RoomTransaction::get_cancel_id() const { return cancel_id_; }

void RoomTransaction::set_tx_id(const std::string& value) {
  tx_id_ = value;
}
void RoomTransaction::set_wallet_id(const std::string& value) {
  wallet_id_ = value;
}
void RoomTransaction::set_init_id(const std::string& value) {
  init_id_ = value;
}
void RoomTransaction::add_sign_id(const std::string& value) {
  sign_ids_.push_back(value);
}
void RoomTransaction::add_reject_id(const std::string& value) {
  reject_ids_.push_back(value);
}
void RoomTransaction::set_broadcast_id(const std::string& value) {
  broadcast_id_ = value;
}
void RoomTransaction::set_cancel_id(const std::string& value) {
  cancel_id_ = value;
}

}  // namespace nunchuk