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

namespace nunchuk {

Transaction::Transaction() {}

std::string Transaction::get_txid() const { return txid_; }
int Transaction::get_height() const { return height_; }
std::vector<TxInput> const& Transaction::get_inputs() const { return inputs_; }
std::vector<TxOutput> const& Transaction::get_outputs() const {
  return outputs_;
}
std::vector<TxOutput> const& Transaction::get_user_outputs() const {
  return user_outputs_;
}
std::vector<TxOutput> const& Transaction::get_receive_outputs() const {
  return receive_output_;
}
int Transaction::get_change_index() const { return change_index_; }
int Transaction::get_m() const { return m_; }
std::map<std::string, bool> const& Transaction::get_signers() const {
  return signers_;
}
std::string Transaction::get_memo() const { return memo_; }
TransactionStatus Transaction::get_status() const { return status_; }
std::string Transaction::get_replaced_by_txid() const {
  return replaced_by_txid_;
}
std::string Transaction::get_replace_txid() const { return replace_txid_; }
Amount Transaction::get_fee() const { return fee_; }
Amount Transaction::get_fee_rate() const { return fee_rate_; }
time_t Transaction::get_blocktime() const { return blocktime_; }
bool Transaction::subtract_fee_from_amount() const {
  return subtract_fee_from_amount_;
}
bool Transaction::is_receive() const { return is_receive_; }
Amount Transaction::get_sub_amount() const { return sub_amount_; }
std::string Transaction::get_psbt() const { return psbt_; }
std::string Transaction::get_raw() const { return raw_; }
std::string Transaction::get_reject_msg() const { return reject_msg_; }
time_t Transaction::get_schedule_time() const { return schedule_time_; }

void Transaction::set_txid(const std::string& value) { txid_ = value; }
void Transaction::set_height(int value) { height_ = value; }
void Transaction::add_input(const TxInput& value) { inputs_.push_back(value); }
void Transaction::add_output(const TxOutput& value) {
  outputs_.push_back(value);
}
void Transaction::add_user_output(const TxOutput& value) {
  user_outputs_.push_back(value);
}
void Transaction::add_receive_output(const TxOutput& value) {
  receive_output_.push_back(value);
}
void Transaction::set_change_index(int value) { change_index_ = value; }
void Transaction::set_m(int value) { m_ = value; }
void Transaction::set_signer(const std::string& signer_id, bool has_signature) {
  signers_[signer_id] = has_signature;
}
void Transaction::set_memo(const std::string& value) { memo_ = value; }
void Transaction::set_status(TransactionStatus value) { status_ = value; }
void Transaction::set_replaced_by_txid(const std::string& value) {
  replaced_by_txid_ = value;
}
void Transaction::set_replace_txid(const std::string& value) {
  replace_txid_ = value;
}
void Transaction::set_fee(const Amount& value) { fee_ = value; }
void Transaction::set_fee_rate(const Amount& value) { fee_rate_ = value; }
void Transaction::set_blocktime(time_t value) { blocktime_ = value; }
void Transaction::set_subtract_fee_from_amount(bool value) {
  subtract_fee_from_amount_ = value;
}
void Transaction::set_receive(bool value) { is_receive_ = value; }
void Transaction::set_sub_amount(const Amount& value) { sub_amount_ = value; }
void Transaction::set_psbt(const std::string& value) { psbt_ = value; }
void Transaction::set_raw(const std::string& value) { raw_ = value; }
void Transaction::set_reject_msg(const std::string& value) {
  reject_msg_ = value;
}
void Transaction::set_schedule_time(time_t value) { schedule_time_ = value; }

}  // namespace nunchuk