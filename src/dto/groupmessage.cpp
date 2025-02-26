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

GroupMessage::GroupMessage(const std::string& id, const std::string& wallet_id)
 : id_(id), wallet_id_(wallet_id) {}

std::string GroupMessage::get_id() const { return id_; }
std::string GroupMessage::get_wallet_id() const { return wallet_id_; }
std::string GroupMessage::get_sender() const { return sender_; }
std::string GroupMessage::get_content() const { return content_; }
std::string GroupMessage::get_signer() const { return signer_; }
time_t GroupMessage::get_ts() const { return ts_; }

void GroupMessage::set_wallet_id(const std::string& value) { wallet_id_ = value; }
void GroupMessage::set_sender(const std::string& value) { sender_ = value; }
void GroupMessage::set_content(const std::string& value) { content_ = value; }
void GroupMessage::set_signer(const std::string& value) { signer_ = value; }
void GroupMessage::set_ts(time_t value) { ts_ = value; }

}  // namespace nunchuk
