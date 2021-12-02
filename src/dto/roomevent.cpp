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

NunchukMatrixEvent::NunchukMatrixEvent() {}

std::string NunchukMatrixEvent::get_type() const { return type_; }
std::string NunchukMatrixEvent::get_content() const { return content_; }
std::string NunchukMatrixEvent::get_event_id() const { return event_id_; }
std::string NunchukMatrixEvent::get_room_id() const { return room_id_; }
std::string NunchukMatrixEvent::get_sender() const { return sender_; }
time_t NunchukMatrixEvent::get_ts() const { return ts_; }

void NunchukMatrixEvent::set_type(const std::string& value) { type_ = value; }
void NunchukMatrixEvent::set_content(const std::string& value) {
  content_ = value;
}
void NunchukMatrixEvent::set_event_id(const std::string& value) {
  event_id_ = value;
}
void NunchukMatrixEvent::set_room_id(const std::string& value) {
  room_id_ = value;
}
void NunchukMatrixEvent::set_sender(const std::string& value) {
  sender_ = value;
}
void NunchukMatrixEvent::set_ts(time_t value) { ts_ = value; }

}  // namespace nunchuk