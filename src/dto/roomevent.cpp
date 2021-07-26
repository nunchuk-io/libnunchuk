// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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