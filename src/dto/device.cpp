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

namespace nunchuk {

Device::Device() {}
Device::Device(const std::string &master_fingerprint)
    : master_fingerprint_(master_fingerprint), connected_(false) {}
Device::Device(const std::string &type, const std::string &model,
               const std::string &master_fingerprint)
    : type_(type),
      model_(model),
      master_fingerprint_(master_fingerprint),
      connected_(false) {}
Device::Device(const std::string &type, const std::string &path,
               const std::string &model, const std::string &master_fingerprint,
               bool needs_pass_phrase_sent, bool needs_pin_sent,
               bool initialized)
    : type_(type),
      path_(path),
      model_(model),
      master_fingerprint_(master_fingerprint),
      connected_(true),
      needs_pass_phrase_sent_(needs_pass_phrase_sent),
      needs_pin_sent_(needs_pin_sent),
      initialized_(initialized) {}

std::string Device::get_type() const { return type_; }
std::string Device::get_path() const { return path_; }
std::string Device::get_model() const { return model_; }
std::string Device::get_master_fingerprint() const {
  return master_fingerprint_;
}
bool Device::connected() const { return connected_; }
bool Device::needs_pass_phrase_sent() const { return needs_pass_phrase_sent_; }
bool Device::needs_pin_sent() const { return needs_pin_sent_; }
bool Device::initialized() const { return initialized_; }
void Device::set_needs_pass_phrase_sent(const bool value) {
  needs_pass_phrase_sent_ = value;
}

}  // namespace nunchuk