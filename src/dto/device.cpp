// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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