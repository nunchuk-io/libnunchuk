// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nunchuk.h>
#include <vector>

namespace nunchuk {

SingleSigner::SingleSigner(const std::string& name, const std::string& xpub,
                           const std::string& public_key,
                           const std::string& derivation_path,
                           const std::string& master_fingerprint,
                           time_t last_health_check,
                           const std::string& master_signer_id, bool used)
    : name_(name),
      xpub_(xpub),
      public_key_(public_key),
      derivation_path_(derivation_path),
      master_fingerprint_(master_fingerprint),
      master_signer_id_(master_signer_id),
      last_health_check_(last_health_check),
      used_(used) {}

std::string SingleSigner::get_name() const { return name_; }
std::string SingleSigner::get_xpub() const { return xpub_; }
std::string SingleSigner::get_public_key() const { return public_key_; }
std::string SingleSigner::get_derivation_path() const {
  return derivation_path_;
}
std::string SingleSigner::get_master_fingerprint() const {
  return master_fingerprint_;
}
std::string SingleSigner::get_master_signer_id() const {
  return master_signer_id_;
}
SignerType SingleSigner::get_type() const { return type_; }
bool SingleSigner::is_used() const { return used_; }
bool SingleSigner::has_master_signer() const {
  return !master_signer_id_.empty();
}
time_t SingleSigner::get_last_health_check() const {
  return last_health_check_;
}
void SingleSigner::set_name(const std::string& value) { name_ = value; }
void SingleSigner::set_used(bool value) { used_ = value; }
void SingleSigner::set_type(SignerType value) { type_ = value; }

}  // namespace nunchuk