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
#include <utils/stringutils.hpp>

namespace nunchuk {

static WalletType get_default_wallet_type(bool is_escrow, int n) {
  return is_escrow ? WalletType::ESCROW
         : n == 1  ? WalletType::SINGLE_SIG
                   : WalletType::MULTI_SIG;
}

Wallet::Wallet(bool strict) noexcept : strict_(strict) {}

Wallet::Wallet(const std::string& id, int m, int n,
               const std::vector<SingleSigner>& signers,
               AddressType address_type, bool is_escrow, time_t create_date,
               bool strict)
    : Wallet(id, {}, m, n, signers, address_type,
             get_default_wallet_type(is_escrow, n), create_date, strict) {}

Wallet::Wallet(const std::string& id, const std::string& name, int m, int n,
               const std::vector<SingleSigner>& signers,
               AddressType address_type, bool is_escrow, time_t create_date,
               bool strict)
    : Wallet(id, name, m, n, signers, address_type,
             get_default_wallet_type(is_escrow, n), create_date, strict) {}

Wallet::Wallet(const std::string& id, const std::string& name, int m, int n,
               const std::vector<SingleSigner>& signers,
               AddressType address_type, WalletType wallet_type,
               time_t create_date, bool strict)
    : id_(id),
      m_(m),
      n_(n),
      signers_(signers),
      address_type_(address_type),
      wallet_type_(wallet_type),
      create_date_(create_date),
      strict_(strict) {
  if (strict_) check_valid();
  if (id_.empty())
    id_ = GetWalletId(signers_, m_, address_type_, wallet_type_,
                      wallet_template_);
  name_ = name;
};

Wallet::Wallet(const std::string& miniscript,
               const std::vector<SingleSigner>& signers,
               AddressType address_type, int keypath_m)
    : m_(keypath_m),
      n_(signers.size()),
      signers_(signers),
      address_type_(address_type),
      wallet_type_(WalletType::MINISCRIPT),
      wallet_template_(WalletTemplate::DEFAULT),
      miniscript_(miniscript) {
  if (address_type_ == AddressType::TAPROOT && keypath_m == 0) {
    wallet_template_ = WalletTemplate::DISABLE_KEY_PATH;
  }
  check_valid();
  id_ = GetDescriptorChecksum(get_descriptor(DescriptorPath::EXTERNAL_ALL));
}

std::string Wallet::get_id() const { return id_; }
std::string Wallet::get_name() const { return name_; }
int Wallet::get_m() const { return m_; }
int Wallet::get_n() const { return n_; }
const std::vector<SingleSigner>& Wallet::get_signers() const {
  return signers_;
}
AddressType Wallet::get_address_type() const { return address_type_; }
WalletType Wallet::get_wallet_type() const { return wallet_type_; }
WalletTemplate Wallet::get_wallet_template() const { return wallet_template_; }
bool Wallet::is_escrow() const { return wallet_type_ == WalletType::ESCROW; }
Amount Wallet::get_balance() const { return balance_; }
Amount Wallet::get_unconfirmed_balance() const { return unconfirmed_balance_; }
time_t Wallet::get_create_date() const { return create_date_; }
std::string Wallet::get_description() const { return description_; }
time_t Wallet::get_last_used() const { return last_used_; }
int Wallet::get_gap_limit() const { return gap_limit_; }
bool Wallet::need_backup() const { return need_backup_; }
bool Wallet::is_archived() const { return archived_; }
std::string Wallet::get_miniscript(DescriptorPath path, int index) const {
  if (path == DescriptorPath::ANY) {
    return miniscript_;
  }
  std::string rs = miniscript_;
  for (auto&& signer : signers_) {
    rs = replaceAll(rs, GetDescriptorForSigner(signer, DescriptorPath::ANY),
                    GetDescriptorForSigner(signer, path, index));
  }
  return rs;
}
void Wallet::check_valid() const {
  if (n_ <= 0)
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid parameter: n <= 0");
  if (m_ <= 0 && wallet_type_ != WalletType::MINISCRIPT)
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid parameter: m <= 0");
  if (m_ > n_)
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid parameter: m > n");
  if (n_ != signers_.size())
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid parameter: n and signers are not match");
  if (n_ == 1 && is_escrow())
    throw NunchukException(
        NunchukException::INVALID_PARAMETER,
        "Invalid parameter: can not create single sig escrow wallet");
  if (address_type_ != AddressType::TAPROOT &&
      wallet_template_ == WalletTemplate::DISABLE_KEY_PATH)
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid parameter: template is not supported");
  if (wallet_type_ == WalletType::MINISCRIPT && miniscript_.empty())
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid parameter: miniscript is empty");
  // TODO: need to call get_descriptor() for bitcoin core validation?
}
void Wallet::set_name(const std::string& value) { name_ = value; }
void Wallet::set_n(int n) {
  n_ = n;
  post_update();
}
void Wallet::set_m(int m) {
  m_ = m;
  post_update();
}
void Wallet::set_signers(std::vector<SingleSigner> signers) {
  signers_ = std::move(signers);
  post_update();
}
void Wallet::set_address_type(AddressType value) {
  address_type_ = value;
  post_update();
}
void Wallet::set_wallet_type(WalletType value) {
  wallet_type_ = value;
  post_update();
}
void Wallet::set_wallet_template(WalletTemplate value) {
  wallet_template_ = value;
  post_update();
}
void Wallet::set_balance(const Amount& value) { balance_ = value; }
void Wallet::set_unconfirmed_balance(const Amount& value) {
  unconfirmed_balance_ = value;
}
void Wallet::set_description(const std::string& value) { description_ = value; }
void Wallet::set_create_date(const time_t value) { create_date_ = value; }
void Wallet::set_last_used(const time_t value) { last_used_ = value; }
void Wallet::set_gap_limit(int value) { gap_limit_ = value; }
void Wallet::set_need_backup(bool value) { need_backup_ = value; }
void Wallet::set_archived(bool value) { archived_ = value; }
void Wallet::set_miniscript(const std::string& value) { miniscript_ = value; }
std::string Wallet::get_descriptor(DescriptorPath path, int index,
                                   bool sorted) const {
  if (get_wallet_type() == WalletType::MINISCRIPT) {
    std::string keypath{};
    if (wallet_template_ == WalletTemplate::DEFAULT) {
      if (m_ == 1) {
        keypath = GetDescriptorForSigner(signers_[0], path, index);
      } else {
        std::stringstream ss;
        ss << "musig(";
        for (int i = 0; i < m_; i++) {
          if (i > 0) ss << ",";
          ss << GetDescriptorForSigner(signers_[i], path, index);
        }
        ss << ")";
        keypath = ss.str();
      }
    }
    auto desc = GetDescriptorForMiniscript(get_miniscript(path, index), keypath,
                                           get_address_type());
    if (path == DescriptorPath::TEMPLATE) {
      return split(desc, '#')[0];
    }
    return desc;
  }
  return GetDescriptorForSigners(
      get_signers(), get_m(), path, get_address_type(), get_wallet_type(),
      get_wallet_template(), is_escrow() ? -1 : index, sorted);
}

void Wallet::post_update() {
  if (signers_.size() == n_ && get_wallet_type() == WalletType::MINISCRIPT) {
    id_ = GetDescriptorChecksum(get_descriptor(DescriptorPath::EXTERNAL_ALL));
  } else if (signers_.size() > 0) {
    if (wallet_template_ == WalletTemplate::DISABLE_KEY_PATH) {
      std::sort(signers_.begin(), signers_.end(),
                [](const SingleSigner& a, const SingleSigner& b) {
                  return a.get_master_fingerprint() <
                         b.get_master_fingerprint();
                });
    }
    id_ = GetWalletId(signers_, m_, address_type_, get_wallet_type(),
                      get_wallet_template());
  }
  if (strict_) {
    check_valid();
  }
}

}  // namespace nunchuk
