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

Wallet::Wallet() {}
Wallet::Wallet(const std::string& id, int m, int n,
               const std::vector<SingleSigner>& signers,
               AddressType address_type, bool is_escrow, time_t create_date)
    : id_(id),
      m_(m),
      n_(n),
      signers_(signers),
      address_type_(address_type),
      escrow_(is_escrow),
      create_date_(create_date) {}
std::string Wallet::get_id() const { return id_; }
std::string Wallet::get_name() const { return name_; }
int Wallet::get_m() const { return m_; }
int Wallet::get_n() const { return n_; }
std::vector<SingleSigner> Wallet::get_signers() const { return signers_; }
AddressType Wallet::get_address_type() const { return address_type_; }
bool Wallet::is_escrow() const { return escrow_; }
Amount Wallet::get_balance() const { return balance_; }
time_t Wallet::get_create_date() const { return create_date_; }
std::string Wallet::get_description() const { return description_; }
void Wallet::set_name(const std::string& value) { name_ = value; }
void Wallet::set_balance(const Amount& value) { balance_ = value; }
void Wallet::set_description(const std::string& value) { description_ = value; }

std::string Wallet::get_descriptor(DescriptorPath key_path, int index,
                                   bool sorted) const {
  return GetDescriptorForSigners(
      get_signers(), get_m(), key_path, get_address_type(),
      get_n() == 1 ? WalletType::SINGLE_SIG
                   : (is_escrow() ? WalletType::ESCROW : WalletType::MULTI_SIG),
      is_escrow() ? -1 : index, sorted);
}

}  // namespace nunchuk