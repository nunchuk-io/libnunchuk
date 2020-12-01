// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nunchuk.h>
#include <vector>

namespace nunchuk {

UnspentOutput::UnspentOutput() {}

std::string UnspentOutput::get_txid() const { return txid_; }
int UnspentOutput::get_vout() const { return vout_; }
std::string UnspentOutput::get_address() const { return address_; }
Amount UnspentOutput::get_amount() const { return amount_; }
int UnspentOutput::get_height() const { return height_; }
std::string UnspentOutput::get_memo() const { return memo_; }

void UnspentOutput::set_txid(const std::string& value) { txid_ = value; }
void UnspentOutput::set_vout(int value) { vout_ = value; }
void UnspentOutput::set_address(const std::string& value) { address_ = value; }
void UnspentOutput::set_amount(const Amount& value) { amount_ = value; }
void UnspentOutput::set_height(int value) { height_ = value; }
void UnspentOutput::set_memo(const std::string& value) { memo_ = value; }

}  // namespace nunchuk