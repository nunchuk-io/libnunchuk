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
#include <utils/txutils.hpp>

namespace nunchuk {

ScriptNode::ScriptNode() {}

ScriptNode::ScriptNode(Type nt, std::vector<ScriptNode>&& subs,
                       std::vector<std::string>&& key,
                       std::vector<unsigned char>&& dat, uint32_t kv)
    : node_type_(nt),
      sub_(std::move(subs)),
      keys_(std::move(key)),
      data_(std::move(dat)),
      k_(kv) {}

bool ScriptNode::operator()() const { return node_type_ != Type::NONE; }

void ScriptNode::set_id(ScriptNodeId&& id) {
  for (size_t i = 0; i < sub_.size(); i++) {
    auto sub_id = id;
    sub_id.push_back(i + 1);
    sub_[i].set_id(std::move(sub_id));
  }
  id_ = std::move(id);
}

ScriptNode::Type ScriptNode::get_type() const { return node_type_; }
const ScriptNodeId& ScriptNode::get_id() const { return id_; }
const std::vector<std::string>& ScriptNode::get_keys() const { return keys_; }
const std::vector<unsigned char>& ScriptNode::get_data() const { return data_; }
const std::vector<ScriptNode>& ScriptNode::get_subs() const { return sub_; }
uint32_t ScriptNode::get_k() const { return k_; }
bool ScriptNode::is_locked(const UnspentOutput& coin, int64_t chain_tip,
                           int64_t& max_lock) const {
  int64_t value = 0;
  int64_t current_value;
  if (node_type_ == ScriptNode::Type::AFTER) {
    Timelock timelock = Timelock::FromK(true, k_);
    value = timelock.value();
    if (timelock.based() == Timelock::Based::TIME_LOCK) {
      current_value = std::time(0);
    } else {
      current_value = chain_tip;
    }
  } else if (node_type_ == ScriptNode::Type::OLDER) {
    Timelock timelock = Timelock::FromK(false, k_);
    if (timelock.based() == Timelock::Based::TIME_LOCK) {
      value = coin.get_blocktime() + timelock.value();
      current_value = std::time(0);
    } else {
      value = coin.get_height() + timelock.value();
      current_value = chain_tip;
    }
  } else if (node_type_ == ScriptNode::Type::ANDOR) {
    return (sub_.at(0).is_locked(coin, chain_tip, max_lock) &&
            sub_.at(1).is_locked(coin, chain_tip, max_lock)) ||
           sub_.at(2).is_locked(coin, chain_tip, max_lock);
  } else if (node_type_ == ScriptNode::Type::OR ||
             node_type_ == ScriptNode::Type::OR_TAPROOT) {
    return sub_.at(0).is_locked(coin, chain_tip, max_lock) ||
           sub_.at(1).is_locked(coin, chain_tip, max_lock);
  } else if (node_type_ == ScriptNode::Type::AND) {
    return sub_.at(0).is_locked(coin, chain_tip, max_lock) &&
           sub_.at(1).is_locked(coin, chain_tip, max_lock);
  } else if (node_type_ == ScriptNode::Type::THRESH) {
    int count = 0;
    for (int j = 0; j < sub_.size(); j++) {
      if (sub_.at(j).is_locked(coin, chain_tip, max_lock)) count++;
    }
    return count >= k_;
  } else {
    return true;
  }

  if (value > current_value && value > max_lock) {
    max_lock = value;
  }
  return value <= current_value;
}

bool ScriptNode::is_satisfiable(const Transaction& tx) const {
  if (node_type_ == ScriptNode::Type::AFTER) {
    return k_ <= tx.get_lock_time();
  } else if (node_type_ == ScriptNode::Type::OLDER) {
    for (int i = 0; i < tx.get_inputs().size(); i++) {
      auto sequence = tx.get_inputs()[i].nSequence;
      if (sequence != Timelock::FromK(false, sequence).k()) return false;
      if (k_ > sequence) return false;
    }
    return true;
  } else if (node_type_ == ScriptNode::Type::ANDOR) {
    return (sub_.at(0).is_satisfiable(tx) && sub_.at(1).is_satisfiable(tx)) ||
           sub_.at(2).is_satisfiable(tx);
  } else if (node_type_ == ScriptNode::Type::OR ||
             node_type_ == ScriptNode::Type::OR_TAPROOT) {
    return sub_.at(0).is_satisfiable(tx) || sub_.at(1).is_satisfiable(tx);
  } else if (node_type_ == ScriptNode::Type::AND) {
    return sub_.at(0).is_satisfiable(tx) && sub_.at(1).is_satisfiable(tx);
  } else if (node_type_ == ScriptNode::Type::THRESH) {
    int count = 0;
    for (int j = 0; j < sub_.size(); j++) {
      if (sub_.at(j).is_satisfiable(tx)) count++;
    }
    return count >= k_;
  } else {
    return true;
  }
}

bool ScriptNode::is_satisfiable(const std::string& psbt) const {
  auto psbtx = DecodePsbt(psbt);
  auto tx = GetTransactionFromCMutableTransaction(psbtx.tx.value(), -1);
  return is_satisfiable(tx);
}

KeysetStatus ScriptNode::get_keyset_status(const Transaction& tx) const {
  if (node_type_ != ScriptNode::Type::MUSIG)
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid node type");
  std::set<std::string> xfps;
  for (auto& key : keys_) {
    std::string xfp = Utils::ParseSignerString(key).get_master_fingerprint();
    xfps.insert(xfp);
  }
  auto keysets = tx.get_keyset_status();
  for (auto& keyset : keysets) {
    if (keyset.second.size() != xfps.size()) continue;
    bool found = true;
    for (auto& xfp : xfps) {
      if (keyset.second.find(xfp) == keyset.second.end()) {
        found = false;
        break;
      }
    }
    if (found) return keyset;
  }
  throw NunchukException(NunchukException::NOT_FOUND, "Keyset not found");
}

std::string ScriptNode::type_to_string(ScriptNode::Type type) {
  switch (type) {
    case ScriptNode::Type::NONE:
      return "NONE";
    case ScriptNode::Type::PK:
      return "PK";
    case ScriptNode::Type::OLDER:
      return "OLDER";
    case ScriptNode::Type::AFTER:
      return "AFTER";
    case ScriptNode::Type::HASH160:
      return "HASH160";
    case ScriptNode::Type::HASH256:
      return "HASH256";
    case ScriptNode::Type::RIPEMD160:
      return "RIPEMD160";
    case ScriptNode::Type::SHA256:
      return "SHA256";
    case ScriptNode::Type::AND:
      return "AND";
    case ScriptNode::Type::OR:
      return "OR";
    case ScriptNode::Type::ANDOR:
      return "ANDOR";
    case ScriptNode::Type::THRESH:
      return "THRESH";
    case ScriptNode::Type::MULTI:
      return "MULTI";
    case ScriptNode::Type::OR_TAPROOT:
      return "OR_TAPROOT";
    case ScriptNode::Type::MUSIG:
      return "MUSIG";
    default:
      return "UNKNOWN";
  }
}

}  // namespace nunchuk