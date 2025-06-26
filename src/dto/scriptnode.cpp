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
bool ScriptNode::is_satisfiable(const UnspentOutput& coin,
                                int64_t current_value,
                                int64_t& max_value) const {
  int64_t value = 0;
  if (node_type_ == ScriptNode::Type::AFTER) {
    value = k_;
  } else if (node_type_ == ScriptNode::Type::OLDER) {
    Timelock timelock = Timelock::FromK(false, k_);
    value = timelock.based() == Timelock::Based::TIME_LOCK
                ? coin.get_blocktime() + timelock.value()
                : coin.get_height() + timelock.value();
  } else if (node_type_ == ScriptNode::Type::ANDOR) {
    return (sub_.at(0).is_satisfiable(coin, current_value, max_value) &&
            sub_.at(1).is_satisfiable(coin, current_value, max_value)) ||
           sub_.at(2).is_satisfiable(coin, current_value, max_value);
  } else if (node_type_ == ScriptNode::Type::OR ||
             node_type_ == ScriptNode::Type::OR_TAPROOT) {
    return sub_.at(0).is_satisfiable(coin, current_value, max_value) ||
           sub_.at(1).is_satisfiable(coin, current_value, max_value);
  } else if (node_type_ == ScriptNode::Type::AND) {
    return sub_.at(0).is_satisfiable(coin, current_value, max_value) &&
           sub_.at(1).is_satisfiable(coin, current_value, max_value);
  } else if (node_type_ == ScriptNode::Type::THRESH) {
    int count = 0;
    for (int j = 0; j < sub_.size(); j++) {
      if (sub_.at(j).is_satisfiable(coin, current_value, max_value)) count++;
    }
    return count >= k_;
  } else {
    return true;
  }

  if (value > current_value && value > max_value) max_value = value;
  return value <= current_value;
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
    default:
      return "UNKNOWN";
  }
}

}  // namespace nunchuk