#include "miniscript/timeline.h"
#include "miniscript/compiler.h"
#include <algorithm>

namespace nunchuk {

MiniscriptTimeline::MiniscriptTimeline(const std::string& miniscript) {
  std::vector<std::string> keypath;
  node_ = Utils::GetScriptNode(miniscript, keypath);
  add_node(node_);
}

void MiniscriptTimeline::add_node(const ScriptNode& node) {
  if (node.get_type() == ScriptNode::Type::AFTER) {
    Timelock timelock = Timelock::FromK(true, node.get_k());
    detect_invalid_value(timelock, node.get_k());
    detect_timelock_mixing(timelock.based());
    absolute_locks_.push_back(timelock.value());
  } else if (node.get_type() == ScriptNode::Type::OLDER) {
    Timelock timelock = Timelock::FromK(false, node.get_k());
    detect_invalid_value(timelock, node.get_k());
    detect_timelock_mixing(timelock.based());
    relative_locks_.push_back(timelock.value());
  }

  for (int i = 0; i < node.get_subs().size(); i++) {
    add_node(node.get_subs()[i]);
  }
}

void MiniscriptTimeline::detect_timelock_mixing(Timelock::Based new_type) {
  if (lock_type_ == Timelock::Based::NONE) {
    lock_type_ = new_type;
  } else if (lock_type_ != new_type) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Timelock mixing");
  }
}

void MiniscriptTimeline::detect_invalid_value(const Timelock& timelock,
                                              uint32_t k) {
  if (timelock.k() == k) return;
  if (timelock.based() == Timelock::Based::TIME_LOCK) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid time value");
  } else {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid height value");
  }
}

std::vector<int64_t> MiniscriptTimeline::get_locks(const UnspentOutput& utxo) {
  std::vector<int64_t> locks = absolute_locks_;
  // Can not calculate relative lock for unconfirmed utxo
  if (utxo.get_height() > 0) {
    for (auto&& lock : relative_locks_) {
      locks.push_back(lock_type_ == Timelock::Based::TIME_LOCK
                          ? utxo.get_blocktime() + lock
                          : utxo.get_height() + lock);
    }
  }
  // sort and unique
  std::sort(locks.begin(), locks.end());
  locks.erase(std::unique(locks.begin(), locks.end()), locks.end());
  return locks;
}

}  // namespace nunchuk