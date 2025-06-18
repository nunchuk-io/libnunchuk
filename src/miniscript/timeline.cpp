#include "miniscript/timeline.h"
#include "miniscript/compiler.h"
#include <algorithm>

namespace nunchuk {

MiniscriptTimeline::MiniscriptTimeline(const std::string& miniscript) {
  std::string keypath;
  node_ = Utils::GetScriptNode(miniscript, keypath);
  add_node(node_);
}

void MiniscriptTimeline::add_node(const ScriptNode& node) {
  if (node.get_type() == ScriptNode::Type::AFTER) {
    detect_timelock_mixing(node.get_k() >= LOCKTIME_THRESHOLD
                               ? Timelock::Based::TIME_LOCK
                               : Timelock::Based::HEIGHT_LOCK);
    absolute_locks_.push_back(node.get_k());
  } else if (node.get_type() == ScriptNode::Type::OLDER) {
    int64_t value;
    if (node.get_k() & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
      detect_timelock_mixing(Timelock::Based::TIME_LOCK);
      value = (int64_t)((node.get_k() & CTxIn::SEQUENCE_LOCKTIME_MASK)
                        << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY);
    } else {
      detect_timelock_mixing(Timelock::Based::HEIGHT_LOCK);
      value = (int)(node.get_k() & CTxIn::SEQUENCE_LOCKTIME_MASK);
    }
    relative_locks_.push_back(value);
  }

  for (int i = 0; i < node.get_subs().size(); i++) {
    add_node(node.get_subs()[i]);
  }
}

void MiniscriptTimeline::detect_timelock_mixing(Timelock::Based new_type) {
  if (lock_type_ == Timelock::Based::NONE) {
    lock_type_ = new_type;
  } else if (lock_type_ != new_type) {
    throw std::runtime_error("Timelock mixing");
  }
}

std::vector<int64_t> MiniscriptTimeline::get_locks(const UnspentOutput& utxo) {
  std::vector<int64_t> locks = absolute_locks_;
  for (auto&& lock : relative_locks_) {
    locks.push_back(lock_type_ == Timelock::Based::TIME_LOCK
                        ? utxo.get_blocktime() + lock
                        : utxo.get_height() + lock);
  }
  // sort and unique
  std::sort(locks.begin(), locks.end());
  locks.erase(std::unique(locks.begin(), locks.end()), locks.end());
  return locks;
}

}  // namespace nunchuk