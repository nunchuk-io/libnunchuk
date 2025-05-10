#include "miniscript/timeline.h"
#include "miniscript/compiler.h"
#include <algorithm>

namespace nunchuk {

MiniscriptTimeline::MiniscriptTimeline(const std::string& miniscript) {
    add_node(ParseMiniscript(miniscript));
}

void MiniscriptTimeline::add_node(const miniscript::NodeRef<std::string>& node) {
    if (node->fragment == miniscript::Fragment::AFTER) {
        detect_timelock_mixing(node->k >= LOCKTIME_THRESHOLD
                                 ? Timelock::Based::TIME_LOCK
                                 : Timelock::Based::HEIGHT_LOCK);
        absolute_locks_.push_back(node->k);
    } else if (node->fragment == miniscript::Fragment::OLDER) {
        int64_t value;
        if (node->k & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            detect_timelock_mixing(Timelock::Based::TIME_LOCK);
            value = (int64_t)((node->k & CTxIn::SEQUENCE_LOCKTIME_MASK)
                          << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) -
                1;
        } else {
            detect_timelock_mixing(Timelock::Based::HEIGHT_LOCK);
            value = (int)(node->k & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1;
        }
        relative_locks_.push_back(value);
    }

    for (int i = 0; i < node->subs.size(); i++) {
        add_node(node->subs[i]);
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

} // namespace nunchuk 