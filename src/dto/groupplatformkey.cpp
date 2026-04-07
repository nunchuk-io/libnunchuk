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

GroupSpendingLimit::GroupSpendingLimit() {}

GroupSpendingLimitInterval GroupSpendingLimit::get_interval() const {
  return interval_;
}

const std::string& GroupSpendingLimit::get_amount() const { return amount_; }

const std::string& GroupSpendingLimit::get_currency() const {
  return currency_;
}

void GroupSpendingLimit::set_interval(GroupSpendingLimitInterval value) {
  interval_ = value;
}

void GroupSpendingLimit::set_amount(const std::string& value) {
  amount_ = value;
}

void GroupSpendingLimit::set_currency(const std::string& value) {
  currency_ = value;
}

GroupPlatformKeyPolicy::GroupPlatformKeyPolicy() {}

bool GroupPlatformKeyPolicy::get_auto_broadcast_transaction() const {
  return auto_broadcast_transaction_;
}

int GroupPlatformKeyPolicy::get_signing_delay_seconds() const {
  return signing_delay_seconds_;
}

const std::optional<GroupSpendingLimit>&
GroupPlatformKeyPolicy::get_spending_limit() const {
  return spending_limit_;
}

void GroupPlatformKeyPolicy::set_auto_broadcast_transaction(bool value) {
  auto_broadcast_transaction_ = value;
}

void GroupPlatformKeyPolicy::set_signing_delay_seconds(int value) {
  signing_delay_seconds_ = value;
}

void GroupPlatformKeyPolicy::set_spending_limit(
    std::optional<GroupSpendingLimit> value) {
  spending_limit_ = std::move(value);
}

GroupPlatformKeySignerPolicy::GroupPlatformKeySignerPolicy() {}

const std::string& GroupPlatformKeySignerPolicy::get_master_fingerprint() const {
  return master_fingerprint_;
}

const GroupPlatformKeyPolicy& GroupPlatformKeySignerPolicy::get_policy() const {
  return policy_;
}

void GroupPlatformKeySignerPolicy::set_master_fingerprint(
    const std::string& value) {
  master_fingerprint_ = value;
}

void GroupPlatformKeySignerPolicy::set_policy(GroupPlatformKeyPolicy value) {
  policy_ = std::move(value);
}

GroupPlatformKeyPolicies::GroupPlatformKeyPolicies() {}

const std::optional<GroupPlatformKeyPolicy>&
GroupPlatformKeyPolicies::get_global() const {
  return global_;
}

const std::vector<GroupPlatformKeySignerPolicy>&
GroupPlatformKeyPolicies::get_signers() const {
  return signers_;
}

void GroupPlatformKeyPolicies::set_global(
    std::optional<GroupPlatformKeyPolicy> value) {
  global_ = std::move(value);
}

void GroupPlatformKeyPolicies::set_signers(
    std::vector<GroupPlatformKeySignerPolicy> value) {
  signers_ = std::move(value);
}

GroupPlatformKey::GroupPlatformKey() {}

GroupPlatformKey::GroupPlatformKey(GroupPlatformKeyPolicies policies)
    : policies_(std::move(policies)) {}

const GroupPlatformKeyPolicies& GroupPlatformKey::get_policies() const {
  return policies_;
}

void GroupPlatformKey::set_policies(GroupPlatformKeyPolicies value) {
  policies_ = std::move(value);
}

}  // namespace nunchuk
