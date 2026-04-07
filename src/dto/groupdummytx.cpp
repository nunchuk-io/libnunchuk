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

GroupDummyTransactionSignature::GroupDummyTransactionSignature() {}

const std::string& GroupDummyTransactionSignature::get_master_fingerprint()
    const {
  return master_fingerprint_;
}

const std::string& GroupDummyTransactionSignature::get_signature() const {
  return signature_;
}

void GroupDummyTransactionSignature::set_master_fingerprint(
    const std::string& value) {
  master_fingerprint_ = value;
}

void GroupDummyTransactionSignature::set_signature(const std::string& value) {
  signature_ = value;
}

GroupDummyTransactionPayload::GroupDummyTransactionPayload() {}

const GroupPlatformKeyPolicies&
GroupDummyTransactionPayload::get_old_policies() const {
  return old_policies_;
}

const GroupPlatformKeyPolicies&
GroupDummyTransactionPayload::get_new_policies() const {
  return new_policies_;
}

void GroupDummyTransactionPayload::set_old_policies(
    GroupPlatformKeyPolicies value) {
  old_policies_ = std::move(value);
}

void GroupDummyTransactionPayload::set_new_policies(
    GroupPlatformKeyPolicies value) {
  new_policies_ = std::move(value);
}

GroupDummyTransaction::GroupDummyTransaction() {}

const std::string& GroupDummyTransaction::get_id() const { return id_; }

const std::string& GroupDummyTransaction::get_wallet_id() const {
  return wallet_id_;
}

GroupDummyTransactionType GroupDummyTransaction::get_type() const {
  return type_;
}

GroupDummyTransactionStatus GroupDummyTransaction::get_status() const {
  return status_;
}

const std::optional<GroupDummyTransactionPayload>& GroupDummyTransaction::get_payload()
    const {
  return payload_;
}

int GroupDummyTransaction::get_required_signatures() const {
  return required_signatures_;
}

int GroupDummyTransaction::get_pending_signatures() const {
  return pending_signatures_;
}

const std::string& GroupDummyTransaction::get_request_body() const {
  return request_body_;
}

const std::vector<GroupDummyTransactionSignature>&
GroupDummyTransaction::get_signatures() const {
  return signatures_;
}

time_t GroupDummyTransaction::get_created_at() const { return created_at_; }

void GroupDummyTransaction::set_id(const std::string& value) { id_ = value; }

void GroupDummyTransaction::set_wallet_id(const std::string& value) {
  wallet_id_ = value;
}

void GroupDummyTransaction::set_type(GroupDummyTransactionType value) {
  type_ = value;
}

void GroupDummyTransaction::set_status(GroupDummyTransactionStatus value) {
  status_ = value;
}

void GroupDummyTransaction::set_payload(
    std::optional<GroupDummyTransactionPayload> value) {
  payload_ = std::move(value);
}

void GroupDummyTransaction::set_required_signatures(int value) {
  required_signatures_ = value;
}

void GroupDummyTransaction::set_pending_signatures(int value) {
  pending_signatures_ = value;
}

void GroupDummyTransaction::set_request_body(const std::string& value) {
  request_body_ = value;
}

void GroupDummyTransaction::set_signatures(
    std::vector<GroupDummyTransactionSignature> value) {
  signatures_ = std::move(value);
}

void GroupDummyTransaction::set_created_at(time_t value) {
  created_at_ = value;
}

GroupPlatformKeyPolicyUpdateRequirement::
    GroupPlatformKeyPolicyUpdateRequirement() {}

bool GroupPlatformKeyPolicyUpdateRequirement::get_success() const {
  return success_;
}

int GroupPlatformKeyPolicyUpdateRequirement::get_delay_apply_in_seconds() const {
  return delay_apply_in_seconds_;
}

bool GroupPlatformKeyPolicyUpdateRequirement::requires_dummy_transaction()
    const {
  return requires_dummy_transaction_;
}

const std::optional<GroupDummyTransaction>&
GroupPlatformKeyPolicyUpdateRequirement::get_dummy_transaction() const {
  return dummy_transaction_;
}

void GroupPlatformKeyPolicyUpdateRequirement::set_success(bool value) {
  success_ = value;
}

void GroupPlatformKeyPolicyUpdateRequirement::set_delay_apply_in_seconds(
    int value) {
  delay_apply_in_seconds_ = value;
}

void GroupPlatformKeyPolicyUpdateRequirement::set_requires_dummy_transaction(
    bool value) {
  requires_dummy_transaction_ = value;
}

void GroupPlatformKeyPolicyUpdateRequirement::set_dummy_transaction(
    std::optional<GroupDummyTransaction> value) {
  dummy_transaction_ = std::move(value);
}

GroupTransactionState::GroupTransactionState() {}

GroupTransactionStatus GroupTransactionState::get_status() const {
  return status_;
}

const std::string& GroupTransactionState::get_message() const {
  return message_;
}

time_t GroupTransactionState::get_cosign_at() const {
  return cosign_at_;
}

void GroupTransactionState::set_status(GroupTransactionStatus value) {
  status_ = value;
}

void GroupTransactionState::set_message(const std::string& value) {
  message_ = value;
}

void GroupTransactionState::set_cosign_at(time_t value) {
  cosign_at_ = value;
}

GroupWalletAlertPayload::GroupWalletAlertPayload() {}

const std::string& GroupWalletAlertPayload::get_dummy_transaction_id() const {
  return dummy_transaction_id_;
}

const std::string& GroupWalletAlertPayload::get_replacement_group_id() const {
  return replacement_group_id_;
}

void GroupWalletAlertPayload::set_dummy_transaction_id(
    const std::string& value) {
  dummy_transaction_id_ = value;
}

void GroupWalletAlertPayload::set_replacement_group_id(
    const std::string& value) {
  replacement_group_id_ = value;
}

GroupWalletAlert::GroupWalletAlert() {}

const std::string& GroupWalletAlert::get_id() const { return id_; }

GroupWalletAlertType GroupWalletAlert::get_type() const { return type_; }

bool GroupWalletAlert::get_viewable() const { return viewable_; }

const std::string& GroupWalletAlert::get_title() const { return title_; }

const std::string& GroupWalletAlert::get_body() const { return body_; }

const std::optional<GroupWalletAlertPayload>& GroupWalletAlert::get_payload()
    const {
  return payload_;
}

time_t GroupWalletAlert::get_created_at() const { return created_at_; }

void GroupWalletAlert::set_id(const std::string& value) { id_ = value; }

void GroupWalletAlert::set_type(GroupWalletAlertType value) { type_ = value; }

void GroupWalletAlert::set_viewable(bool value) { viewable_ = value; }

void GroupWalletAlert::set_title(const std::string& value) { title_ = value; }

void GroupWalletAlert::set_body(const std::string& value) { body_ = value; }

void GroupWalletAlert::set_payload(std::optional<GroupWalletAlertPayload> value) {
  payload_ = std::move(value);
}

void GroupWalletAlert::set_created_at(time_t value) { created_at_ = value; }

}  // namespace nunchuk
