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
#include <utils/loguru.hpp>
#include <utils/bsms.hpp>

#include <vector>
#include <iostream>
#include <iomanip>
#include <regex>
#include <thread>
#include <chrono>

using namespace nunchuk;

std::unique_ptr<Nunchuk> nu;

inline std::string input_string(const std::string& message) {
  std::cout << "... " << message << ": ";
  std::string input;
  std::cin >> input;
  return input;
}

inline int input_int(const std::string& message) {
  std::cout << "... " << message << ": ";
  int input;
  std::cin >> input;
  return input;
}

inline bool input_bool(const std::string& message) {
  std::cout << message << " (Y/n)? ";
  std::string yn;
  std::cin >> yn;
  return (yn != "n" && yn != "N");
}

inline std::string input_multiline_string(const std::string& message,
                                          const std::string& terminator =
                                              "END") {
  std::cout << "... " << message << std::endl;
  std::cout << "... Finish input with a line containing only " << terminator
            << std::endl;
  std::string line;
  std::string result;
  std::getline(std::cin >> std::ws, line);
  while (line != terminator) {
    if (!result.empty()) result += "\n";
    result += line;
    std::getline(std::cin, line);
  }
  return result;
}

inline AddressType input_address_type(const WalletType& wallet_type) {
  std::cout << "... Choose address type: " << std::endl;
  std::cout << "1: Native Segwit" << std::endl;
  std::cout << "2: Nested Segwit" << std::endl;
  std::cout << "3: Legacy" << std::endl;
  std::cout << "4: Taproot (singlesig only)" << std::endl;
  int input;
  std::cin >> input;
  switch (input) {
    case 1:
      return AddressType::NATIVE_SEGWIT;
    case 2:
      return AddressType::NESTED_SEGWIT;
    case 3:
      return AddressType::LEGACY;
    case 4:
      if (wallet_type != WalletType::SINGLE_SIG)
        throw std::runtime_error("Only SingleSig wallet support Taproot");
      return AddressType::TAPROOT;
  }
  throw std::runtime_error("Invalid address type");
}

inline void print_list_devices(const std::vector<Device>& devices) {
  int i = 0;
  std::cout << std::endl;
  for (auto&& device : devices) {
    std::cout << i++ << ": [" << device.get_master_fingerprint() << "] "
              << device.get_model() << " (" << device.get_path() << ")"
              << std::endl;
  }
}

inline void print_list_signers(const std::vector<MasterSigner>& master,
                               const std::vector<SingleSigner>& remote) {
  int i = 0;
  std::cout << std::endl;
  for (auto&& signer : master) {
    std::cout << i++ << ": [" << signer.get_id() << "] " << signer.get_name()
              << std::endl;
  }
  for (auto&& signer : remote) {
    std::cout << i++ << ": [" << signer.get_master_fingerprint() << "] "
              << signer.get_name() << " (remote)" << std::endl;
  }
}

inline void print_list_wallets(const std::vector<Wallet>& wallets) {
  int i = 0;
  std::cout << std::endl;
  for (auto&& wallet : wallets) {
    std::cout << i++ << ": [" << wallet.get_id() << "] " << wallet.get_name()
              << " (" << wallet.get_m() << "/" << wallet.get_n()
              << "). Balance: " << wallet.get_balance() << " sat" << std::endl;
  }
}

void listdevices() { print_list_devices(nu.get()->GetDevices()); }

void listsigners() {
  print_list_signers(nu.get()->GetMasterSigners(),
                     nu.get()->GetRemoteSigners());
}

void listwallets() { print_list_wallets(nu.get()->GetWallets()); }

void newremotesigner() {
  auto name = input_string("Enter signer name");
  auto xpub = input_string("Enter xpub");
  auto path = input_string("Enter derivation path");
  auto xfp = input_string("Enter master fingerprint");
  auto remote_signer = nu.get()->CreateSigner(name, xpub, {}, path, xfp);
  std::cout << "\nRemote signer create success." << std::endl;
}

void newmastersigner() {
  auto devices = nu.get()->GetDevices();
  if (devices.empty()) {
    throw std::runtime_error("Please plug-in your device and retry");
  }

  auto name = input_string("Enter signer name");
  print_list_devices(devices);
  int device_idx = input_int("Choose device to create signer");
  if (device_idx < 0 || device_idx > devices.size()) {
    throw std::runtime_error("Invalid device");
  }
  auto device_xfp = devices[device_idx].get_master_fingerprint();
  auto master_signer = nu.get()->CreateMasterSigner(
      name, {device_xfp}, [](int percent) { return true; });
  nu.get()->CacheMasterSignerXPub(master_signer.get_id(), [](int percent) {
    std::cout << "Caching xpub... " << percent << "%" << std::endl;
    return true;
  });
  std::cout << "\nMaster signer create success." << std::endl;
}

void newsoftwaresigner() {
  auto name = input_string("Enter signer name");
  auto mnemonic = Utils::GenerateMnemonic();
  std::cout << "Mnemonic: " << mnemonic << std::endl;
  auto master_signer = nu.get()->CreateSoftwareSigner(
      name, mnemonic, "", [](int percent) { return true; });
  nu.get()->CacheMasterSignerXPub(master_signer.get_id(),
                                  [](int percent) { return true; });
  std::cout << "\nMaster signer create success. Please back up your mnemonic."
            << std::endl;
}

void newsigner() {
  if (input_bool("Is it software signer")) {
    newsoftwaresigner();
  } else if (input_bool("Is it remote signer")) {
    newremotesigner();
  } else {
    newmastersigner();
  }
}

void newwallet() {
  auto master_signers = nu.get()->GetMasterSigners();
  auto remote_signers = nu.get()->GetRemoteSigners();
  if (master_signers.empty() && remote_signers.empty()) {
    throw std::runtime_error("Please create signer first");
  }

  auto name = input_string("Enter wallet name");
  auto n = input_int("Total signers");
  auto m = input_int("Required signatures");
  if (m > n) {
    throw std::runtime_error(
        "Required signatures must less or equal total signers");
  }
  WalletType wallet_type =
      n == 1 ? WalletType::SINGLE_SIG : WalletType::MULTI_SIG;
  AddressType address_type = input_address_type(wallet_type);

  std::vector<SingleSigner> signers;
  for (int i = 0; i < n; i++) {
    print_list_signers(master_signers, remote_signers);
    int signer_idx = input_int("Choose a singer to add");
    if (signer_idx >= 0 && signer_idx < master_signers.size()) {
      auto signer = nu.get()->GetUnusedSignerFromMasterSigner(
          master_signers[signer_idx].get_id(), wallet_type, address_type);
      signers.push_back(signer);
      master_signers.erase(master_signers.begin() + signer_idx);
    } else if (signer_idx >= master_signers.size() &&
               signer_idx < master_signers.size() + remote_signers.size()) {
      auto signer = remote_signers[signer_idx - master_signers.size()];
      signers.push_back(signer);
      remote_signers.erase(remote_signers.begin() + signer_idx -
                           master_signers.size());
    } else {
      throw std::runtime_error("Invalid signer");
    }
  }

  auto wallet =
      nu.get()->CreateWallet(name, m, n, signers, address_type, false);
  std::cout << "\nWallet create success. Wallet id: " << wallet.get_id()
            << std::endl;
  std::cout << GetDescriptorRecord(wallet) << std::endl;
}

void newaddress() {
  auto wallets = nu.get()->GetWallets();
  if (wallets.empty()) {
    throw std::runtime_error("Please create wallet first");
  }
  print_list_wallets(wallets);
  int wallet_idx = input_int("Choose wallet to create address");
  if (wallet_idx < 0 || wallet_idx > wallets.size()) {
    throw std::runtime_error("Invalid wallet");
  }

  std::cout << "\nNew address: "
            << nu.get()->NewAddress(wallets[wallet_idx].get_id()) << std::endl;
}

void history() {
  auto wallets = nu.get()->GetWallets();
  if (wallets.empty()) {
    throw std::runtime_error("You don't have any wallet");
  }
  print_list_wallets(wallets);
  int wallet_idx = input_int("Choose wallet to show history");
  if (wallet_idx < 0 || wallet_idx > wallets.size()) {
    throw std::runtime_error("Invalid wallet");
  }

  auto history =
      nu.get()->GetTransactionHistory(wallets[wallet_idx].get_id(), 1000, 0);
  for (auto&& tx : history) {
    std::cout << std::setw(18) << tx.get_height() << " " << tx.get_txid() << " "
              << tx.get_sub_amount() << " sat ("
              << (tx.is_receive() ? "receive" : "send") << ")" << std::endl;
  }
}

void send() {
  auto wallets = nu.get()->GetWallets();
  if (wallets.empty()) {
    throw std::runtime_error("You don't have any wallet");
  }
  print_list_wallets(wallets);
  int wallet_idx = input_int("Choose wallet to send from");
  if (wallet_idx < 0 || wallet_idx > wallets.size()) {
    throw std::runtime_error("Invalid wallet");
  }
  auto wallet = wallets[wallet_idx];

  std::map<std::string, Amount> outputs;
  Amount subtotal = 0;
  do {
    auto to_address = input_string("Enter to address");
    Amount amount = input_int("Enter amount (in satoshi)");
    outputs[to_address] = amount;
    subtotal += amount;
  } while (input_bool("Add another output"));
  Amount fee_rate = input_int("Enter fee rate (sats/kvB)");
  bool sffa = input_bool("Subtract fee from amount");

  // Create transaction
  auto tx = nu.get()->CreateTransaction(wallet.get_id(), outputs, {}, {},
                                        fee_rate, sffa);
  std::cout << "Transaction info\n  Inputs:\n";
  for (auto&& input : tx.get_inputs()) {
    std::cout << "    " << input.txid << ":" << input.vout << std::endl;
  }
  std::cout << "  Psbt: " << tx.get_psbt() << std::endl;
  std::cout << "  Sub total: " << subtotal << std::endl;
  std::cout << "  Fee: " << tx.get_fee() << std::endl;
  std::cout << "  Fee Rate: " << tx.get_fee_rate() << std::endl;
  Amount package_fee_rate{0};
  bool isCpfp = nu.get()->IsCPFP(wallet.get_id(), tx, package_fee_rate);
  if (isCpfp) {
    std::cout << "  Package Fee Rate: " << package_fee_rate << std::endl;
  }
  std::cout << "  Total: " << (subtotal + tx.get_fee()) << "\n\n";

  // Sign transaction
  while (tx.get_status() == TransactionStatus::PENDING_SIGNATURES) {
    auto devices = nu.get()->GetDevices();
    auto signers = nu.get()->GetMasterSigners();
    for (auto&& signer : signers) {
      if (signer.is_software()) devices.push_back(signer.get_device());
    }
    for (auto&& device : devices) {
      auto signers = tx.get_signers();
      auto xfp = device.get_master_fingerprint();
      if (signers.find(xfp) != signers.end() && !signers.at(xfp)) {
        std::cout << "Sign with " << device.get_type() << std::endl;
        tx = nu.get()->SignTransaction(wallet.get_id(), tx.get_txid(), device);
      }
    }
    if (tx.get_status() == TransactionStatus::PENDING_SIGNATURES) {
      if (!input_bool("Plug another signer to sign to transaction")) {
        throw std::runtime_error("Don't have enough sinatures to broadcast");
      }
    }
  }

  // Broadcast transaction
  tx = nu.get()->BroadcastTransaction(wallet.get_id(), tx.get_txid());
  std::cout << "\nTransaction broadcasted. TxID: " << tx.get_txid()
            << std::endl;
}

// Group wallet commands
void newsandbox() {
  auto name = input_string("Enter wallet name");
  auto n = input_int("Total signers");
  auto m = input_int("Required signatures");
  if (m > n) {
    throw std::runtime_error(
        "Required signatures must less or equal total signers");
  }
  if (n < 2) {
    throw std::runtime_error("Group wallet must have at least 2 signers");
  }
  WalletType wallet_type = WalletType::MULTI_SIG;
  AddressType address_type = input_address_type(wallet_type);

  auto group = nu.get()->CreateGroup(name, m, n, address_type);
  std::cout << "\nGroup sandbox create success. Group id: " << group.get_id()
            << std::endl;
  std::cout << "Join url: " << group.get_url() << std::endl;
}

void print_platform_key_policies(
    const std::optional<GroupPlatformKey>& platform_key) {
  std::cout << "- Platform key policies: " << std::endl;
  if (!platform_key.has_value()) {
    return;
  }

  if (platform_key->get_policies().get_global().has_value()) {
    const auto& policy = platform_key->get_policies().get_global().value();
    std::cout << " . Global" << std::endl;
    std::cout << "   - AutoBroadcast: "
              << policy.get_auto_broadcast_transaction() << std::endl;
    std::cout << "   - SigningDelaySeconds: "
              << policy.get_signing_delay_seconds() << std::endl;
    if (policy.get_spending_limit().has_value()) {
      const auto& limit = policy.get_spending_limit().value();
      std::cout << "   - SpendingLimit:" << std::endl;
      std::cout << "     . Interval: " << int(limit.get_interval())
                << std::endl;
      std::cout << "     . Amount: " << limit.get_amount() << std::endl;
      std::cout << "     . Currency: " << limit.get_currency() << std::endl;
    }
  }

  int i = 0;
  for (auto&& signer_policy : platform_key->get_policies().get_signers()) {
    const auto& policy = signer_policy.get_policy();
    std::cout << " . Signer " << i++ << std::endl;
    std::cout << "   - MasterFingerprint: "
              << signer_policy.get_master_fingerprint() << std::endl;
    std::cout << "   - AutoBroadcast: "
              << policy.get_auto_broadcast_transaction() << std::endl;
    std::cout << "   - SigningDelaySeconds: "
              << policy.get_signing_delay_seconds() << std::endl;
    if (policy.get_spending_limit().has_value()) {
      const auto& limit = policy.get_spending_limit().value();
      std::cout << "   - SpendingLimit:" << std::endl;
      std::cout << "     . Interval: " << int(limit.get_interval())
                << std::endl;
      std::cout << "     . Amount: " << limit.get_amount() << std::endl;
      std::cout << "     . Currency: " << limit.get_currency() << std::endl;
    }
  }
}

void print_platform_key_policies(const GroupPlatformKeyPolicies& policies) {
  print_platform_key_policies(GroupPlatformKey(policies));
}

void print_group_dummy_transaction(const GroupDummyTransaction& tx) {
  std::cout << "DummyTransaction ID: " << tx.get_id() << std::endl;
  std::cout << "- Wallet ID: " << tx.get_wallet_id() << std::endl;
  std::cout << "- Type: " << int(tx.get_type()) << std::endl;
  std::cout << "- Status: " << int(tx.get_status()) << std::endl;
  std::cout << "- RequiredSignatures: " << tx.get_required_signatures()
            << std::endl;
  std::cout << "- PendingSignatures: " << tx.get_pending_signatures()
            << std::endl;
  std::cout << "- RequestBody: " << tx.get_request_body() << std::endl;
  std::cout << "- CreatedAt: " << tx.get_created_at() << std::endl;
  std::cout << "- Signatures:" << std::endl;
  for (auto&& signature : tx.get_signatures()) {
    std::cout << " . " << signature.get_master_fingerprint() << ": "
              << signature.get_signature() << std::endl;
  }
  if (tx.get_payload().has_value()) {
    std::cout << "- OldPolicies:" << std::endl;
    print_platform_key_policies(tx.get_payload()->get_old_policies());
    std::cout << "- NewPolicies:" << std::endl;
    print_platform_key_policies(tx.get_payload()->get_new_policies());
  }
}

void print_group_wallet_alert(const GroupWalletAlert& alert) {
  std::cout << "Alert ID: " << alert.get_id() << std::endl;
  std::cout << "- Type: " << int(alert.get_type()) << std::endl;
  std::cout << "- Viewable: " << alert.get_viewable() << std::endl;
  std::cout << "- Title: " << alert.get_title() << std::endl;
  std::cout << "- Body: " << alert.get_body() << std::endl;
  if (alert.get_payload().has_value()) {
    std::cout << "- DummyTransactionId: "
              << alert.get_payload()->get_dummy_transaction_id()
              << std::endl;
    std::cout << "- ReplacementGroupId: "
              << alert.get_payload()->get_replacement_group_id()
              << std::endl;
  }
  std::cout << "- CreatedAt: " << alert.get_created_at() << std::endl;
}

void print_group_transaction_state(const GroupTransactionState& state) {
  std::cout << "- Status: " << int(state.get_status()) << std::endl;
  std::cout << "- Message: " << state.get_message() << std::endl;
  std::cout << "- CosignAt: " << state.get_cosign_at() << std::endl;
}

Wallet choose_group_wallet(const std::string& message) {
  auto wallets = nu.get()->GetGroupWallets();
  if (wallets.empty()) {
    throw std::runtime_error("You don't have any group wallet");
  }
  print_list_wallets(wallets);
  int wallet_idx = input_int(message);
  if (wallet_idx < 0 || wallet_idx >= wallets.size()) {
    throw std::runtime_error("Invalid wallet");
  }
  return wallets[wallet_idx];
}

void printGroup(const GroupSandbox& group) {
  std::cout << std::endl;
  std::cout << "Group ID: " << group.get_id() << std::endl;
  std::cout << "- Name: " << group.get_name() << std::endl;
  std::cout << "- URL: " << group.get_url() << std::endl;
  std::cout << "- M/N: " << group.get_m() << "/" << group.get_n() << std::endl;
  std::cout << "- AddressType: " << int(group.get_address_type()) << std::endl;
  std::cout << "- State: " << group.get_state_id() << std::endl;
  std::cout << "- Finalized: " << group.is_finalized() << std::endl;
  std::cout << "- HasPlatformKey: " << group.get_platform_key().has_value()
            << std::endl;
  std::cout << "- ReplaceWallet: " << group.get_replace_wallet_id()
            << std::endl;
  std::cout << "- Signers: " << std::endl;
  for (auto&& signer : group.get_signers()) {
    if (signer.get_name() == "ADDED" &&
        signer.get_master_fingerprint().empty()) {
      std::cout << " . [xxxxxxxx] (Added)" << std::endl;
    } else {
      std::cout << " . " << signer.get_descriptor() << std::endl;
    }
  }
  std::cout << "- Keys: " << std::endl;
  for (auto&& key : group.get_ephemeral_keys()) {
    std::cout << " . " << key << std::endl;
  }
  std::cout << "- Occupied: " << std::endl;
  for (auto&& [i, v] : group.get_occupied()) {
    std::cout << " . " << i << ": ts " << v.first << " by " << v.second
              << std::endl;
  }
  std::cout << "- Platform key slots: " << std::endl;
  for (auto&& slot : group.get_platform_key_slots()) {
    std::cout << " . " << slot << std::endl;
  }
  std::cout << "- Platform key index: ";
  if (group.get_platform_key_index().has_value()) {
    std::cout << group.get_platform_key_index().value() << std::endl;
  } else {
    std::cout << "(none)" << std::endl;
  }
  print_platform_key_policies(group.get_platform_key());
  std::cout << std::endl;
  std::cout << std::endl;
}

inline void print_list_sandbox(const std::vector<GroupSandbox>& sandboxes) {
  int i = 0;
  std::cout << std::endl;
  for (auto&& sandbox : sandboxes) {
    std::cout << i++ << ": [" << sandbox.get_id() << "] " << sandbox.get_name()
              << " (" << sandbox.is_finalized() << ")" << std::endl;
  }
}

void listsandboxs() { print_list_sandbox(nu.get()->GetGroups()); }

void listgroups() { print_list_wallets(nu.get()->GetGroupWallets()); }

void getsandbox() {
  auto groups = nu.get()->GetGroups();
  if (groups.empty()) {
    throw std::runtime_error("You don't have any group sandbox");
  }
  print_list_sandbox(groups);
  int group_idx = input_int("Choose sandbox to show detail");
  if (group_idx < 0 || group_idx > groups.size()) {
    throw std::runtime_error("Invalid group");
  }

  auto group = nu.get()->GetGroup(groups[group_idx].get_id());
  printGroup(group);
}

void parseurl() {
  auto group_url = input_string("Enter group url");
  auto group = nu.get()->ParseGroupUrl(group_url);
  std::cout << "Group ID: " << group.first << std::endl;
  std::cout << "Redirect url: " << group.second << std::endl;
}

void joinsandbox() {
  auto group_id = input_string("Enter group id");
  auto group = nu.get()->JoinGroup(group_id);
}

void deletesandbox() {
  auto groups = nu.get()->GetGroups();
  if (groups.empty()) {
    throw std::runtime_error("You don't have any group sandbox");
  }
  print_list_sandbox(groups);
  int group_idx = input_int("Choose sandbox to delete");
  if (group_idx < 0 || group_idx > groups.size()) {
    throw std::runtime_error("Invalid group");
  }
  nu.get()->DeleteGroup(groups[group_idx].get_id());
}

void addkeytosandbox() {
  auto master_signers = nu.get()->GetMasterSigners();
  auto remote_signers = nu.get()->GetRemoteSigners();
  if (master_signers.empty() && remote_signers.empty()) {
    throw std::runtime_error("Please create signer first");
  }

  auto groups = nu.get()->GetGroups();
  if (groups.empty()) {
    throw std::runtime_error("You don't have any group sandbox");
  }
  print_list_sandbox(groups);
  int group_idx = input_int("Choose sandbox to add key");
  if (group_idx < 0 || group_idx > groups.size()) {
    throw std::runtime_error("Invalid group");
  }
  auto group = groups[group_idx];

  int slot = input_int("Choose signer slot");
  if (slot < 0 || slot >= group.get_n()) {
    throw std::runtime_error("Invalid signer slot");
  }

  print_list_signers(master_signers, remote_signers);
  int signer_idx = input_int("Choose a signer to add");
  SingleSigner signer{};
  if (signer_idx >= 0 && signer_idx < master_signers.size()) {
    signer = nu.get()->GetUnusedSignerFromMasterSigner(
        master_signers[signer_idx].get_id(), WalletType::MULTI_SIG,
        group.get_address_type());
  } else if (signer_idx >= master_signers.size() &&
             signer_idx < master_signers.size() + remote_signers.size()) {
    signer = remote_signers[signer_idx - master_signers.size()];
  } else {
    throw std::runtime_error("Invalid signer");
  }

  nu.get()->AddSignerToGroup(group.get_id(), signer, slot);
}

void enableplatformkey() {
  auto groups = nu.get()->GetGroups();
  if (groups.empty()) {
    throw std::runtime_error("You don't have any group sandbox");
  }
  print_list_sandbox(groups);
  int group_idx = input_int("Choose sandbox to enable platform key");
  if (group_idx < 0 || group_idx > groups.size()) {
    throw std::runtime_error("Invalid group");
  }
  auto chosen = groups[group_idx];
  std::vector<std::string> slot_names{};
  if (chosen.get_wallet_type() == WalletType::MINISCRIPT) {
    int count = input_int("Platform key slot count");
    if (count < 0) {
      throw std::runtime_error("Invalid platform key slot count");
    }
    for (int i = 0; i < count; i++) {
      slot_names.push_back(input_string("Enter platform key slot name"));
    }
  }
  auto group =
      nu.get()->EnableGroupPlatformKey(chosen.get_id(), slot_names);
  printGroup(group);
}

void disableplatformkey() {
  auto groups = nu.get()->GetGroups();
  if (groups.empty()) {
    throw std::runtime_error("You don't have any group sandbox");
  }
  print_list_sandbox(groups);
  int group_idx = input_int("Choose sandbox to disable platform key");
  if (group_idx < 0 || group_idx > groups.size()) {
    throw std::runtime_error("Invalid group");
  }
  auto group = nu.get()->DisableGroupPlatformKey(groups[group_idx].get_id());
  printGroup(group);
}

GroupSpendingLimit input_group_spending_limit() {
  std::cout << "... Choose spending limit interval: " << std::endl;
  std::cout << "1: Daily" << std::endl;
  std::cout << "2: Weekly" << std::endl;
  std::cout << "3: Monthly" << std::endl;
  std::cout << "4: Yearly" << std::endl;
  int input;
  std::cin >> input;

  GroupSpendingLimit limit{};
  switch (input) {
    case 1:
      limit.set_interval(GroupSpendingLimitInterval::DAILY);
      break;
    case 2:
      limit.set_interval(GroupSpendingLimitInterval::WEEKLY);
      break;
    case 3:
      limit.set_interval(GroupSpendingLimitInterval::MONTHLY);
      break;
    case 4:
      limit.set_interval(GroupSpendingLimitInterval::YEARLY);
      break;
    default:
      throw std::runtime_error("Invalid interval");
  }
  limit.set_amount(input_string("Enter spending limit amount"));
  limit.set_currency(input_string("Enter spending limit currency"));
  return limit;
}

GroupPlatformKeyPolicy input_platform_key_global_policy() {
  GroupPlatformKeyPolicy policy{};
  policy.set_auto_broadcast_transaction(
      input_bool("Auto broadcast transaction"));
  policy.set_signing_delay_seconds(input_int("Enter signing delay seconds"));
  if (input_bool("Set spending limit")) {
    policy.set_spending_limit(input_group_spending_limit());
  }
  return policy;
}

GroupPlatformKeySignerPolicy input_platform_key_signer_policy(
    const std::string& fingerprint) {
  GroupPlatformKeySignerPolicy signer_policy{};
  signer_policy.set_master_fingerprint(fingerprint);
  GroupPlatformKeyPolicy policy{};
  policy.set_auto_broadcast_transaction(
      input_bool("Auto broadcast transaction"));
  policy.set_signing_delay_seconds(input_int("Enter signing delay seconds"));
  if (input_bool("Set spending limit")) {
    policy.set_spending_limit(input_group_spending_limit());
  }
  signer_policy.set_policy(std::move(policy));
  return signer_policy;
}

GroupPlatformKeyPolicies input_platform_key_policies(
    const GroupSandbox& group, const GroupPlatformKeyPolicies& current) {
  std::cout << "... Choose platform key policy type: " << std::endl;
  std::cout << "1: Global" << std::endl;
  std::cout << "2: Signer" << std::endl;
  int input;
  std::cin >> input;

  GroupPlatformKeyPolicies policies = current;
  switch (input) {
    case 1: {
      policies.set_global(input_platform_key_global_policy());
      policies.set_signers({});
      break;
    }
    case 2: {
      std::vector<GroupPlatformKeySignerPolicy> signers{};
      auto named_signers = group.get_wallet_type() == WalletType::MINISCRIPT
                               ? group.get_named_signers()
                               : std::map<std::string, SingleSigner>{};
      for (int i = 0; i < group.get_signers().size(); i++) {
        auto signer = group.get_signers()[i];
        if (signer.get_master_fingerprint().empty()) {
          continue;
        }
        if (group.get_platform_key_index().has_value() &&
            i == group.get_platform_key_index().value()) {
          continue;
        }
        if (group.get_wallet_type() == WalletType::MINISCRIPT) {
          bool is_platform_slot = false;
          for (auto&& slot : group.get_platform_key_slots()) {
            auto it = named_signers.find(slot);
            if (it != named_signers.end() &&
                it->second.get_master_fingerprint() ==
                    signer.get_master_fingerprint()) {
              is_platform_slot = true;
              break;
            }
          }
          if (is_platform_slot) {
            continue;
          }
        }
        std::cout << "... Enter platform key policy for signer ["
                  << signer.get_master_fingerprint() << "]" << std::endl;
        signers.push_back(
            input_platform_key_signer_policy(signer.get_master_fingerprint()));
      }
      if (signers.empty()) {
        throw std::runtime_error("Sandbox has no signer to configure");
      }
      policies.set_global(std::nullopt);
      policies.set_signers(std::move(signers));
      break;
    }
    default:
      throw std::runtime_error("Invalid policy type");
  }
  return policies;
}

GroupPlatformKeyPolicies input_wallet_platform_key_policies(
    const Wallet& wallet, const GroupWalletConfig& config,
    const GroupPlatformKeyPolicies& current) {
  std::cout << "... Choose platform key policy type: " << std::endl;
  std::cout << "1: Global" << std::endl;
  std::cout << "2: Signer" << std::endl;
  int input;
  std::cin >> input;

  GroupPlatformKeyPolicies policies = current;
  switch (input) {
    case 1: {
      policies.set_global(input_platform_key_global_policy());
      policies.set_signers({});
      break;
    }
    case 2: {
      std::vector<GroupPlatformKeySignerPolicy> signers{};
      const auto& platform_fingerprint = config.get_platform_key_fingerprint();
      const int multisig_platform_index =
          (config.get_platform_key().has_value() &&
           wallet.get_wallet_type() == WalletType::MULTI_SIG)
              ? wallet.get_n() - 1
              : -1;
      for (int i = 0; i < wallet.get_signers().size(); i++) {
        auto signer = wallet.get_signers()[i];
        if (signer.get_master_fingerprint().empty()) continue;
        if (!platform_fingerprint.empty() &&
            signer.get_master_fingerprint() == platform_fingerprint) {
          continue;
        }
        if (platform_fingerprint.empty() && i == multisig_platform_index) {
          continue;
        }
        std::cout << "... Enter platform key policy for signer ["
                  << signer.get_master_fingerprint() << "]" << std::endl;
        signers.push_back(
            input_platform_key_signer_policy(signer.get_master_fingerprint()));
      }
      if (signers.empty()) {
        throw std::runtime_error("Wallet has no signer to configure");
      }
      policies.set_global(std::nullopt);
      policies.set_signers(std::move(signers));
      break;
    }
    default:
      throw std::runtime_error("Invalid policy type");
  }
  return policies;
}

void setplatformkeypolicy() {
  auto groups = nu.get()->GetGroups();
  if (groups.empty()) {
    throw std::runtime_error("You don't have any group sandbox");
  }
  print_list_sandbox(groups);
  int group_idx = input_int("Choose sandbox to set platform key policy");
  if (group_idx < 0 || group_idx > groups.size()) {
    throw std::runtime_error("Invalid group");
  }

  auto group = groups[group_idx];
  GroupPlatformKeyPolicies policies{};
  if (group.get_platform_key().has_value() &&
      !input_bool("Replace existing platform key policies")) {
    policies = group.get_platform_key()->get_policies();
  }
  policies = input_platform_key_policies(group, policies);
  group = nu.get()->SetGroupPlatformKeyPolicies(group.get_id(), policies);
  printGroup(group);
}

void finalizesandbox() {
  auto groups = nu.get()->GetGroups();
  if (groups.empty()) {
    throw std::runtime_error("You don't have any group sandbox");
  }
  print_list_sandbox(groups);
  int group_idx = input_int("Choose sandbox to finalize");
  if (group_idx < 0 || group_idx > groups.size()) {
    throw std::runtime_error("Invalid group");
  }
  auto group = groups[group_idx];
  nu.get()->FinalizeGroup(group.get_id());
}

void sendchat() {
  auto wallets = nu.get()->GetGroupWallets();
  if (wallets.empty()) {
    throw std::runtime_error("You don't have any group wallet");
  }
  print_list_wallets(wallets);
  int wallet_idx = input_int("Choose group wallet to send chat");
  if (wallet_idx < 0 || wallet_idx > wallets.size()) {
    throw std::runtime_error("Invalid wallet");
  }
  auto wallet = wallets[wallet_idx];
  auto msg = input_string("Input chat message");
  nu.get()->SendGroupMessage(wallet.get_id(), msg);
}

void replacewallet() {
  auto wallets = nu.get()->GetGroupWallets();
  if (wallets.empty()) {
    throw std::runtime_error("You don't have any group wallet");
  }
  print_list_wallets(wallets);
  int wallet_idx = input_int("Choose group wallet to replace");
  if (wallet_idx < 0 || wallet_idx > wallets.size()) {
    throw std::runtime_error("Invalid wallet");
  }
  auto wallet = wallets[wallet_idx];
  nu.get()->CreateReplaceGroup(wallet.get_id());
}

void getreplacestatus() {
  auto wallets = nu.get()->GetGroupWallets();
  if (wallets.empty()) {
    throw std::runtime_error("You don't have any group wallet");
  }
  print_list_wallets(wallets);
  int wallet_idx = input_int("Choose group wallet");
  if (wallet_idx < 0 || wallet_idx > wallets.size()) {
    throw std::runtime_error("Invalid wallet");
  }
  auto wallet = wallets[wallet_idx];
  auto rs = nu.get()->GetReplaceGroups(wallet.get_id());

  int i = 0;
  std::cout << std::endl;
  for (auto&& [group_id, accepted] : rs) {
    std::cout << i++ << ": " << group_id << " "
              << (accepted ? "accepted" : "pending") << std::endl;
  }
}

void acceptreplace() {
  auto wallets = nu.get()->GetGroupWallets();
  if (wallets.empty()) {
    throw std::runtime_error("You don't have any group wallet");
  }
  print_list_wallets(wallets);
  int wallet_idx = input_int("Choose group wallet");
  if (wallet_idx < 0 || wallet_idx > wallets.size()) {
    throw std::runtime_error("Invalid wallet");
  }
  auto wallet = wallets[wallet_idx];
  auto rs = nu.get()->GetReplaceGroups(wallet.get_id());

  int i = 0;
  std::cout << std::endl;
  std::map<int, std::string> idx_group;
  for (auto&& [group_id, accepted] : rs) {
    idx_group[i] = group_id;
    std::cout << i++ << ": " << group_id << " "
              << (accepted ? "accepted" : "pending") << std::endl;
  }
  int idx = input_int("Choose group sandbox to accept");
  if (idx < 0 || idx >= i) {
    throw std::runtime_error("Invalid sandbox");
  }
  nu.get()->AcceptReplaceGroup(wallet.get_id(), idx_group[idx]);
}

void deletetransaction() {
  auto wallets = nu.get()->GetWallets();
  if (wallets.empty()) {
    throw std::runtime_error("You don't have any wallet");
  }
  print_list_wallets(wallets);
  int wallet_idx = input_int("Choose wallet to show history");
  if (wallet_idx < 0 || wallet_idx > wallets.size()) {
    throw std::runtime_error("Invalid wallet");
  }

  auto wallet_id = wallets[wallet_idx].get_id();
  auto history = nu.get()->GetTransactionHistory(wallet_id, 1000, 0);
  auto check = [&](const Transaction& tx) {
    return tx.get_height() != -1 || tx.is_receive();
  };
  history.erase(std::remove_if(history.begin(), history.end(), check),
                history.end());
  int i = 0;
  for (auto&& tx : history) {
    std::cout << i++ << ": " << tx.get_txid() << " " << tx.get_sub_amount()
              << " sat" << std::endl;
  }
  int tx_idx = input_int("Choose transaction to delete");
  if (tx_idx < 0 || tx_idx > history.size()) {
    throw std::runtime_error("Invalid transaction");
  }
  nu.get()->DeleteTransaction(wallet_id, history[tx_idx].get_txid());
}

void groupconfig() {
  auto wallets = nu.get()->GetGroupWallets();
  if (wallets.empty()) {
    throw std::runtime_error("You don't have any group wallet");
  }
  print_list_wallets(wallets);
  int wallet_idx = input_int("Choose wallet to update config");
  if (wallet_idx < 0 || wallet_idx > wallets.size()) {
    throw std::runtime_error("Invalid wallet");
  }

  auto wallet_id = wallets[wallet_idx].get_id();
  auto config = nu.get()->GetGroupWalletConfig(wallet_id);
  std::cout << "- Current chat retention days: "
            << config.get_chat_retention_days() << std::endl;
  std::cout << "- Has platform key: "
            << config.get_platform_key().has_value() << std::endl;
  std::cout << "- Platform key fingerprint: "
            << config.get_platform_key_fingerprint() << std::endl;
  print_platform_key_policies(config.get_platform_key());

  if (!input_bool("Do you want to change config")) {
    return;
  }

  auto options = nu.get()->GetGroupConfig().get_retention_days_options();

  int d = input_int("Enter chat retention days (" + join(options, ',') + ")");
  if (std::find(options.begin(), options.end(), d) == options.end()) {
    throw std::runtime_error("Invalid config");
  }
  config.set_chat_retention_days(d);
  nu.get()->SetGroupWalletConfig(wallet_id, config);
}

void loopgroupconfig() {
  auto wallets = nu.get()->GetGroupWallets();
  if (wallets.empty()) {
    throw std::runtime_error("You don't have any group wallet");
  }
  print_list_wallets(wallets);
  int wallet_idx = input_int("Choose wallet to loop get config");
  if (wallet_idx < 0 || wallet_idx >= wallets.size()) {
    throw std::runtime_error("Invalid wallet");
  }

  auto wallet_id = wallets[wallet_idx].get_id();
  int iterations =
      input_int("Enter loop count (0 or negative means infinite)");
  int delay_ms = input_int("Enter delay in milliseconds between calls");

  std::cout << "Looping GetGroupWalletConfig for wallet " << wallet_id
            << std::endl;
  for (int i = 0; iterations <= 0 || i < iterations; ++i) {
    try {
      auto config = nu.get()->GetGroupWalletConfig(wallet_id);
      if (i == 0 || (i + 1) % 10 == 0) {
        std::cout << "Success iteration " << (i + 1)
                  << ": retention=" << config.get_chat_retention_days()
                  << ", hasPlatformKey="
                  << config.get_platform_key().has_value() << std::endl;
      }
    } catch (const std::exception& e) {
      std::cout << "Failed at iteration " << (i + 1) << ": " << e.what()
                << std::endl;
      return;
    }

    if (delay_ms > 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
  }
  std::cout << "Loop finished without error." << std::endl;
}

void getwallet() {
  auto wallets = nu.get()->GetWallets();
  if (wallets.empty()) {
    throw std::runtime_error("You don't have any wallet");
  }
  print_list_wallets(wallets);
  int wallet_idx = input_int("Choose wallet to show detail");
  if (wallet_idx < 0 || wallet_idx >= wallets.size()) {
    throw std::runtime_error("Invalid wallet");
  }

  const auto& wallet = wallets[wallet_idx];
  std::cout << "Wallet ID: " << wallet.get_id() << std::endl;
  std::cout << "Wallet Name: " << wallet.get_name() << std::endl;
  std::cout << "Descriptor:" << std::endl;
  std::cout << nu.get()->GetWalletExportData(wallet.get_id(),
                                             ExportFormat::DESCRIPTOR)
            << std::endl;
  std::cout << "BSMS:" << std::endl;
  std::cout << nu.get()->GetWalletExportData(wallet.get_id(),
                                             ExportFormat::BSMS)
            << std::endl;
}

void previewplatformkeypolicyupdate() {
  auto wallet = choose_group_wallet("Choose group wallet to preview policy update");
  auto config = nu.get()->GetGroupWalletConfig(wallet.get_id());
  if (!config.get_platform_key().has_value()) {
    throw std::runtime_error("Wallet does not have platform key");
  }
  GroupPlatformKeyPolicies current = config.get_platform_key()->get_policies();
  auto policies = input_wallet_platform_key_policies(wallet, config, current);
  auto result =
      nu.get()->PreviewGroupPlatformKeyPolicyUpdate(wallet.get_id(), policies);
  std::cout << "- Success: " << result.get_success() << std::endl;
  std::cout << "- DelayApplyInSeconds: "
            << result.get_delay_apply_in_seconds() << std::endl;
  std::cout << "- RequiresDummyTransaction: "
            << result.requires_dummy_transaction() << std::endl;
  if (result.get_dummy_transaction().has_value()) {
    print_group_dummy_transaction(result.get_dummy_transaction().value());
  }
}

void requestplatformkeypolicyupdate() {
  auto wallet = choose_group_wallet("Choose group wallet to request policy update");
  auto config = nu.get()->GetGroupWalletConfig(wallet.get_id());
  if (!config.get_platform_key().has_value()) {
    throw std::runtime_error("Wallet does not have platform key");
  }
  GroupPlatformKeyPolicies current = config.get_platform_key()->get_policies();
  auto policies = input_wallet_platform_key_policies(wallet, config, current);
  auto result =
      nu.get()->RequestGroupPlatformKeyPolicyUpdate(wallet.get_id(), policies);
  std::cout << "- Success: " << result.get_success() << std::endl;
  std::cout << "- DelayApplyInSeconds: "
            << result.get_delay_apply_in_seconds() << std::endl;
  std::cout << "- RequiresDummyTransaction: "
            << result.requires_dummy_transaction() << std::endl;
  if (result.get_dummy_transaction().has_value()) {
    print_group_dummy_transaction(result.get_dummy_transaction().value());
  }
}

void listgroupdummytxs() {
  auto wallet = choose_group_wallet("Choose group wallet to list dummy transactions");
  auto txs = nu.get()->GetGroupDummyTransactions(wallet.get_id());
  int i = 0;
  for (auto&& tx : txs) {
    std::cout << i++ << ": [" << tx.get_id() << "] type=" << int(tx.get_type())
              << " status=" << int(tx.get_status())
              << " pending=" << tx.get_pending_signatures() << std::endl;
  }
}

void getgroupdummytx() {
  auto wallet = choose_group_wallet("Choose group wallet to show dummy transaction");
  auto tx_id = input_string("Enter dummy transaction id");
  auto tx = nu.get()->GetGroupDummyTransaction(wallet.get_id(), tx_id);
  print_group_dummy_transaction(tx);
}

void signgroupdummytx() {
  auto wallet =
      choose_group_wallet("Choose group wallet to sign and update dummy transaction");
  auto group_dummy_tx_id = input_string("Enter dummy transaction id");
  auto group_dummy_tx =
      nu.get()->GetGroupDummyTransaction(wallet.get_id(), group_dummy_tx_id);

  auto devices = nu.get()->GetDevices();
  auto master_signers = nu.get()->GetMasterSigners();
  for (auto&& signer : master_signers) {
    if (signer.is_software()) devices.push_back(signer.get_device());
  }
  if (devices.empty()) {
    throw std::runtime_error("No signer device available");
  }

  print_list_devices(devices);
  int device_idx = input_int("Choose device to sign dummy transaction");
  if (device_idx < 0 || device_idx >= devices.size()) {
    throw std::runtime_error("Invalid device");
  }

  auto fingerprint = devices[device_idx].get_master_fingerprint();
  auto signer_it = std::find_if(
      wallet.get_signers().begin(), wallet.get_signers().end(),
      [&](const SingleSigner& signer) {
        return signer.get_master_fingerprint() == fingerprint;
      });
  if (signer_it == wallet.get_signers().end()) {
    throw std::runtime_error("Signer not found in wallet");
  }

  auto dummy = Utils::GetHealthCheckDummyTx(wallet, group_dummy_tx.get_request_body());

  auto signature = nu.get()->SignHealthCheckMessage(
      wallet, devices[device_idx], *signer_it, dummy);
  auto request_token = Utils::CreateRequestToken(signature, fingerprint);
  auto updated = nu.get()->SignGroupDummyTransaction(wallet.get_id(),
                                                     group_dummy_tx_id,
                                                     {request_token});
  print_group_dummy_transaction(updated);
}


void cancelgroupdummytx() {
  auto wallet =
      choose_group_wallet("Choose group wallet to cancel dummy transaction");
  auto tx_id = input_string("Enter dummy transaction id");
  nu.get()->CancelGroupDummyTransaction(wallet.get_id(), tx_id);
}

void alertcount() {
  auto wallet = choose_group_wallet("Choose group wallet to get alert count");
  std::cout << "AlertCount: "
            << nu.get()->GetGroupWalletAlertCount(wallet.get_id())
            << std::endl;
}

void listalerts() {
  auto wallet = choose_group_wallet("Choose group wallet to list alerts");
  int page = input_int("Enter page");
  int page_size = input_int("Enter page size");
  auto alerts = nu.get()->GetGroupWalletAlerts(wallet.get_id(), page, page_size);
  int i = 0;
  for (auto&& alert : alerts) {
    std::cout << i++ << ": [" << alert.get_id() << "] type="
              << int(alert.get_type()) << " title=" << alert.get_title()
              << std::endl;
  }
}

void getalert() {
  auto wallet = choose_group_wallet("Choose group wallet to show alerts");
  int page = input_int("Enter page");
  int page_size = input_int("Enter page size");
  auto alerts = nu.get()->GetGroupWalletAlerts(wallet.get_id(), page, page_size);
  if (alerts.empty()) {
    throw std::runtime_error("No alerts");
  }
  int idx = input_int("Choose alert index");
  if (idx < 0 || idx >= alerts.size()) {
    throw std::runtime_error("Invalid alert");
  }
  print_group_wallet_alert(alerts[idx]);
}

void viewalert() {
  auto wallet = choose_group_wallet("Choose group wallet to mark alert viewed");
  auto alert_id = input_string("Enter alert id");
  nu.get()->MarkGroupWalletAlertViewed(wallet.get_id(), alert_id);
}

void dismissalert() {
  auto wallet = choose_group_wallet("Choose group wallet to dismiss alert");
  auto alert_id = input_string("Enter alert id");
  nu.get()->DismissGroupWalletAlert(wallet.get_id(), alert_id);
}

void getgrouptxplatformkeystatus() {
  auto wallet =
      choose_group_wallet("Choose group wallet to get transaction platform key status");
  auto tx_id = input_string("Enter transaction id");
  auto state = nu.get()->GetGroupTransactionState(wallet.get_id(), tx_id);
  print_group_transaction_state(state);
}

void recovergroupwallet() {
  auto descriptor = input_multiline_string(
      "Paste wallet descriptor or BSMS payload", "END");
  auto wallet = Utils::ParseWalletDescriptor(descriptor);

  std::cout << "Parsed wallet:" << std::endl;
  std::cout << "- Id: " << wallet.get_id() << std::endl;
  std::cout << "- Name: " << wallet.get_name() << std::endl;

  bool exists = nu.get()->CheckGroupWalletExists(wallet);
  std::cout << "- Group wallet exists on backend: " << exists << std::endl;
  if (!exists) {
    return;
  }

  if (nu.get()->HasWallet(wallet.get_id())) {
    wallet = nu.get()->GetWallet(wallet.get_id());
  } else {
    wallet = nu.get()->CreateWallet(wallet, true);
  }

  nu.get()->RecoverGroupWallet(wallet.get_id());
  std::cout << "Recover group wallet requested for: " << wallet.get_id()
            << std::endl;
}

void init() {
  auto account = input_string("Enter account name");
  auto token = input_string("Enter token");

  AppSettings settings;
  settings.set_chain(Chain::MAIN);
  settings.set_chain(Chain::TESTNET);
  settings.set_hwi_path("/home/giahuy/Documents/nunchuk/HWI/hwi.py");
  settings.enable_proxy(false);
  settings.set_testnet_servers({"testnet.nunchuk.io:50001"});
  //settings.set_testnet_servers({"signet.nunchuk.io:50002"});
  settings.set_mainnet_servers({"mainnet.nunchuk.io:51001"});
  settings.set_storage_path("/home/bringer/libnunchuk/examples/playground.cpp");
  settings.set_group_server("https://api-testnet.nunchuk.io");
  //settings.set_group_server("http://localhost:8080");
  nu = MakeNunchukForAccount(settings, {}, account);
  nu->EnableGroupWallet("ubuntu", "22.04", "1.0.0", "desktop", account, token);
}

void interactive() {
  class Command {
   public:
    using Actor = std::function<void()>;

    Command(Actor actor, const std::string& name,
            const std::string& description)
        : actor_(std::move(actor)),
          name_(std::move(name)),
          description_(std::move(description)) {}
    Actor actor_;
    std::string name_;
    std::string description_;
  };

  Command commands[] = {
      {listdevices, "listdevices", "list devices"},
      {listsigners, "listsigners", "list master signers"},
      {listwallets, "listwallets", "list wallets"},
      {newsigner, "newsigner", "create new signer"},
      {newwallet, "newwallet", "create new wallet"},
      {newaddress, "newaddress", "create new receive address"},

      {newsandbox, "newsandbox", "create new group sandbox"},
      {listsandboxs, "listsandboxs", "list group sandboxs"},
      {parseurl, "parseurl", "parse group sandbox url"},
      {getsandbox, "getsandbox", "get group sandbox detail"},
      {joinsandbox, "joinsandbox", "join group sandbox"},
      {deletesandbox, "deletesandbox", "delete sandbox"},
      {addkeytosandbox, "addkeytosandbox", "add key to group sandbox"},
      {enableplatformkey, "enableplatformkey", "enable platform key"},
      {disableplatformkey, "disableplatformkey", "disable platform key"},
      {setplatformkeypolicy, "setplatformkeypolicy",
       "set platform key policy on sandbox"},
      {finalizesandbox, "finalizesandbox", "finalize group sandbox"},
      {listgroups, "listgroups", "list group wallets"},
      {sendchat, "sendchat", "send group chat"},
      {deletetransaction, "deletetransaction", "delete transaction"},
      {groupconfig, "getgroupconfig",
       "show group config and optionally update it"},
      {loopgroupconfig, "loopgroupconfig",
       "loop GetGroupWalletConfig until failure or completion"},
      {getwallet, "getwallet", "show wallet descriptor and BSMS"},
      {previewplatformkeypolicyupdate, "previewplatformkeypolicyupdate",
       "preview wallet platform key policy update"},
      {requestplatformkeypolicyupdate, "requestplatformkeypolicyupdate",
       "request wallet platform key policy update"},
      {listgroupdummytxs, "listgroupdummytxs",
       "list wallet dummy transactions"},
      {getgroupdummytx, "getgroupdummytx", "show wallet dummy transaction"},
      {signgroupdummytx, "signgroupdummytx", "sign wallet dummy transaction"},
      {cancelgroupdummytx, "cancelgroupdummytx",
       "cancel wallet dummy transaction"},
      {getgrouptxplatformkeystatus, "getgrouptxplatformkeystatus",
       "show platform key status for a group wallet transaction"},
      {recovergroupwallet, "recovergroupwallet",
       "recover group wallet from pasted descriptor"},
      {alertcount, "alertcount", "get group wallet alert count"},
      {listalerts, "listalerts", "list group wallet alerts"},
      {getalert, "getalert", "show one group wallet alert"},
      {viewalert, "viewalert", "mark group wallet alert viewed"},
      {dismissalert, "dismissalert", "dismiss group wallet alert"},
      {replacewallet, "replacewallet", "create replace sandbox"},
      {getreplacestatus, "getreplacestatus", "get replace sandbox"},
      {acceptreplace, "acceptreplace", "accept replace sandbox"},

      {history, "history", "list transaction history"},
      {send, "send", "create new transaction"}};

  std::map<std::string, const Command*> mapCommands;
  for (auto&& command : commands) {
    mapCommands[command.name_] = &command;
  }

  std::cout << "\e[1mKusari\e[0m 0.1.0 (GroupWallet)" << std::endl;
  std::cout << "Type \"#help\" for more information." << std::endl;
  for (;;) {
    std::string input_line;
    std::cout << "\n>>> _\b";
    std::cin >> input_line;
    input_line = std::regex_replace(input_line, std::regex("^ +| +$"), "$1");

    if (input_line == "#quit") {
      break;
    } else if (input_line == "#help") {
      std::cout << "\nYou can type in following commands and hit enter: \n\n";
      for (auto&& command : commands) {
        std::cout << std::setw(18) << command.name_ << ": "
                  << command.description_ << std::endl;
      }
    } else {
      auto c = mapCommands.find(input_line);
      if (c == mapCommands.end()) {
        std::cout
            << "Error: Invalid command. Type \"#help\" for more information."
            << std::endl;
      } else {
        //try {
          (*c).second->actor_();
        //} catch (std::exception& e) {
        //  std::cout << "Error: " << e.what() << std::endl;
        //}
      }
    }
  }
}

void sandboxListener(const GroupSandbox& state) {
  std::cout << "\n--- Received sandbox update" << std::endl;
  printGroup(state);
}

void messageListener(const GroupMessage& msg) {
  std::cout << "\n--- Received message ";
  std::cout << "(" << msg.get_wallet_id() << "): " << msg.get_content();
  std::cout << std::endl;
}

void transactionListener(std::string tx_id, TransactionStatus status,
                         std::string wallet_id) {
  std::cout << "\n--- Received transaction update ";
  std::cout << "(" << wallet_id << "): " << tx_id << ". Status " << int(status);
  std::cout << std::endl;
}

void replaceLisnter(const std::string& wallet_id, const std::string& group_id) {
  std::cout << "\n--- Received replace request ";
  std::cout << "(" << wallet_id << "): " << group_id;
  std::cout << std::endl;
}

void dashboardListener(const std::string& wallet_id) {
  std::cout << "\n--- Group wallet dashboard update ";
  std::cout << "(" << wallet_id << ")";
  std::cout << std::endl;
  try {
    auto count = nu->GetGroupWalletAlertCount(wallet_id);
    auto alerts = nu->GetGroupWalletAlerts(wallet_id, 0, 10);
    auto dummy_txs = nu->GetGroupDummyTransactions(wallet_id);
    std::cout << "AlertCount: " << count << std::endl;
    std::cout << "Alerts: " << alerts.size() << std::endl;
    for (auto&& alert : alerts) {
      std::cout << " . [" << alert.get_id() << "] type="
                << int(alert.get_type()) << " title=" << alert.get_title() << " body=" << alert.get_body() << " viewable=" << alert.get_viewable()
                << std::endl;
    }
    std::cout << "DummyTransactions: " << dummy_txs.size() << std::endl;
    for (auto&& tx : dummy_txs) {
      std::cout << " . [" << tx.get_id() << "] type=" << int(tx.get_type())
                << " status=" << int(tx.get_status())
                << " pending=" << tx.get_pending_signatures() << std::endl;
    }
  } catch (std::exception& e) {
    std::cout << "DashboardListenerError: " << e.what() << std::endl;
  }
}

int main(int argc, char** argv) {
  loguru::g_stderr_verbosity = loguru::Verbosity_OFF;
  init();
  auto t1 = std::thread([&]() { nu->StartConsumeGroupEvent(); });
  nu->AddGroupUpdateListener(sandboxListener);
  nu->AddGroupMessageListener(messageListener);
  nu->AddTransactionListener(transactionListener);
  nu->AddReplaceRequestListener(replaceLisnter);
  nu->AddGroupWalletDashboardListener(dashboardListener);

  interactive();
  nu->StopConsumeGroupEvent();
  t1.join();
  nu.reset();
}
