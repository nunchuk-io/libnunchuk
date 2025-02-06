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
    std::cout << "    " << input.first << ":" << input.second << std::endl;
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

void printGroup(const GroupSandbox& group) {
  std::cout << std::endl;
  std::cout << "Group ID: " << group.get_id() << std::endl;
  std::cout << "- Name: " << group.get_name() << std::endl;
  std::cout << "- URL: " << group.get_url() << std::endl;
  std::cout << "- M/N: " << group.get_m() << "/" << group.get_n() << std::endl;
  std::cout << "- AddressType: " << int(group.get_address_type()) << std::endl;
  std::cout << "- State: " << group.get_state_id() << std::endl;
  std::cout << "- Finalized: " << group.is_finalized() << std::endl;
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

void joinsandbox() {
  auto group_id = input_string("Enter group id");
  auto group = nu.get()->JoinGroup(group_id);
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

  auto options = nu.get()->GetGroupConfig().get_retention_days_options();

  int d = input_int("Enter chat retention days (" + join(options, ',') + ")");
  if (std::find(options.begin(), options.end(), d) == options.end()) {
    throw std::runtime_error("Invalid config");
  }
  config.set_chat_retention_days(d);
  nu.get()->SetGroupWalletConfig(wallet_id, config);
}

void init() {
  auto account = input_string("Enter account name");

  AppSettings settings;
  settings.set_chain(Chain::TESTNET);
  settings.set_hwi_path("lib/bin/hwi");
  settings.enable_proxy(false);
  settings.set_testnet_servers({"testnet.nunchuk.io:50001"});
  settings.set_storage_path("/home/bringer/libnunchuk/examples/playground.cpp");
  settings.set_group_server("https://api-testnet.nunchuk.io");
  nu = MakeNunchukForAccount(settings, {}, account);
  nu->EnableGroupWallet("ubuntu", "22.04", "1.0.0", "desktop", account, {});
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
      {getsandbox, "getsandbox", "get group sandbox detail"},
      {joinsandbox, "joinsandbox", "join group sandbox"},
      {addkeytosandbox, "addkeytosandbox", "add key to group sandbox"},
      {finalizesandbox, "finalizesandbox", "finalize group sandbox"},
      {listgroups, "listgroups", "list group wallets"},
      {sendchat, "sendchat", "send group chat"},
      {deletetransaction, "deletetransaction", "delete transaction"},
      {groupconfig, "setgroupconfig", "set group config"},

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
        try {
          (*c).second->actor_();
        } catch (std::exception& e) {
          std::cout << "Error: " << e.what() << std::endl;
        }
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

int main(int argc, char** argv) {
  loguru::g_stderr_verbosity = loguru::Verbosity_OFF;
  init();
  auto t1 = std::thread([&]() { nu->StartConsumeGroupEvent(); });
  nu->AddGroupUpdateListener(sandboxListener);
  nu->AddGroupMessageListener(messageListener);
  nu->AddTransactionListener(transactionListener);

  interactive();
  nu->StopConsumeGroupEvent();
  t1.join();
  nu.reset();
}
