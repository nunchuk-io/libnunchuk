// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nunchuk.h>
#include <utils/loguru.hpp>

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

inline void print_list_devices(const std::vector<Device>& devices) {
  int i = 0;
  std::cout << std::endl;
  for (auto&& device : devices) {
    std::cout << i++ << ": [" << device.get_master_fingerprint() << "] "
              << device.get_model() << " (" << device.get_path() << ")"
              << std::endl;
  }
}

inline void print_list_master_signers(
    const std::vector<MasterSigner>& signers) {
  int i = 0;
  std::cout << std::endl;
  for (auto&& signer : signers) {
    std::cout << i++ << ": [" << signer.get_id() << "] " << signer.get_name()
              << std::endl;
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

void listsigners() { print_list_master_signers(nu.get()->GetMasterSigners()); }

void listwallets() { print_list_wallets(nu.get()->GetWallets()); }

void newsigner() {
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
      "signer_name", {device_xfp}, [](int percent) { return true; });
  std::cout << "\nSigner create success. Signer id: " << master_signer.get_id()
            << std::endl;
}

void newwallet() {
  auto master_signers = nu.get()->GetMasterSigners();
  if (master_signers.empty()) {
    throw std::runtime_error("Please create signer first");
  }

  auto name = input_string("Enter wallet name");
  auto n = input_int("Total signers");
  auto m = input_int("Required signatures");
  if (m > n) {
    throw std::runtime_error(
        "Required signatures must less or equal total signers");
  }
  AddressType address_type = AddressType::NATIVE_SEGWIT;
  WalletType wallet_type =
      n == 1 ? WalletType::SINGLE_SIG : WalletType::MULTI_SIG;

  std::vector<SingleSigner> signers;
  for (int i = 0; i < n; i++) {
    print_list_master_signers(master_signers);
    int signer_idx = input_int("Choose a singer to add");
    if (signer_idx < 0 || signer_idx > master_signers.size()) {
      throw std::runtime_error("Invalid signer");
    }
    auto signer = nu.get()->GetUnusedSignerFromMasterSigner(
        master_signers[signer_idx].get_id(), wallet_type, address_type);
    signers.push_back(signer);
    master_signers.erase(master_signers.begin() + signer_idx);
  }

  auto wallet =
      nu.get()->CreateWallet(name, m, n, signers, address_type, false);
  std::cout << "\nWallet create success. Wallet id: " << wallet.get_id()
            << std::endl;
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
    Amount amount = input_int("Enter amount (int satoshi)");
    outputs[to_address] = amount;
    subtotal += amount;
  } while (input_bool("Add another output"));

  // Create transaction
  auto tx = nu.get()->CreateTransaction(wallet.get_id(), outputs);
  std::cout << "Transaction info\n  Inputs:\n";
  for (auto&& input : tx.get_inputs()) {
    std::cout << "    " << input.first << ":" << input.second << std::endl;
  }
  std::cout << "  Sub total: " << subtotal << std::endl;
  std::cout << "  Fee: " << tx.get_fee() << std::endl;
  std::cout << "  Total: " << (subtotal + tx.get_fee()) << "\n\n";

  // Sign transaction
  while (tx.get_status() == TransactionStatus::PENDING_SIGNATURES) {
    auto devices = nu.get()->GetDevices();
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

void init() {
  AppSettings settings;
  settings.set_chain(Chain::TESTNET);
  settings.set_hwi_path("lib/bin/hwi");
  settings.enable_proxy(false);
  settings.set_testnet_servers({"127.0.0.1:50001"});
  nu = MakeNunchuk(settings);
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
      {history, "history", "list transaction history"},
      {send, "send", "create new transaction"}};

  std::map<std::string, const Command*> mapCommands;
  for (auto&& command : commands) {
    mapCommands[command.name_] = &command;
  }

  std::cout << "\e[1mKusari\e[0m 0.0.1" << std::endl;
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

int main(int argc, char** argv) {
  loguru::g_stderr_verbosity = loguru::Verbosity_OFF;
  init();
  interactive();
}