// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nunchukmatriximpl.h>
#include <iostream>
#include <sstream>
#include <utils/json.hpp>

#include <descriptor.h>
#include <coreutils.h>

using json = nlohmann::json;

namespace nunchuk {

std::string ChainToStr(Chain value) {
  if (value == Chain::TESTNET) return "TESTNET";
  if (value == Chain::REGTEST) return "REGTEST";
  return "MAIN";
}

Chain ChainFromStr(const std::string& value) {
  if (value == "TESTNET") return Chain::TESTNET;
  if (value == "REGTEST") return Chain::REGTEST;
  if (value == "MAIN") return Chain::MAIN;
  throw NunchukException(NunchukException::INVALID_CHAIN, "invalid chain");
}

std::string AddressTypeToStr(AddressType value) {
  if (value == AddressType::LEGACY) return "LEGACY";
  if (value == AddressType::NESTED_SEGWIT) return "NESTED_SEGWIT";
  return "NATIVE_SEGWIT";
}

AddressType AddressTypeFromStr(const std::string& value) {
  if (value == "LEGACY") return AddressType::LEGACY;
  if (value == "NESTED_SEGWIT") return AddressType::NESTED_SEGWIT;
  if (value == "NATIVE_SEGWIT") return AddressType::NATIVE_SEGWIT;
  throw NunchukException(NunchukException::INVALID_ADDRESS_TYPE,
                         "invalid address type");
}

std::string SignerToStr(const SingleSigner& value) {
  std::stringstream key;
  key << "[" << value.get_master_fingerprint()
      << FormalizePath(value.get_derivation_path()) << "]"
      << (value.get_xpub().empty() ? value.get_public_key() : value.get_xpub())
      << std::endl;
  return key.str();
}

NunchukMatrixEvent NunchukMatrixImpl::NewEvent(const std::string& room_id,
                                               const std::string& event_type,
                                               const std::string& content) {
  NunchukMatrixEvent event{};
  event.set_room_id(room_id);
  event.set_type(event_type);
  event.set_content(content);
  event.set_sender(sender_);
  event.set_ts(std::time(0));
  return event;
}

NunchukMatrixImpl::NunchukMatrixImpl(const std::string& sender, Chain chain)
    : db_(), sender_(sender), chain_(chain) {}

NunchukMatrix::~NunchukMatrix() = default;
NunchukMatrixImpl::~NunchukMatrixImpl() {}

NunchukMatrixEvent NunchukMatrixImpl::InitWallet(
    const std::string& room_id, const std::string& name, int m, int n,
    AddressType address_type, bool is_escrow, const std::string& description) {
  if (db_.HasWallet(room_id)) {
    throw new NunchukMatrixException(
        NunchukMatrixException::SHARED_WALLET_EXISTS, "shared wallet exists");
  }
  json content = {{"msgtype", "io.nunchuk.wallet.init"},
                  {"body",
                   {{"name", name},
                    {"description", description},
                    {"m", m},
                    {"n", n},
                    {"address_type", AddressTypeToStr(address_type)},
                    {"is_escrow", is_escrow},
                    {"members", json::array()},
                    {"chain", ChainToStr(chain_)}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::JoinWallet(const std::string& room_id,
                                                 const SingleSigner& signer) {
  auto wallet = db_.GetWallet(room_id);
  json content = {
      {"msgtype", "io.nunchuk.wallet.join"},
      {"body",
       {{"key", SignerToStr(signer)},
        {"io.nunchuk.relates_to", {{"init_id", wallet.get_init_id()}}}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::LeaveWallet(const std::string& room_id,
                                                  const std::string& join_id,
                                                  const std::string& reason) {
  auto wallet = db_.GetWallet(room_id);
  json content = {
      {"msgtype", "io.nunchuk.wallet.leave"},
      {"body",
       {{"reason", reason},
        {"io.nunchuk.relates_to",
         {{"init_id", wallet.get_init_id()}, {"join_id", join_id}}}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::CancelWallet(const std::string& room_id,
                                                   const std::string& reason) {
  auto wallet = db_.GetWallet(room_id);
  json content = {
      {"msgtype", "io.nunchuk.wallet.cancel"},
      {"body",
       {{"reason", reason},
        {"io.nunchuk.relates_to", {{"init_id", wallet.get_init_id()}}}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::CreateWallet(
    const std::unique_ptr<Nunchuk>& nu, const std::string& room_id) {
  auto wallet = db_.GetWallet(room_id);
  auto join_ids = wallet.get_join_ids();

  auto init_event = db_.GetEvent(wallet.get_init_id());

  std::vector<SingleSigner> signers = {};
  for (auto& id : join_ids) {
    auto event = db_.GetEvent(id);
    json content = json::parse(event.get_content());
    signers.push_back(ParseSignerString(content["key"]));
  }

  json wallet_config = json::parse(init_event.get_content())["body"];
  std::string name = wallet_config["name"];
  int m = wallet_config["m"];
  int n = wallet_config["n"];
  std::string description = wallet_config["description"];
  bool is_escrow = wallet_config["is_escrow"];
  auto a = AddressTypeFromStr(wallet_config["address_type"]);
  auto w = n == 1 ? WalletType::SINGLE_SIG
                  : (is_escrow ? WalletType::ESCROW : WalletType::MULTI_SIG);

  auto nwallet =
      nu->CreateWallet(name, m, n, signers, a, is_escrow, description);
  wallet.set_wallet_id(nwallet.get_id());
  db_.SetWallet(room_id, wallet);

  std::string descriptor = GetDescriptorForSigners(
      signers, m, DescriptorPath::TEMPLATE, a, w, 0, true);
  std::string first_address = CoreUtils::getInstance().DeriveAddresses(
      GetDescriptorForSigners(signers, m, DescriptorPath::EXTERNAL_ALL, a, w,
                              is_escrow ? -1 : 0, true),
      is_escrow ? -1 : 0);

  json content = {
      {"msgtype", "io.nunchuk.wallet.create"},
      {"body",
       {{"descriptor", descriptor},
        {"path_restriction", "/0/*,/1/*"},
        {"first_address", first_address},
        {"io.nunchuk.relates_to",
         {{"init_id", wallet.get_init_id()}, {"join_ids", join_ids}}}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::InitTransaction(
    const std::string& room_id, const Transaction& tx) {
  auto wallet = db_.GetWallet(room_id);
  json content = {{"msgtype", "io.nunchuk.transaction.init"},
                  {"body",
                   {{"wallet_id", wallet.get_wallet_id()},
                    {"memo", tx.get_memo()},
                    {"psbt", tx.get_psbt()},
                    {"fee_rate", tx.get_fee_rate()},
                    {"subtract_fee_from_amount", tx.subtract_fee_from_amount()},
                    {"chain", ChainToStr(chain_)}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::SignTransaction(
    const std::string& init_id, const Transaction& tx) {
  auto event = db_.GetEvent(init_id);
  std::string room_id = event.get_room_id();
  json content = {{"msgtype", "io.nunchuk.transaction.sign"},
                  {"body",
                   {{"psbt", tx.get_psbt()},
                    {"io.nunchuk.relates_to", {{"init_id", init_id}}}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::RejectTransaction(
    const std::string& init_id, const std::string& reason) {
  auto event = db_.GetEvent(init_id);
  std::string room_id = event.get_room_id();
  json content = {{"msgtype", "io.nunchuk.transaction.reject"},
                  {"body",
                   {{"reason", reason},
                    {"io.nunchuk.relates_to", {{"init_id", init_id}}}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::CancelTransaction(
    const std::string& init_id, const std::string& reason) {
  auto event = db_.GetEvent(init_id);
  std::string room_id = event.get_room_id();
  json content = {{"msgtype", "io.nunchuk.transaction.cancel"},
                  {"body",
                   {{"reason", reason},
                    {"io.nunchuk.relates_to", {{"init_id", init_id}}}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::BroadcastTransaction(
    const std::string& init_id, const Transaction& tx) {
  auto event = db_.GetEvent(init_id);
  std::string room_id = event.get_room_id();
  auto pendingTx = db_.GetTransaction(init_id);
  json content = {{"msgtype", "io.nunchuk.transaction.broadcast"},
                  {"body",
                   {{"tx_id", tx.get_txid()},
                    {"io.nunchuk.relates_to",
                     {{"init_id", pendingTx.get_init_id()},
                      {"sign_ids", pendingTx.get_sign_ids()}}}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content.dump());
}

RoomSharedWallet NunchukMatrixImpl::GetRoomWallet(const std::string& room_id) {
  return db_.GetWallet(room_id);
}

std::vector<RoomTransaction> NunchukMatrixImpl::GetPendingTransactions(
    const std::string& room_id) {
  auto pending = db_.GetPendingTransactions(room_id);
  std::vector<RoomTransaction> rs{};
  for (auto& id : pending) {
    rs.push_back(db_.GetTransaction(id));
  }
  return rs;
}

void NunchukMatrixImpl::ConsumeEvent(const std::unique_ptr<Nunchuk>& nu,
                                     const NunchukMatrixEvent& event) {
  if (event.get_type() != "io.nunchuk.wallet" &&
      event.get_type() != "io.nunchuk.transaction")
    return;
  if (event.get_event_id().empty()) return;

  db_.SetEvent(event.get_event_id(), event);
  json content = json::parse(event.get_content());
  std::string msgtype = content["msgtype"];
  json body = content["body"];
  if (msgtype == "io.nunchuk.wallet.init") {
    RoomSharedWallet wallet{};
    wallet.set_init_id(event.get_event_id());
    db_.SetWallet(event.get_room_id(), wallet);
  } else if (msgtype == "io.nunchuk.wallet.join") {
    auto wallet = db_.GetWallet(event.get_room_id());
    wallet.add_join_id(event.get_event_id());
    db_.SetWallet(event.get_room_id(), wallet);
  } else if (msgtype == "io.nunchuk.wallet.leave") {
    auto wallet = db_.GetWallet(event.get_room_id());
    wallet.add_leave_id(event.get_event_id());
    db_.SetWallet(event.get_room_id(), wallet);
  } else if (msgtype == "io.nunchuk.wallet.cancel") {
    auto wallet = db_.GetWallet(event.get_room_id());
    wallet.set_cancel_id(event.get_event_id());
    db_.SetWallet(event.get_room_id(), wallet);
  } else if (msgtype == "io.nunchuk.wallet.create") {
    auto wallet = db_.GetWallet(event.get_room_id());
    wallet.set_finalize_id(event.get_event_id());

    if (event.get_sender() != sender_) {
      auto init_event = db_.GetEvent(wallet.get_init_id());
      json wallet_config = json::parse(init_event.get_content())["body"];
      std::string name = wallet_config["name"];
      std::string description = wallet_config["description"];
      std::string desc = body["descriptor"];

      AddressType a;
      WalletType w;
      int m;
      int n;
      std::vector<SingleSigner> signers;
      if (!ParseDescriptors(desc, a, w, m, n, signers)) {
        throw NunchukException(NunchukException::INVALID_PARAMETER,
                               "Could not parse descriptor");
      }
      auto nwallet = nu->CreateWallet(name, m, n, signers, a,
                                      w == WalletType::ESCROW, description);
      wallet.set_wallet_id(nwallet.get_id());
    }
    db_.SetWallet(event.get_room_id(), wallet);
  } else if (msgtype == "io.nunchuk.transaction.init") {
    RoomTransaction tx{};
    tx.set_init_id(event.get_event_id());
    tx.set_wallet_id(body["wallet_id"]);
    auto ntx = nu->ImportPsbt(tx.get_wallet_id(), body["psbt"]);
    tx.set_tx_id(ntx.get_txid());
    db_.SetTransaction(event.get_room_id(), event.get_event_id(), tx);
  } else if (msgtype == "io.nunchuk.transaction.sign") {
    std::string init_id = content["io.nunchuk.relates_to"]["init_id"];
    auto tx = db_.GetTransaction(init_id);
    tx.add_sign_id(event.get_event_id());
    nu->ImportPsbt(tx.get_wallet_id(), body["psbt"]);
    db_.SetTransaction(event.get_room_id(), init_id, tx);
  } else if (msgtype == "io.nunchuk.transaction.reject") {
    std::string init_id = content["io.nunchuk.relates_to"]["init_id"];
    auto tx = db_.GetTransaction(init_id);
    tx.add_reject_id(event.get_event_id());
    db_.SetTransaction(event.get_room_id(), init_id, tx);
  } else if (msgtype == "io.nunchuk.transaction.cancel") {
    std::string init_id = content["io.nunchuk.relates_to"]["init_id"];
    auto tx = db_.GetTransaction(init_id);
    tx.set_cancel_id(event.get_event_id());
    db_.SetTransaction(event.get_room_id(), init_id, tx);
  } else if (msgtype == "io.nunchuk.transaction.broadcast") {
    std::string init_id = content["io.nunchuk.relates_to"]["init_id"];
    auto tx = db_.GetTransaction(init_id);
    tx.set_broadcast_id(event.get_event_id());
    db_.SetTransaction(event.get_room_id(), init_id, tx);
  }
}

std::unique_ptr<NunchukMatrix> MakeNunchukMatrixForAccount(
    const AppSettings& appsettings, const std::string& passphrase,
    const std::string& account) {
  return std::unique_ptr<NunchukMatrixImpl>(
      new NunchukMatrixImpl(account, appsettings.get_chain()));
}

}  // namespace nunchuk