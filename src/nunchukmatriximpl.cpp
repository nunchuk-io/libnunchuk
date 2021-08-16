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
  event.set_event_id(sendfunc_(room_id, event_type, content));

  auto db = storage_.GetRoomDb(chain_);
  db.SetEvent(event.get_event_id(), event);
  return event;
}

NunchukMatrixImpl::NunchukMatrixImpl(const AppSettings& appsettings,
                                     const std::string& passphrase,
                                     const std::string& account,
                                     SendEventFunc sendfunc)
    : storage_(appsettings.get_storage_path(), passphrase, account),
      sender_(account),
      chain_(appsettings.get_chain()),
      sendfunc_(sendfunc) {}
NunchukMatrix::~NunchukMatrix() = default;
NunchukMatrixImpl::~NunchukMatrixImpl() {}

NunchukMatrixEvent NunchukMatrixImpl::InitWallet(
    const std::string& room_id, const std::string& name, int m, int n,
    AddressType address_type, bool is_escrow, const std::string& description) {
  auto db = storage_.GetRoomDb(chain_);
  if (db.HasWallet(room_id)) {
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
  auto event = NewEvent(room_id, "io.nunchuk.wallet", content.dump());
  RoomWallet wallet{};
  wallet.set_init_event_id(event.get_event_id());
  db.SetWallet(event.get_room_id(), wallet);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::JoinWallet(const std::string& room_id,
                                                 const SingleSigner& signer) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetWallet(room_id);
  json content = {{"msgtype", "io.nunchuk.wallet.join"},
                  {"body",
                   {{"key", SignerToStr(signer)},
                    {"io.nunchuk.relates_to",
                     {{"init_event_id", wallet.get_init_event_id()}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.wallet", content.dump());
  wallet.add_join_event_id(event.get_event_id());
  db.SetWallet(event.get_room_id(), wallet);
  SendWalletReady(room_id);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::LeaveWallet(
    const std::string& room_id, const std::string& join_event_id,
    const std::string& reason) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetWallet(room_id);
  json content = {{"msgtype", "io.nunchuk.wallet.leave"},
                  {"body",
                   {{"reason", reason},
                    {"io.nunchuk.relates_to",
                     {{"init_event_id", wallet.get_init_event_id()},
                      {"join_event_id", join_event_id}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.wallet", content.dump());
  wallet.add_leave_event_id(event.get_event_id());
  db.SetWallet(event.get_room_id(), wallet);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::CancelWallet(const std::string& room_id,
                                                   const std::string& reason) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetWallet(room_id);
  json content = {{"msgtype", "io.nunchuk.wallet.cancel"},
                  {"body",
                   {{"reason", reason},
                    {"io.nunchuk.relates_to",
                     {{"init_event_id", wallet.get_init_event_id()}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.wallet", content.dump());
  wallet.set_cancel_event_id(event.get_event_id());
  db.SetWallet(event.get_room_id(), wallet);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::CreateWallet(
    const std::unique_ptr<Nunchuk>& nu, const std::string& room_id) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetWallet(room_id);
  auto join_event_ids = wallet.get_join_event_ids();

  auto init_event = db.GetEvent(wallet.get_init_event_id());

  std::vector<SingleSigner> signers = {};
  for (auto& id : join_event_ids) {
    auto event = db.GetEvent(id);
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

  std::string descriptor = GetDescriptorForSigners(
      signers, m, DescriptorPath::TEMPLATE, a, w, 0, true);
  std::string first_address = CoreUtils::getInstance().DeriveAddresses(
      GetDescriptorForSigners(signers, m, DescriptorPath::EXTERNAL_ALL, a, w,
                              is_escrow ? -1 : 0, true),
      is_escrow ? -1 : 0);

  json content = {{"msgtype", "io.nunchuk.wallet.create"},
                  {"body",
                   {{"descriptor", descriptor},
                    {"path_restriction", "/0/*,/1/*"},
                    {"first_address", first_address},
                    {"io.nunchuk.relates_to",
                     {{"init_event_id", wallet.get_init_event_id()},
                      {"join_event_ids", join_event_ids}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.wallet", content.dump());
  wallet.set_finalize_event_id(event.get_event_id());
  db.SetWallet(event.get_room_id(), wallet);
  return event;
}

void NunchukMatrixImpl::SendWalletReady(const std::string& room_id) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetWallet(room_id);
  if (!wallet.get_ready_event_id().empty()) return;  // Ready event sent

  auto join_event_ids = wallet.get_join_event_ids();
  auto leave_event_ids = wallet.get_leave_event_ids();
  auto init_event = db.GetEvent(wallet.get_init_event_id());
  json wallet_config = json::parse(init_event.get_content())["body"];
  int n = wallet_config["n"];
  if (join_event_ids.size() - leave_event_ids.size() != n)
    return;  // Wallet not ready
  json content = {{"msgtype", "io.nunchuk.wallet.ready"},
                  {"body",
                   {{"io.nunchuk.relates_to",
                     {{"init_event_id", wallet.get_init_event_id()},
                      {"join_event_ids", join_event_ids}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.wallet", content.dump());
  wallet.set_ready_event_id(event.get_event_id());
  db.SetWallet(event.get_room_id(), wallet);
}

NunchukMatrixEvent NunchukMatrixImpl::InitTransaction(
    const std::unique_ptr<Nunchuk>& nu, const std::string& room_id,
    const std::map<std::string, Amount> outputs, const std::string& memo,
    const std::vector<UnspentOutput> inputs, Amount fee_rate,
    bool subtract_fee_from_amount) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetWallet(room_id);
  auto tx = nu->CreateTransaction(wallet.get_wallet_id(), outputs, memo, inputs,
                                  fee_rate, subtract_fee_from_amount);
  json content = {{"msgtype", "io.nunchuk.transaction.init"},
                  {"body",
                   {{"wallet_id", wallet.get_wallet_id()},
                    {"memo", tx.get_memo()},
                    {"psbt", tx.get_psbt()},
                    {"fee_rate", tx.get_fee_rate()},
                    {"subtract_fee_from_amount", tx.subtract_fee_from_amount()},
                    {"chain", ChainToStr(chain_)}}}};
  auto event = NewEvent(room_id, "io.nunchuk.transaction", content.dump());
  RoomTransaction rtx{};
  rtx.set_init_event_id(event.get_event_id());
  rtx.set_wallet_id(wallet.get_wallet_id());
  rtx.set_tx_id(tx.get_txid());
  db.SetTransaction(event.get_room_id(), event.get_event_id(), rtx);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::SignTransaction(
    const std::unique_ptr<Nunchuk>& nu, const std::string& init_event_id,
    const Device& device) {
  auto db = storage_.GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  auto rtx = db.GetTransaction(init_event_id);
  auto tx = nu->SignTransaction(rtx.get_wallet_id(), rtx.get_tx_id(), device);
  json content = {
      {"msgtype", "io.nunchuk.transaction.sign"},
      {"body",
       {{"psbt", tx.get_psbt()},
        {"master_fingerprint", device.get_master_fingerprint()},
        {"io.nunchuk.relates_to", {{"init_event_id", init_event_id}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.transaction", content.dump());
  rtx.add_sign_event_id(event.get_event_id());
  db.SetTransaction(event.get_room_id(), init_event_id, rtx);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::RejectTransaction(
    const std::string& init_event_id, const std::string& reason) {
  auto db = storage_.GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  json content = {
      {"msgtype", "io.nunchuk.transaction.reject"},
      {"body",
       {{"reason", reason},
        {"io.nunchuk.relates_to", {{"init_event_id", init_event_id}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.transaction", content.dump());
  auto rtx = db.GetTransaction(init_event_id);
  rtx.add_reject_event_id(event.get_event_id());
  db.SetTransaction(event.get_room_id(), init_event_id, rtx);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::CancelTransaction(
    const std::string& init_event_id, const std::string& reason) {
  auto db = storage_.GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  json content = {
      {"msgtype", "io.nunchuk.transaction.cancel"},
      {"body",
       {{"reason", reason},
        {"io.nunchuk.relates_to", {{"init_event_id", init_event_id}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.transaction", content.dump());
  auto rtx = db.GetTransaction(init_event_id);
  rtx.set_cancel_event_id(event.get_event_id());
  db.SetTransaction(event.get_room_id(), init_event_id, rtx);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::BroadcastTransaction(
    const std::unique_ptr<Nunchuk>& nu, const std::string& init_event_id) {
  auto db = storage_.GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  auto rtx = db.GetTransaction(init_event_id);
  auto tx = nu->BroadcastTransaction(rtx.get_wallet_id(), rtx.get_tx_id());
  json content = {{"msgtype", "io.nunchuk.transaction.broadcast"},
                  {"body",
                   {{"tx_id", tx.get_txid()},
                    {"io.nunchuk.relates_to",
                     {{"init_event_id", rtx.get_init_event_id()},
                      {"sign_event_ids", rtx.get_sign_event_ids()}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.transaction", content.dump());
  rtx.set_tx_id(tx.get_txid());
  rtx.set_broadcast_event_id(event.get_event_id());
  db.SetTransaction(event.get_room_id(), init_event_id, rtx);
  return event;
}

void NunchukMatrixImpl::SendTransactionReady(const std::string& room_id,
                                             const std::string& init_event_id) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetWallet(room_id);
  auto init_event = db.GetEvent(wallet.get_init_event_id());
  json wallet_config = json::parse(init_event.get_content())["body"];
  int n = wallet_config["n"];

  auto rtx = db.GetTransaction(init_event_id);
  if (rtx.get_sign_event_ids().size() != n) return;  // Transaction not ready
  json content = {{"msgtype", "io.nunchuk.transaction.ready"},
                  {"body",
                   {{"io.nunchuk.relates_to",
                     {{"init_event_id", wallet.get_init_event_id()},
                      {"sign_event_ids", rtx.get_sign_event_ids()}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.transaction", content.dump());
  rtx.set_ready_event_id(event.get_event_id());
  db.SetTransaction(event.get_room_id(), init_event_id, rtx);
}

std::vector<RoomWallet> NunchukMatrixImpl::GetAllRoomWallets() {
  auto db = storage_.GetRoomDb(chain_);
  return db.GetWallets();
}

RoomWallet NunchukMatrixImpl::GetRoomWallet(const std::string& room_id) {
  auto db = storage_.GetRoomDb(chain_);
  return db.GetWallet(room_id);
}

std::vector<RoomTransaction> NunchukMatrixImpl::GetPendingTransactions(
    const std::string& room_id) {
  auto db = storage_.GetRoomDb(chain_);
  return db.GetPendingTransactions(room_id);
}

NunchukMatrixEvent NunchukMatrixImpl::GetEvent(const std::string& event_id) {
  auto db = storage_.GetRoomDb(chain_);
  return db.GetEvent(event_id);
}

void NunchukMatrixImpl::ConsumeEvent(const std::unique_ptr<Nunchuk>& nu,
                                     const NunchukMatrixEvent& event) {
  if (event.get_type() != "io.nunchuk.wallet" &&
      event.get_type() != "io.nunchuk.transaction")
    return;
  if (event.get_event_id().empty()) return;

  auto db = storage_.GetRoomDb(chain_);
  db.SetEvent(event.get_event_id(), event);
  json content = json::parse(event.get_content());
  std::string msgtype = content["msgtype"];
  json body = content["body"];
  if (msgtype == "io.nunchuk.wallet.init") {
    RoomWallet wallet{};
    wallet.set_init_event_id(event.get_event_id());
    db.SetWallet(event.get_room_id(), wallet);
  } else if (msgtype == "io.nunchuk.wallet.join") {
    auto wallet = db.GetWallet(event.get_room_id());
    wallet.add_join_event_id(event.get_event_id());
    db.SetWallet(event.get_room_id(), wallet);
    SendWalletReady(event.get_room_id());
  } else if (msgtype == "io.nunchuk.wallet.leave") {
    auto wallet = db.GetWallet(event.get_room_id());
    wallet.add_leave_event_id(event.get_event_id());
    db.SetWallet(event.get_room_id(), wallet);
  } else if (msgtype == "io.nunchuk.wallet.cancel") {
    auto wallet = db.GetWallet(event.get_room_id());
    wallet.set_cancel_event_id(event.get_event_id());
    db.SetWallet(event.get_room_id(), wallet);
  } else if (msgtype == "io.nunchuk.wallet.create") {
    auto wallet = db.GetWallet(event.get_room_id());
    wallet.set_finalize_event_id(event.get_event_id());

    if (event.get_sender() != sender_) {
      auto init_event = db.GetEvent(wallet.get_init_event_id());
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
    db.SetWallet(event.get_room_id(), wallet);
  } else if (msgtype == "io.nunchuk.transaction.init") {
    RoomTransaction tx{};
    tx.set_init_event_id(event.get_event_id());
    tx.set_wallet_id(body["wallet_id"]);
    auto ntx = nu->ImportPsbt(tx.get_wallet_id(), body["psbt"]);
    tx.set_tx_id(ntx.get_txid());
    db.SetTransaction(event.get_room_id(), event.get_event_id(), tx);
  } else if (msgtype == "io.nunchuk.transaction.sign") {
    std::string init_event_id =
        content["io.nunchuk.relates_to"]["init_event_id"];
    auto tx = db.GetTransaction(init_event_id);
    tx.add_sign_event_id(event.get_event_id());
    nu->ImportPsbt(tx.get_wallet_id(), body["psbt"]);
    db.SetTransaction(event.get_room_id(), init_event_id, tx);
    SendTransactionReady(event.get_room_id(), init_event_id);
  } else if (msgtype == "io.nunchuk.transaction.reject") {
    std::string init_event_id =
        content["io.nunchuk.relates_to"]["init_event_id"];
    auto tx = db.GetTransaction(init_event_id);
    tx.add_reject_event_id(event.get_event_id());
    db.SetTransaction(event.get_room_id(), init_event_id, tx);
  } else if (msgtype == "io.nunchuk.transaction.cancel") {
    std::string init_event_id =
        content["io.nunchuk.relates_to"]["init_event_id"];
    auto tx = db.GetTransaction(init_event_id);
    tx.set_cancel_event_id(event.get_event_id());
    db.SetTransaction(event.get_room_id(), init_event_id, tx);
  } else if (msgtype == "io.nunchuk.transaction.broadcast") {
    std::string init_event_id =
        content["io.nunchuk.relates_to"]["init_event_id"];
    auto tx = db.GetTransaction(init_event_id);
    tx.set_broadcast_event_id(event.get_event_id());
    db.SetTransaction(event.get_room_id(), init_event_id, tx);
  }
}

std::unique_ptr<NunchukMatrix> MakeNunchukMatrixForAccount(
    const AppSettings& appsettings, const std::string& passphrase,
    const std::string& account, SendEventFunc SendEventFunc) {
  return std::unique_ptr<NunchukMatrixImpl>(
      new NunchukMatrixImpl(appsettings, passphrase, account, SendEventFunc));
}

}  // namespace nunchuk