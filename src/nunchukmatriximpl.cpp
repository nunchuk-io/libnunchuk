// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nunchukmatriximpl.h>
#include <iostream>
#include <sstream>
#include <set>
#include <utils/json.hpp>
#include <utils/attachment.hpp>

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
      << (value.get_xpub().empty() ? value.get_public_key() : value.get_xpub());
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

  if (!event.get_event_id().empty()) {
    auto db = storage_.GetRoomDb(chain_);
    db.SetEvent(event);
  }
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
  if (db.HasActiveWallet(room_id)) {
    throw NunchukMatrixException(NunchukMatrixException::SHARED_WALLET_EXISTS,
                                 "shared wallet exists");
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
  if (event.get_event_id().empty()) return event;
  RoomWallet wallet{};
  wallet.set_room_id(room_id);
  wallet.set_init_event_id(event.get_event_id());
  db.SetWallet(wallet);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::JoinWallet(const std::string& room_id,
                                                 const SingleSigner& signer) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
  json content = {{"msgtype", "io.nunchuk.wallet.join"},
                  {"body",
                   {{"key", SignerToStr(signer)},
                    {"io.nunchuk.relates_to",
                     {{"init_event_id", wallet.get_init_event_id()}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.wallet", content.dump());
  if (event.get_event_id().empty()) return event;
  wallet.add_join_event_id(event.get_event_id());
  db.SetWallet(wallet);
  SendWalletReady(room_id);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::LeaveWallet(
    const std::string& room_id, const std::string& join_event_id,
    const std::string& reason) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
  json content = {{"msgtype", "io.nunchuk.wallet.leave"},
                  {"body",
                   {{"reason", reason},
                    {"io.nunchuk.relates_to",
                     {{"init_event_id", wallet.get_init_event_id()},
                      {"join_event_id", join_event_id}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.wallet", content.dump());
  if (event.get_event_id().empty()) return event;
  wallet.add_leave_event_id(event.get_event_id());
  db.SetWallet(wallet);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::CancelWallet(const std::string& room_id,
                                                   const std::string& reason) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
  json content = {{"msgtype", "io.nunchuk.wallet.cancel"},
                  {"body",
                   {{"reason", reason},
                    {"io.nunchuk.relates_to",
                     {{"init_event_id", wallet.get_init_event_id()}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.wallet", content.dump());
  if (event.get_event_id().empty()) return event;
  wallet.set_cancel_event_id(event.get_event_id());
  db.SetWallet(wallet);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::DeleteWallet(
    const std::unique_ptr<Nunchuk>& nu, const std::string& room_id) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
  nu->DeleteWallet(wallet.get_wallet_id());
  json content = {{"msgtype", "io.nunchuk.wallet.delete"},
                  {"body",
                   {{"wallet_id", wallet.get_wallet_id()},
                    {"io.nunchuk.relates_to",
                     {{"init_event_id", wallet.get_init_event_id()}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.wallet", content.dump());
  if (event.get_event_id().empty()) return event;
  wallet.set_delete_event_id(event.get_event_id());
  db.SetWallet(wallet);
  return event;
}

NunchukMatrixEvent NunchukMatrixImpl::CreateWallet(
    const std::unique_ptr<Nunchuk>& nu, const std::string& room_id) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);

  std::set<std::string> leave_ids;
  for (auto&& leave_event_id : wallet.get_leave_event_ids()) {
    auto leave_event = db.GetEvent(leave_event_id);
    auto leave_body = json::parse(leave_event.get_content())["body"];
    std::string join_id = leave_body["io.nunchuk.relates_to"]["join_event_id"];
    leave_ids.insert(join_id);
  }

  std::vector<std::string> join_event_ids;
  std::vector<SingleSigner> signers = {};
  for (auto&& join_event_id : wallet.get_join_event_ids()) {
    if (leave_ids.count(join_event_id)) continue;
    auto join_event = db.GetEvent(join_event_id);
    auto join_body = json::parse(join_event.get_content())["body"];
    join_event_ids.push_back(join_event_id);
    std::string key = join_body["key"];
    signers.push_back(ParseSignerString(key));
  }

  auto init_event = db.GetEvent(wallet.get_init_event_id());
  json init_body = json::parse(init_event.get_content())["body"];
  std::string name = init_body["name"];
  int m = init_body["m"];
  int n = init_body["n"];
  std::string description = init_body["description"];
  bool is_escrow = init_body["is_escrow"];
  auto a = AddressTypeFromStr(init_body["address_type"]);
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
                      {"init_event_body", init_body},
                      {"join_event_ids", join_event_ids}}}}}};
  auto event = NewEvent(room_id, "io.nunchuk.wallet", content.dump());
  wallet.set_finalize_event_id(event.get_event_id());
  db.SetWallet(wallet);
  return event;
}

void NunchukMatrixImpl::SendWalletReady(const std::string& room_id) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
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
  if (event.get_event_id().empty()) return;
  wallet.set_ready_event_id(event.get_event_id());
  db.SetWallet(wallet);
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
  if (event.get_event_id().empty()) return event;
  RoomTransaction rtx{};
  rtx.set_room_id(room_id);
  rtx.set_init_event_id(event.get_event_id());
  rtx.set_wallet_id(wallet.get_wallet_id());
  rtx.set_tx_id(tx.get_txid());
  db.SetTransaction(rtx);
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
  if (event.get_event_id().empty()) return event;
  rtx.add_sign_event_id(event.get_event_id());
  db.SetTransaction(rtx);
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
  if (event.get_event_id().empty()) return event;
  auto rtx = db.GetTransaction(init_event_id);
  rtx.add_reject_event_id(event.get_event_id());
  db.SetTransaction(rtx);
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
  if (event.get_event_id().empty()) return event;
  auto rtx = db.GetTransaction(init_event_id);
  rtx.set_cancel_event_id(event.get_event_id());
  db.SetTransaction(rtx);
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
  if (event.get_event_id().empty()) return event;
  rtx.set_tx_id(tx.get_txid());
  rtx.set_broadcast_event_id(event.get_event_id());
  db.SetTransaction(rtx);
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
  if (event.get_event_id().empty()) return;
  rtx.set_ready_event_id(event.get_event_id());
  db.SetTransaction(rtx);
}

NunchukMatrixEvent NunchukMatrixImpl::Backup(const std::unique_ptr<Nunchuk>& nu,
                                             const std::string& sync_room_id,
                                             const std::string& access_token) {
  auto db = storage_.GetRoomDb(chain_);
  std::string room_id = sync_room_id;
  if (room_id.empty()) {
    room_id = db.GetSyncRoomId();
  } else {
    db.SetSyncRoomId(room_id);
  }
  if (room_id.empty() || access_token.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "invalid room_id or access_token");
  }
  auto data = nu->ExportBackup();
  auto file = json::parse(EncryptAttachment(access_token, data));
  json content = {{"msgtype", "io.nunchuk.sync.file"}, {"file", file}};
  return NewEvent(room_id, "io.nunchuk.sync", content.dump());
}

std::vector<RoomWallet> NunchukMatrixImpl::GetAllRoomWallets() {
  auto db = storage_.GetRoomDb(chain_);
  return db.GetWallets();
}

RoomWallet NunchukMatrixImpl::GetRoomWallet(const std::string& room_id) {
  auto db = storage_.GetRoomDb(chain_);
  return db.GetActiveWallet(room_id);
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
  if (event.get_type().rfind("io.nunchuk", 0) != 0) return;
  if (event.get_event_id().empty()) return;

  auto db = storage_.GetRoomDb(chain_);
  if (db.HasEvent(event.get_event_id())) return;
  db.SetEvent(event);
  json content = json::parse(event.get_content());
  std::string msgtype = content["msgtype"];
  json body = content["body"];
  std::string init_event_id =
      content["io.nunchuk.relates_to"].empty()
          ? ""
          : content["io.nunchuk.relates_to"]["init_event_id"];
  if (msgtype == "io.nunchuk.wallet.init") {
    auto wallet = db.GetWallet(init_event_id);
    wallet.set_room_id(event.get_room_id());
    wallet.set_init_event_id(event.get_event_id());
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.join") {
    auto wallet = db.GetWallet(init_event_id);
    wallet.set_room_id(event.get_room_id());
    wallet.add_join_event_id(event.get_event_id());
    db.SetWallet(wallet);
    SendWalletReady(event.get_room_id());
  } else if (msgtype == "io.nunchuk.wallet.leave") {
    auto wallet = db.GetWallet(init_event_id);
    wallet.set_room_id(event.get_room_id());
    wallet.add_leave_event_id(event.get_event_id());
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.cancel") {
    auto wallet = db.GetWallet(init_event_id);
    wallet.set_room_id(event.get_room_id());
    wallet.set_cancel_event_id(event.get_event_id());
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.ready") {
    auto wallet = db.GetWallet(init_event_id);
    wallet.set_room_id(event.get_room_id());
    wallet.set_ready_event_id(event.get_event_id());
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.delete") {
    auto wallet = db.GetWallet(init_event_id);
    wallet.set_room_id(event.get_room_id());
    wallet.set_delete_event_id(event.get_event_id());
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.create") {
    auto wallet = db.GetWallet(init_event_id);
    wallet.set_room_id(event.get_room_id());
    wallet.set_finalize_event_id(event.get_event_id());
    if (wallet.get_wallet_id().empty() &&
        wallet.get_delete_event_id().empty()) {
      auto init_body = content["io.nunchuk.relates_to"]["init_event_body"];
      std::string name = init_body["name"];
      std::string description = init_body["description"];
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
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.transaction.init") {
    auto tx = db.GetTransaction(init_event_id);
    tx.set_room_id(event.get_room_id());
    tx.set_init_event_id(event.get_event_id());
    tx.set_wallet_id(body["wallet_id"]);
    auto ntx = nu->ImportPsbt(tx.get_wallet_id(), body["psbt"]);
    tx.set_tx_id(ntx.get_txid());
    db.SetTransaction(tx);
  } else if (msgtype == "io.nunchuk.transaction.sign") {
    auto tx = db.GetTransaction(init_event_id);
    tx.set_room_id(event.get_room_id());
    tx.add_sign_event_id(event.get_event_id());
    nu->ImportPsbt(tx.get_wallet_id(), body["psbt"]);
    db.SetTransaction(tx);
    SendTransactionReady(event.get_room_id(), init_event_id);
  } else if (msgtype == "io.nunchuk.transaction.reject") {
    auto tx = db.GetTransaction(init_event_id);
    tx.set_room_id(event.get_room_id());
    tx.add_reject_event_id(event.get_event_id());
    db.SetTransaction(tx);
  } else if (msgtype == "io.nunchuk.transaction.cancel") {
    auto tx = db.GetTransaction(init_event_id);
    tx.set_room_id(event.get_room_id());
    tx.set_cancel_event_id(event.get_event_id());
    db.SetTransaction(tx);
  } else if (msgtype == "io.nunchuk.transaction.ready") {
    auto tx = db.GetTransaction(init_event_id);
    tx.set_room_id(event.get_room_id());
    tx.set_ready_event_id(event.get_event_id());
    db.SetTransaction(tx);
  } else if (msgtype == "io.nunchuk.transaction.broadcast") {
    auto tx = db.GetTransaction(init_event_id);
    tx.set_room_id(event.get_room_id());
    tx.set_broadcast_event_id(event.get_event_id());
    db.SetTransaction(tx);
  } else if (msgtype == "io.nunchuk.sync.file") {
    auto data = content["file"];
    db.SetSyncRoomId(event.get_room_id());
    nu->SyncWithBackup(data.dump());
  }
}

std::unique_ptr<NunchukMatrix> MakeNunchukMatrixForAccount(
    const AppSettings& appsettings, const std::string& passphrase,
    const std::string& account, SendEventFunc SendEventFunc) {
  return std::unique_ptr<NunchukMatrixImpl>(
      new NunchukMatrixImpl(appsettings, passphrase, account, SendEventFunc));
}

}  // namespace nunchuk