// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nunchukmatriximpl.h>
#include <iostream>
#include <sstream>
#include <set>
#include <utils/json.hpp>
#include <utils/attachment.hpp>
#include <boost/thread/locks.hpp>
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

std::string SignerTypeToStr(SignerType value) {
  if (value == SignerType::SOFTWARE) return "SOFTWARE";
  if (value == SignerType::FOREIGN_SOFTWARE) return "FOREIGN_SOFTWARE";
  if (value == SignerType::AIRGAP) return "AIRGAP";
  return "HARDWARE";
}

SignerType SignerTypeFromStr(const std::string& value) {
  if (value == "SOFTWARE") return SignerType::SOFTWARE;
  if (value == "FOREIGN_SOFTWARE") return SignerType::FOREIGN_SOFTWARE;
  if (value == "AIRGAP") return SignerType::AIRGAP;
  if (value == "HARDWARE") return SignerType::HARDWARE;
  throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                         "invalid signer type");
}

std::string SignerToStr(const SingleSigner& value) {
  std::stringstream key;
  key << "[" << value.get_master_fingerprint()
      << FormalizePath(value.get_derivation_path()) << "]"
      << (value.get_xpub().empty() ? value.get_public_key() : value.get_xpub());
  return key.str();
}

json GetInitBody(const json& body) {
  return body["io.nunchuk.relates_to"]["init_event"]["content"]["body"];
}

json EventToJson(const NunchukMatrixEvent& event) {
  return {
      {"room_id", event.get_room_id()},
      {"type", event.get_type()},
      {"content", json::parse(event.get_content())},
      {"sender", event.get_sender()},
      {"ts", event.get_ts()},
      {"event_id", event.get_event_id()},
  };
}

NunchukMatrixEvent JsonToEvent(const json& j) {
  NunchukMatrixEvent event{};
  event.set_room_id(j["room_id"]);
  event.set_type(j["type"]);
  event.set_content(j["content"].dump());
  event.set_sender(j["sender"]);
  event.set_ts(j["ts"]);
  event.set_event_id(j["event_id"]);
  return event;
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
  sendfunc_(room_id, event_type, content);
  return event;
}

NunchukMatrixImpl::NunchukMatrixImpl(const AppSettings& appsettings,
                                     const std::string& access_token,
                                     const std::string& account,
                                     SendEventFunc sendfunc)
    : storage_(appsettings.get_storage_path(), "", account),
      access_token_(access_token),
      sender_(account),
      chain_(appsettings.get_chain()),
      sendfunc_(sendfunc) {}
NunchukMatrix::~NunchukMatrix() = default;
NunchukMatrixImpl::~NunchukMatrixImpl() {}

NunchukMatrixEvent NunchukMatrixImpl::InitWallet(
    const std::string& room_id, const std::string& name, int m, int n,
    AddressType address_type, bool is_escrow, const std::string& description) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  if (db.HasActiveWallet(room_id)) {
    throw NunchukMatrixException(NunchukMatrixException::SHARED_WALLET_EXISTS,
                                 "shared wallet exists");
  }
  json content = {{"msgtype", "io.nunchuk.wallet.init"},
                  {"v", NUNCHUK_EVENT_VER},
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
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);

  auto init_event = db.GetEvent(wallet.get_init_event_id());
  json init_body = json::parse(init_event.get_content())["body"];
  auto chain = ChainFromStr(init_body["chain"]);
  if (chain_ != chain) {
    throw NunchukMatrixException(NunchukMatrixException::MISMATCHED_NETWORKS,
                                 "mismatched networks");
  }
  bool is_escrow = init_body["is_escrow"];
  if (is_escrow && !signer.get_xpub().empty()) {
    throw NunchukMatrixException(NunchukMatrixException::MISMATCHED_KEY_TYPES,
                                 "mismatched key types");
  }

  std::set<std::string> leave_ids;
  for (auto&& leave_event_id : wallet.get_leave_event_ids()) {
    auto leave_event = db.GetEvent(leave_event_id);
    auto leave_body = json::parse(leave_event.get_content())["body"];
    std::string join_id = leave_body["io.nunchuk.relates_to"]["join_event_id"];
    leave_ids.insert(join_id);
  }

  std::string key = SignerToStr(signer);
  for (auto&& join_event_id : wallet.get_join_event_ids()) {
    if (leave_ids.count(join_event_id)) continue;
    auto join_event = db.GetEvent(join_event_id);
    auto join_body = json::parse(join_event.get_content())["body"];
    std::string join_key = join_body["key"];
    if (key == join_key) {
      throw NunchukMatrixException(NunchukMatrixException::DUPPLICATE_KEYS,
                                   "dupplicate keys");
    }
  }

  json content = {
      {"msgtype", "io.nunchuk.wallet.join"},
      {"v", NUNCHUK_EVENT_VER},
      {"body",
       {{"key", key},
        {"type", SignerTypeToStr(signer.get_type())},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::LeaveWallet(
    const std::string& room_id, const std::string& join_event_id,
    const std::string& reason) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
  auto init_event = db.GetEvent(wallet.get_init_event_id());
  json content = {{"msgtype", "io.nunchuk.wallet.leave"},
                  {"v", NUNCHUK_EVENT_VER},
                  {"body",
                   {{"reason", reason},
                    {"io.nunchuk.relates_to",
                     {{"init_event", EventToJson(init_event)},
                      {"join_event_id", join_event_id}}}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::CancelWallet(const std::string& room_id,
                                                   const std::string& reason) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
  auto init_event = db.GetEvent(wallet.get_init_event_id());
  json content = {
      {"msgtype", "io.nunchuk.wallet.cancel"},
      {"v", NUNCHUK_EVENT_VER},
      {"body",
       {{"reason", reason},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::DeleteWallet(
    const std::unique_ptr<Nunchuk>& nu, const std::string& room_id) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
  nu->DeleteWallet(wallet.get_wallet_id());
  auto init_event = db.GetEvent(wallet.get_init_event_id());
  json content = {
      {"msgtype", "io.nunchuk.wallet.delete"},
      {"v", NUNCHUK_EVENT_VER},
      {"body",
       {{"wallet_id", wallet.get_wallet_id()},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.wallet", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::CreateWallet(
    const std::unique_ptr<Nunchuk>& nu, const std::string& room_id) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
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

  std::string external_desc =
      GetDescriptorForSigners(signers, m, DescriptorPath::EXTERNAL_ALL, a, w);
  auto wallet_id = GetDescriptorChecksum(external_desc);
  wallet.set_wallet_id(wallet_id);
  wallet2room_[wallet_id] = room_id;
  nu->CreateWallet(name, m, n, signers, a, is_escrow, description);

  std::string descriptor = GetDescriptorForSigners(
      signers, m, DescriptorPath::TEMPLATE, a, w, 0, true);
  std::string first_address = CoreUtils::getInstance().DeriveAddresses(
      GetDescriptorForSigners(signers, m, DescriptorPath::EXTERNAL_ALL, a, w,
                              is_escrow ? -1 : 0, true),
      is_escrow ? -1 : 0);

  json content = {{"msgtype", "io.nunchuk.wallet.create"},
                  {"v", NUNCHUK_EVENT_VER},
                  {"body",
                   {{"descriptor", descriptor},
                    {"path_restriction", "/0/*,/1/*"},
                    {"first_address", first_address},
                    {"io.nunchuk.relates_to",
                     {{"init_event", EventToJson(init_event)},
                      {"join_event_ids", join_event_ids}}}}}};
  db.SetWallet(wallet);
  return NewEvent(room_id, "io.nunchuk.wallet", content.dump());
}

void NunchukMatrixImpl::SendWalletReady(const std::string& room_id) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id, false);
  if (!wallet.get_ready_event_id().empty()) return;  // Ready event sent

  auto join_event_ids = db.GetJoinIds(wallet);
  auto init_event = db.GetEvent(wallet.get_init_event_id());
  json wallet_config = json::parse(init_event.get_content())["body"];
  int n = wallet_config["n"];
  if (join_event_ids.size() != n) return;  // Wallet not ready
  json content = {{"msgtype", "io.nunchuk.wallet.ready"},
                  {"v", NUNCHUK_EVENT_VER},
                  {"body",
                   {{"io.nunchuk.relates_to",
                     {{"init_event", EventToJson(init_event)},
                      {"join_event_ids", join_event_ids}}}}}};
  NewEvent(room_id, "io.nunchuk.wallet", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::InitTransaction(
    const std::unique_ptr<Nunchuk>& nu, const std::string& room_id,
    const std::map<std::string, Amount> outputs, const std::string& memo,
    const std::vector<UnspentOutput> inputs, Amount fee_rate,
    bool subtract_fee_from_amount) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
  auto tx = nu->CreateTransaction(wallet.get_wallet_id(), outputs, memo, inputs,
                                  fee_rate, subtract_fee_from_amount);
  json content = {{"msgtype", "io.nunchuk.transaction.init"},
                  {"v", NUNCHUK_EVENT_VER},
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
    const std::unique_ptr<Nunchuk>& nu, const std::string& init_event_id,
    const Device& device) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  auto rtx = db.GetTransaction(init_event_id);
  auto tx = nu->SignTransaction(rtx.get_wallet_id(), rtx.get_tx_id(), device);
  json content = {
      {"msgtype", "io.nunchuk.transaction.sign"},
      {"v", NUNCHUK_EVENT_VER},
      {"body",
       {{"psbt", tx.get_psbt()},
        {"master_fingerprint", device.get_master_fingerprint()},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::RejectTransaction(
    const std::string& init_event_id, const std::string& reason) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  json content = {
      {"msgtype", "io.nunchuk.transaction.reject"},
      {"v", NUNCHUK_EVENT_VER},
      {"body",
       {{"reason", reason},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::CancelTransaction(
    const std::string& init_event_id, const std::string& reason) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  json content = {
      {"msgtype", "io.nunchuk.transaction.cancel"},
      {"v", NUNCHUK_EVENT_VER},
      {"body",
       {{"reason", reason},
        {"io.nunchuk.relates_to", {{"init_event", EventToJson(init_event)}}}}}};
  return NewEvent(room_id, "io.nunchuk.transaction", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::BroadcastTransaction(
    const std::unique_ptr<Nunchuk>& nu, const std::string& init_event_id) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  auto init_event = db.GetEvent(init_event_id);
  std::string room_id = init_event.get_room_id();
  auto rtx = db.GetTransaction(init_event_id);
  auto tx = nu->BroadcastTransaction(rtx.get_wallet_id(), rtx.get_tx_id());
  json content = {{"msgtype", "io.nunchuk.transaction.broadcast"},
                  {"v", NUNCHUK_EVENT_VER},
                  {"body",
                   {{"tx_id", tx.get_txid()},
                    {"io.nunchuk.relates_to",
                     {{"init_event", EventToJson(init_event)},
                      {"sign_event_ids", rtx.get_sign_event_ids()}}}}}};
  rtx.set_tx_id(tx.get_txid());
  db.SetTransaction(rtx);
  return NewEvent(room_id, "io.nunchuk.transaction", content.dump());
}

void NunchukMatrixImpl::SendTransactionReady(const std::string& room_id,
                                             const std::string& init_event_id) {
  auto db = storage_.GetRoomDb(chain_);
  auto wallet = db.GetActiveWallet(room_id);
  auto wallet_init_event = db.GetEvent(wallet.get_init_event_id());
  json wallet_config = json::parse(wallet_init_event.get_content())["body"];
  int m = wallet_config["m"];

  auto rtx = db.GetTransaction(init_event_id);
  if (rtx.get_sign_event_ids().size() < m) return;  // Transaction not ready
  auto init_event = db.GetEvent(init_event_id);
  json content = {{"msgtype", "io.nunchuk.transaction.ready"},
                  {"v", NUNCHUK_EVENT_VER},
                  {"body",
                   {{"io.nunchuk.relates_to",
                     {{"init_event", EventToJson(init_event)},
                      {"sign_event_ids", rtx.get_sign_event_ids()}}}}}};
  NewEvent(room_id, "io.nunchuk.transaction", content.dump());
}

std::string NunchukMatrixImpl::GetTransactionId(const std::string& event_id) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);

  auto event = db.GetEvent(event_id);
  auto encrypted = json::parse(event.get_content())["body"]["encrypted_tx_id"];

  auto wallet = db.GetActiveWallet(event.get_room_id());
  if (wallet.get_finalize_event_id().empty()) {
    throw NunchukMatrixException(
        NunchukMatrixException::SHARED_WALLET_NOT_FOUND,
        "shared wallet not finalized");
  }
  auto wallet_finalize_event = db.GetEvent(wallet.get_finalize_event_id());
  std::string desc =
      json::parse(wallet_finalize_event.get_content())["body"]["descriptor"];

  return DecryptTxId(desc, encrypted.dump());
}

void NunchukMatrixImpl::SendReceiveTransaction(const std::string& room_id,
                                               const std::string& tx_id) {
  // boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  if (db.HasTransactionNotify(tx_id)) return;
  auto wallet = db.GetActiveWallet(room_id);
  if (wallet.get_finalize_event_id().empty()) return;
  auto wallet_finalize_event = db.GetEvent(wallet.get_finalize_event_id());
  std::string desc =
      json::parse(wallet_finalize_event.get_content())["body"]["descriptor"];
  std::string encrypted_tx_id = EncryptTxId(desc, tx_id);
  json content = {
      {"msgtype", "io.nunchuk.transaction.receive"},
      {"v", NUNCHUK_EVENT_VER},
      {"body", {{"encrypted_tx_id", json::parse(encrypted_tx_id)}}}};
  NewEvent(room_id, "io.nunchuk.transaction", content.dump());
}

void NunchukMatrixImpl::EnableGenerateReceiveEvent(
    const std::unique_ptr<Nunchuk>& nu) {
  auto wallets = GetAllRoomWallets();
  for (auto&& wallet : wallets) {
    if (!wallet.get_wallet_id().empty()) {
      wallet2room_[wallet.get_wallet_id()] = wallet.get_room_id();
    }
  }
  nu->AddTransactionListener(
      [&](std::string tx_id, TransactionStatus status, std::string wallet_id) {
        if (status != TransactionStatus::PENDING_CONFIRMATION &&
            status != TransactionStatus::CONFIRMED)
          return;
        if (wallet2room_.count(wallet_id) == 0) return;
        if (!nu->GetTransaction(wallet_id, tx_id).is_receive()) return;
        SendReceiveTransaction(wallet2room_.at(wallet_id), tx_id);
      });
}

NunchukMatrixEvent NunchukMatrixImpl::Backup(const std::unique_ptr<Nunchuk>& nu,
                                             const std::string& sync_room_id,
                                             const std::string& access_token) {
  if (!sync_room_id.empty()) sync_room_id_ = sync_room_id;
  if (!access_token.empty()) access_token_ = access_token;
  if (sync_room_id_.empty() || access_token_.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "invalid room_id or access_token");
  }
  auto data = nu->ExportBackup();
  auto file = json::parse(EncryptAttachment(
      [&](const std::string&, const std::string&, const char* body,
          size_t length) {
        auto upload = UploadAttachment(access_token_, body, length);
        std::string url = json::parse(upload)["content_uri"];
        return url;
      },
      data));
  json content = {{"msgtype", "io.nunchuk.sync.file"},
                  {"v", NUNCHUK_EVENT_VER},
                  {"file", file}};
  return NewEvent(sync_room_id_, "io.nunchuk.sync", content.dump());
}

NunchukMatrixEvent NunchukMatrixImpl::Backup(const std::unique_ptr<Nunchuk>& nu,
                                             UploadFileFunc uploadfunction) {
  auto data = nu->ExportBackup();
  auto file = json::parse(EncryptAttachment(uploadfunction, data));
  json content = {{"msgtype", "io.nunchuk.sync.file"},
                  {"v", NUNCHUK_EVENT_VER},
                  {"file", file}};
  return NewEvent(sync_room_id_, "io.nunchuk.sync", content.dump());
}

void NunchukMatrixImpl::EnableAutoBackup(const std::unique_ptr<Nunchuk>& nu,
                                         const std::string& sync_room_id,
                                         const std::string& access_token) {
  sync_room_id_ = sync_room_id;
  access_token_ = access_token;
  if (sync_room_id_.empty() || access_token_.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "invalid room_id or access_token");
  }
  nu->AddStorageUpdateListener([&]() { Backup(nu); });
}

void NunchukMatrixImpl::EnableAutoBackup(const std::unique_ptr<Nunchuk>& nu,
                                         const std::string& sync_room_id,
                                         UploadFileFunc uploadfunction) {
  sync_room_id_ = sync_room_id;
  nu->AddStorageUpdateListener([&]() { Backup(nu, uploadfunction); });
}

std::vector<RoomWallet> NunchukMatrixImpl::GetAllRoomWallets() {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  return db.GetWallets();
}

RoomWallet NunchukMatrixImpl::GetRoomWallet(const std::string& room_id) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  return db.GetActiveWallet(room_id);
}

std::vector<RoomTransaction> NunchukMatrixImpl::GetPendingTransactions(
    const std::string& room_id) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  return db.GetPendingTransactions(room_id);
}

RoomTransaction NunchukMatrixImpl::GetRoomTransaction(
    const std::string& init_event_id) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  return db.GetTransaction(init_event_id);
}

NunchukMatrixEvent NunchukMatrixImpl::GetEvent(const std::string& event_id) {
  boost::shared_lock<boost::shared_mutex> lock(access_);
  auto db = storage_.GetRoomDb(chain_);
  return db.GetEvent(event_id);
}

void NunchukMatrixImpl::ConsumeEvent(const std::unique_ptr<Nunchuk>& nu,
                                     const NunchukMatrixEvent& event) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  if (event.get_type().rfind("io.nunchuk.sync", 0) == 0) return;
  if (event.get_type().rfind("io.nunchuk", 0) != 0) return;
  if (event.get_event_id().empty()) return;
  if (event.get_event_id().rfind("$local", 0) == 0) return;

  auto db = storage_.GetRoomDb(chain_);
  if (db.HasEvent(event.get_event_id())) return;
  json content = json::parse(event.get_content());
  if (content["v"] == nullptr) return;
  std::string msgtype = content["msgtype"];
  json body = content["body"];
  std::string init_event_id = "";
  if (body["io.nunchuk.relates_to"] != nullptr) {
    auto init_event = JsonToEvent(body["io.nunchuk.relates_to"]["init_event"]);
    if (!db.HasEvent(init_event.get_event_id())) db.SetEvent(init_event);
    init_event_id = init_event.get_event_id();
  }

  if (msgtype == "io.nunchuk.wallet.init") {
    auto wallet = db.GetWallet(event.get_event_id(), false);
    wallet.set_room_id(event.get_room_id());
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.join") {
    auto wallet = db.GetWallet(init_event_id, false);
    wallet.set_room_id(event.get_room_id());
    wallet.add_join_event_id(event.get_event_id());
    db.SetWallet(wallet);
    db.SetEvent(event);
    SendWalletReady(event.get_room_id());
  } else if (msgtype == "io.nunchuk.wallet.leave") {
    auto wallet = db.GetWallet(init_event_id, false);
    wallet.set_room_id(event.get_room_id());
    wallet.add_leave_event_id(event.get_event_id());
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.cancel") {
    auto wallet = db.GetWallet(init_event_id, false);
    wallet.set_room_id(event.get_room_id());
    wallet.set_cancel_event_id(event.get_event_id());
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.ready") {
    auto wallet = db.GetWallet(init_event_id, false);
    wallet.set_room_id(event.get_room_id());
    wallet.set_ready_event_id(event.get_event_id());
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.delete") {
    auto wallet = db.GetWallet(init_event_id, false);
    wallet.set_room_id(event.get_room_id());
    wallet.set_delete_event_id(event.get_event_id());
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.wallet.create") {
    auto wallet = db.GetWallet(init_event_id, false);
    wallet.set_room_id(event.get_room_id());
    wallet.set_finalize_event_id(event.get_event_id());
    if (wallet.get_wallet_id().empty() &&
        wallet.get_delete_event_id().empty()) {
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

      auto init_body = GetInitBody(body);
      std::string name = init_body["name"];
      std::string d = init_body["description"];

      std::string external_desc = GetDescriptorForSigners(
          signers, m, DescriptorPath::EXTERNAL_ALL, a, w);
      auto wallet_id = GetDescriptorChecksum(external_desc);
      wallet.set_wallet_id(wallet_id);
      wallet2room_[wallet_id] = event.get_room_id();

      try {
        nu->CreateWallet(name, m, n, signers, a, w == WalletType::ESCROW, d);
      } catch (...) {
        // Most likely the wallet existed
      }
    }
    db.SetWallet(wallet);
  } else if (msgtype == "io.nunchuk.transaction.receive") {
    auto wallet = db.GetActiveWallet(event.get_room_id());
    if (!wallet.get_finalize_event_id().empty()) {
      auto encrypted = body["encrypted_tx_id"];
      auto wallet_finalize_event = db.GetEvent(wallet.get_finalize_event_id());
      std::string desc = json::parse(
          wallet_finalize_event.get_content())["body"]["descriptor"];
      db.SetTransactionNotify(DecryptTxId(desc, encrypted.dump()),
                              event.get_event_id());
    }
  } else if (msgtype.rfind("io.nunchuk.transaction", 0) == 0) {
    json init_body;
    if (msgtype == "io.nunchuk.transaction.init") {
      init_event_id = event.get_event_id();
      init_body = body;
    } else {
      init_body = GetInitBody(body);
    }

    auto tx = db.GetTransaction(init_event_id);
    tx.set_room_id(event.get_room_id());
    tx.set_wallet_id(init_body["wallet_id"]);
    if (tx.get_broadcast_event_id().empty()) {
      try {
        auto ntx = nu->ImportPsbt(tx.get_wallet_id(), init_body["psbt"]);
        tx.set_tx_id(ntx.get_txid());
      } catch (...) {
      }
    }

    if (msgtype == "io.nunchuk.transaction.sign") {
      tx.add_sign_event_id(event.get_event_id());
      if (tx.get_broadcast_event_id().empty()) {
        nu->ImportPsbt(tx.get_wallet_id(), body["psbt"]);
      }
    } else if (msgtype == "io.nunchuk.transaction.reject") {
      tx.add_reject_event_id(event.get_event_id());
    } else if (msgtype == "io.nunchuk.transaction.cancel") {
      tx.set_cancel_event_id(event.get_event_id());
    } else if (msgtype == "io.nunchuk.transaction.ready") {
      tx.set_ready_event_id(event.get_event_id());
    } else if (msgtype == "io.nunchuk.transaction.broadcast") {
      tx.set_broadcast_event_id(event.get_event_id());
      tx.set_tx_id(body["tx_id"]);
    }

    db.SetTransaction(tx);
    if (msgtype == "io.nunchuk.transaction.sign") {
      db.SetEvent(event);
      SendTransactionReady(event.get_room_id(), init_event_id);
    }
  }
  db.SetEvent(event);
}

void NunchukMatrixImpl::ConsumeSyncEvent(const std::unique_ptr<Nunchuk>& nu,
                                         const NunchukMatrixEvent& event,
                                         std::function<bool(int)> progress) {
  boost::unique_lock<boost::shared_mutex> lock(access_);
  if (event.get_type().rfind("io.nunchuk.sync", 0) != 0) return;
  if (event.get_event_id().empty()) return;
  if (event.get_event_id().rfind("$local", 0) == 0) return;

  auto db = storage_.GetRoomDb(chain_);
  if (db.HasEvent(event.get_event_id())) return;
  json content = json::parse(event.get_content());
  if (content["v"] == nullptr) return;
  std::string msgtype = content["msgtype"];
  if (msgtype == "io.nunchuk.sync.file") {
    auto data = content["file"];
    db.SetSyncRoomId(event.get_room_id());
    nu->SyncWithBackup(data.dump(), progress);
  }
  db.SetEvent(event);
}

std::unique_ptr<NunchukMatrix> MakeNunchukMatrixForAccount(
    const AppSettings& appsettings, const std::string& passphrase,
    const std::string& account, SendEventFunc SendEventFunc) {
  return std::unique_ptr<NunchukMatrixImpl>(
      new NunchukMatrixImpl(appsettings, passphrase, account, SendEventFunc));
}

}  // namespace nunchuk