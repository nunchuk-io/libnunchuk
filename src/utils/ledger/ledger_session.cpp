/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (c) 2020 Enigmo.
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * libnunchuk is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libnunchuk. If not, see <http://www.gnu.org/licenses/>.
 */

#include "utils/ledger/ledger_session.hpp"

#include <mutex>
#include <stdexcept>
#include <string_view>
#include <tinyformat.h>

#include "utils/ledger/bitcoin_app.hpp"
#include "utils/ledger/psbt.hpp"

namespace nunchuk::ledger {
namespace {

constexpr const char* BITCOIN_MAINNET_APP_NAME = "Bitcoin";
constexpr const char* BITCOIN_TESTNET_APP_NAME = "Bitcoin Test";
constexpr const char* LEDGER_OS_NAME = "BOLOS";
constexpr const char* LEDGER_OS_ALT_NAME = "OLOS";
constexpr size_t MESSAGE_CHUNK_SIZE = 64;
constexpr unsigned char BLE_MTU_OP = 0x08;
constexpr size_t BLE_MTU_RESPONSE_SIZE = 6;
constexpr size_t BLE_MTU_VALUE_OFFSET = 5;

const char* BitcoinAppName() {
  switch (Utils::GetChain()) {
    case Chain::MAIN:
      return BITCOIN_MAINNET_APP_NAME;
    case Chain::TESTNET:
    case Chain::SIGNET:
    case Chain::REGTEST:
      return BITCOIN_TESTNET_APP_NAME;
  }
  return BITCOIN_MAINNET_APP_NAME;
}

LedgerStep FailedStep(const std::string& message,
                      uint16_t status_word = SW_NONE) {
  LedgerStep step;
  step.type = LedgerStepType::FAILED;
  if (status_word == SW_DEVICE_LOCKED) {
    step.interaction = UserInteraction::UNLOCK_DEVICE;
  }
  step.error = LedgerError{-1, message, status_word};
  return step;
}

LedgerStep AppSwitchStep() {
  LedgerStep step;
  step.type = LedgerStepType::APP_SWITCH;
  step.interaction = UserInteraction::CONFIRM_OPEN_APP;
  return step;
}

std::string OpenAppStatusWordMessage(uint16_t status_word,
                                     const std::string& app_name) {
  switch (status_word) {
    case SW_DEVICE_LOCKED:
      return "Ledger device is locked. Unlock it and retry.";
    case SW_OS_NO_APP_NAME:
      return "Ledger OS error: no app name provided";
    case SW_OS_UNKNOWN_APP_NAME:
      return strprintf("Ledger app \"%s\" is not installed or cannot be "
                       "opened. Install it in Ledger Wallet, then retry.",
                       app_name);
    default:
      return strprintf("Ledger OS returned status word 0x%04x while opening "
                       "Ledger app \"%s\"",
                       status_word, app_name);
  }
}

std::string LedgerOsStatusWordMessage(uint16_t status_word) {
  if (status_word == SW_DEVICE_LOCKED) {
    return "Ledger device is locked. Unlock it and retry.";
  }
  return strprintf("Ledger OS returned status word 0x%04x", status_word);
}

std::string ParseCurrentAppName(const ApduResponse& response) {
  if (response.status_word != SW_OK) {
    throw std::runtime_error(LedgerOsStatusWordMessage(response.status_word));
  }
  if (response.data.empty() || response.data[0] != 0x01) {
    throw std::runtime_error(
        "Ledger app/version response has unsupported format");
  }
  size_t offset = 1;
  return ReadLvString(response.data, offset, "Ledger app/version response",
                      "app name");
}

bool IsDashboardName(const std::string& app_name) {
  constexpr std::string_view os_alt_name{LEDGER_OS_ALT_NAME};
  return app_name == LEDGER_OS_NAME || app_name == LEDGER_OS_ALT_NAME ||
         (app_name.size() == os_alt_name.size() + 1 &&
          app_name.back() == '\0' &&
          app_name.compare(0, os_alt_name.size(), os_alt_name) == 0);
}

std::vector<unsigned char> PrepareMessageSigningContext(
    LedgerContinuationContext& context, const std::string& message) {
  auto tree = BuildLedgerMerkleTree(message, MESSAGE_CHUNK_SIZE);
  const auto root = tree.root;
  context.addMerkleTree(tree);
  return root;
}

std::vector<unsigned char> SerializeWalletPolicy(
    const std::string& name, const std::string& descriptor,
    const LedgerMerkleTree& keys_tree, size_t keys_count) {
  constexpr unsigned char WALLET_POLICY_V2 = 0x02;
  std::vector<unsigned char> serialized;
  serialized.reserve(1 + 1 + name.size() + 9 + 32 + 9 + 32);
  serialized.push_back(WALLET_POLICY_V2);
  AppendLvString(serialized, name, "wallet name");

  const auto descriptor_length = EncodeLedgerVarint(descriptor.size());
  serialized.insert(serialized.end(), descriptor_length.begin(),
                    descriptor_length.end());
  const auto descriptor_hash = Sha256(descriptor);
  serialized.insert(serialized.end(), descriptor_hash.begin(),
                    descriptor_hash.end());

  const auto keys_length = EncodeLedgerVarint(keys_count);
  serialized.insert(serialized.end(), keys_length.begin(), keys_length.end());
  serialized.insert(serialized.end(), keys_tree.root.begin(),
                    keys_tree.root.end());
  return serialized;
}

struct PreparedWalletPolicy {
  std::vector<unsigned char> serialized_wallet;
  std::vector<unsigned char> wallet_id;
};

PreparedWalletPolicy PrepareWalletPolicyContext(
    LedgerContinuationContext& context, const Bip388Policy& policy,
    const std::string& wallet_name) {
  if (policy.keys_info.empty()) {
    throw std::invalid_argument("Wallet policy must contain key info");
  }

  const auto& descriptor = policy.descriptor_template;
  auto keys_tree = BuildLedgerMerkleTree(policy.keys_info);
  const auto serialized_wallet = SerializeWalletPolicy(
      wallet_name, descriptor, keys_tree, policy.keys_info.size());
  const auto wallet_id = Sha256(serialized_wallet);

  context.addPreimage(wallet_id, serialized_wallet);
  context.addPreimage(Sha256(descriptor), descriptor);
  context.addMerkleTree(keys_tree);
  return {serialized_wallet, wallet_id};
}

std::vector<unsigned char> PrepareRegisteredWalletAddressContext(
    LedgerContinuationContext& context, const RegisteredWallet& wallet) {
  return PrepareWalletPolicyContext(context, wallet.policy, wallet.name)
      .wallet_id;
}

std::vector<unsigned char> BuildBleMtuRequest() {
  return {BLE_MTU_OP, 0x00, 0x00, 0x00, 0x00};
}

size_t RequireBleMtuResponse(const std::vector<unsigned char>& data) {
  if (data.size() < BLE_MTU_RESPONSE_SIZE || data[0] != BLE_MTU_OP) {
    throw std::runtime_error("Invalid Ledger BLE MTU response");
  }
  const auto packet_size = static_cast<size_t>(data[BLE_MTU_VALUE_OFFSET]);
  if (packet_size == 0) {
    throw std::runtime_error("Invalid Ledger BLE MTU response");
  }
  return packet_size;
}

}  // namespace

LedgerSession::LedgerSession(LedgerTransport transport)
    : transport_(transport), framer_(transport) {}

LedgerStep LedgerSession::onData(const std::vector<unsigned char>& data) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!awaiting_response_) {
    return fail("LedgerSession received data with no active command");
  }
  if (active_command_ == ActiveCommand::SETUP_BLE_MTU) {
    return completeBleMtuSetup(data);
  }

  const auto decoded = framer_.decode(data);
  switch (decoded.type) {
    case ApduDecodeResult::Type::READ_MORE: {
      LedgerStep step;
      step.type = LedgerStepType::READ_MORE;
      step.interaction = active_interaction_;
      return step;
    }
    case ApduDecodeResult::Type::COMPLETE:
      return completeResponse(decoded.response);
    case ApduDecodeResult::Type::FAILED:
      resetState();
      return FailedStep(decoded.error.message, decoded.error.status_word);
  }

  return fail("LedgerSession reached an invalid decode state");
}

LedgerStep LedgerSession::resume() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!canResumeAppSwitch()) {
    return fail("LedgerSession has no command to resume after app switch");
  }

  framer_.reset();
  active_command_ = ActiveCommand::NONE;
  awaiting_response_ = false;
  awaiting_app_switch_resume_ = false;
  return checkCurrentApp();
}

void LedgerSession::updateTransport(LedgerTransport transport) {
  std::lock_guard<std::mutex> lock(mutex_);
  transport_ = transport;
  framer_ = ApduFramer(transport_);
  ble_mtu_setup_done_ = false;
}

LedgerValue LedgerSession::result() const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!has_result_) {
    throw std::logic_error("LedgerSession has no result");
  }
  return result_;
}

LedgerStep LedgerSession::getExtendedPublicKey(
    WalletType wallet_type, AddressType address_type, int index,
    const GetExtendedPublicKeyOptions& options) {
  auto path = Utils::GetBip32Path(wallet_type, address_type, index);
  return getExtendedPublicKey(path, options);
}

LedgerStep LedgerSession::getExtendedPublicKey(
    const std::string& derivation_path,
    const GetExtendedPublicKeyOptions& options) {
  std::lock_guard<std::mutex> lock(mutex_);
  (void)options.return_chain_code;
  auto path = derivation_path;
  std::replace(path.begin(), path.end(), 'h', '\'');
  try {
    return sendBitcoinApdu(
        bitcoin::BuildGetExtendedPublicKeyApdu(path, options),
        ActiveCommand::GET_EXTENDED_PUBLIC_KEY);
  } catch (const std::exception& e) {
    resetState();
    return FailedStep(e.what());
  }
}

LedgerStep LedgerSession::getMasterFingerprint() {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    return sendBitcoinApdu(bitcoin::BuildGetMasterFingerprintApdu(),
                           ActiveCommand::GET_MASTER_FINGERPRINT);
  } catch (const std::exception& e) {
    resetState();
    return FailedStep(e.what());
  }
}

LedgerStep LedgerSession::signMessage(const std::string& derivation_path,
                                      const std::string& message) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    resetState();
    const auto message_root =
        PrepareMessageSigningContext(continuation_context_, message);
    return queueBitcoinApdu(bitcoin::BuildSignMessageApdu(
                                derivation_path, message.size(), message_root),
                            ActiveCommand::SIGN_MESSAGE,
                            UserInteraction::SIGN_MESSAGE);
  } catch (const std::exception& e) {
    resetState();
    return FailedStep(e.what());
  }
}

LedgerStep LedgerSession::signPsbt(const RegisteredWallet& wallet,
                                   const std::string& psbt) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    resetState();
    const auto wallet_id =
        PrepareRegisteredWalletAddressContext(continuation_context_, wallet);
    const auto psbt_commitment =
        PreparePsbtSigningContext(continuation_context_, psbt);
    pending_psbt_ = psbt;
    return queueBitcoinApdu(
        bitcoin::BuildSignPsbtApdu(
            psbt_commitment.global_commitment, psbt_commitment.inputs_count,
            psbt_commitment.inputs_root, psbt_commitment.outputs_count,
            psbt_commitment.outputs_root, wallet_id, ParseHex(wallet.hmac)),
        ActiveCommand::SIGN_PSBT, UserInteraction::SIGN_TRANSACTION);
  } catch (const std::exception& e) {
    resetState();
    return FailedStep(e.what());
  }
}

LedgerStep LedgerSession::getWalletAddress(
    const RegisteredWallet& wallet, uint32_t address_index,
    const WalletAddressOptions& options) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    resetState();
    const auto wallet_id =
        PrepareRegisteredWalletAddressContext(continuation_context_, wallet);
    return queueBitcoinApdu(
        bitcoin::BuildGetWalletAddressApdu(options.check_on_device, wallet_id,
                                           ParseHex(wallet.hmac),
                                           options.change, address_index),
        ActiveCommand::GET_WALLET_ADDRESS,
        options.check_on_device ? UserInteraction::VERIFY_ADDRESS
                                : UserInteraction::NONE);
  } catch (const std::exception& e) {
    resetState();
    return FailedStep(e.what());
  }
}

LedgerStep LedgerSession::registerWallet(const Wallet& wallet) {
  return registerWallet(GetBip388Policy(wallet), wallet.get_name());
}

LedgerStep LedgerSession::registerWallet(const Bip388Policy& policy,
                                         const std::string& wallet_name) {
  std::lock_guard<std::mutex> lock(mutex_);
  try {
    resetState();
    const auto prepared = PrepareWalletPolicyContext(
        continuation_context_, policy, wallet_name);
    const auto apdu =
        bitcoin::BuildRegisterWalletApdu(prepared.serialized_wallet);
    return queueBitcoinApdu(apdu, ActiveCommand::REGISTER_WALLET,
                            UserInteraction::REGISTER_WALLET);
  } catch (const std::exception& e) {
    resetState();
    return FailedStep(e.what());
  }
}

LedgerStep LedgerSession::sendBitcoinApdu(
    const std::vector<unsigned char>& apdu, ActiveCommand command,
    UserInteraction interaction) {
  resetState();
  return queueBitcoinApdu(apdu, command, interaction);
}

LedgerStep LedgerSession::queueBitcoinApdu(
    const std::vector<unsigned char>& apdu, ActiveCommand command,
    UserInteraction interaction) {
  pending_apdu_ = apdu;
  pending_command_ = command;
  pending_interaction_ = interaction;
  return checkCurrentApp();
}

LedgerStep LedgerSession::beginWrite(const std::vector<unsigned char>& apdu,
                                     ActiveCommand command,
                                     UserInteraction interaction) {
  LedgerStep step;
  step.type = LedgerStepType::WRITE;
  step.interaction = interaction;
  step.writes = framer_.encode(apdu);
  active_command_ = command;
  active_interaction_ = interaction;
  awaiting_response_ = true;
  return step;
}

LedgerStep LedgerSession::checkCurrentApp() {
  if (needsBleMtuSetup()) {
    return beginBleMtuSetup();
  }
  return beginWrite(bitcoin::BuildGetAppAndVersionApdu(),
                    ActiveCommand::GET_APP_AND_VERSION);
}

LedgerStep LedgerSession::beginBleMtuSetup() {
  LedgerStep step;
  step.type = LedgerStepType::WRITE;
  step.interaction = UserInteraction::NONE;
  step.writes = {BuildBleMtuRequest()};
  active_command_ = ActiveCommand::SETUP_BLE_MTU;
  active_interaction_ = UserInteraction::NONE;
  awaiting_response_ = true;
  return step;
}

LedgerStep LedgerSession::sendCloseApp() {
  framer_.reset();
  return beginWrite(bitcoin::BuildCloseAppApdu(), ActiveCommand::CLOSE_APP);
}

LedgerStep LedgerSession::sendOpenApp() {
  framer_.reset();
  return beginWrite(bitcoin::BuildOpenAppApdu(BitcoinAppName()),
                    ActiveCommand::OPEN_APP, UserInteraction::CONFIRM_OPEN_APP);
}

LedgerStep LedgerSession::sendPendingCommand() {
  if (!pending_apdu_.has_value() || pending_command_ == ActiveCommand::NONE) {
    return fail("LedgerSession has no pending command");
  }
  const auto apdu = *pending_apdu_;
  const auto command = pending_command_;
  const auto interaction = pending_interaction_;
  pending_apdu_.reset();
  pending_command_ = ActiveCommand::NONE;
  pending_interaction_ = UserInteraction::NONE;
  return beginWrite(apdu, command, interaction);
}

LedgerStep LedgerSession::completeBleMtuSetup(
    const std::vector<unsigned char>& data) {
  try {
    framer_.setPacketSize(RequireBleMtuResponse(data));
    ble_mtu_setup_done_ = true;
    active_command_ = ActiveCommand::NONE;
    active_interaction_ = UserInteraction::NONE;
    awaiting_response_ = false;
    return checkCurrentApp();
  } catch (const std::exception& e) {
    resetState();
    return FailedStep(e.what());
  }
}

LedgerStep LedgerSession::completeResponse(const ApduResponse& response) {
  try {
    if (response.status_word == SW_INTERRUPTED_EXECUTION &&
        supportsInterruptedExecution(active_command_)) {
      return completeInterruptedExecution(response);
    }

    switch (active_command_) {
      case ActiveCommand::SETUP_BLE_MTU:
        return fail("Ledger BLE MTU setup response reached APDU parser");
      case ActiveCommand::GET_APP_AND_VERSION:
        return completeGetAppAndVersion(response);
      case ActiveCommand::CLOSE_APP:
        return completeCloseApp(response);
      case ActiveCommand::OPEN_APP:
        return completeOpenApp(response);
      case ActiveCommand::GET_EXTENDED_PUBLIC_KEY:
        result_ = bitcoin::ParseGetExtendedPublicKeyResponse(response);
        break;
      case ActiveCommand::GET_MASTER_FINGERPRINT:
        result_ = bitcoin::ParseGetMasterFingerprintResponse(response);
        break;
      case ActiveCommand::SIGN_MESSAGE:
        result_ = bitcoin::ParseMessageSignatureResponse(response);
        break;
      case ActiveCommand::SIGN_PSBT:
        if (!pending_psbt_.has_value()) {
          throw std::runtime_error("LedgerSession has no pending PSBT");
        }
        bitcoin::RequireSuccessResponse(response);
        result_ = BuildSignedPsbtResult(*pending_psbt_,
                                        continuation_context_.yieldedResults());
        break;
      case ActiveCommand::REGISTER_WALLET:
        result_ = RegisteredWalletResult{
            bitcoin::ParseRegisterWalletResponse(response)};
        break;
      case ActiveCommand::GET_WALLET_ADDRESS:
        result_ = bitcoin::ParseWalletAddressResponse(response);
        break;
      case ActiveCommand::NONE:
        return fail("LedgerSession has no command parser");
    }
  } catch (const std::exception& e) {
    resetState();
    return FailedStep(e.what(), response.status_word);
  }

  active_command_ = ActiveCommand::NONE;
  pending_command_ = ActiveCommand::NONE;
  active_interaction_ = UserInteraction::NONE;
  pending_interaction_ = UserInteraction::NONE;
  pending_apdu_.reset();
  pending_psbt_.reset();
  continuation_context_.reset();
  awaiting_response_ = false;
  awaiting_app_switch_resume_ = false;
  has_result_ = true;

  LedgerStep step;
  step.type = LedgerStepType::COMPLETE;
  return step;
}

LedgerStep LedgerSession::completeInterruptedExecution(
    const ApduResponse& response) {
  const auto command = active_command_;
  const auto interaction = active_interaction_;
  const auto payload = continuation_context_.resolve(response.data);
  framer_.reset();
  return beginWrite(bitcoin::BuildContinueApdu(payload), command, interaction);
}

LedgerStep LedgerSession::completeGetAppAndVersion(
    const ApduResponse& response) {
  if (response.status_word == SW_BUSY) {
    framer_.reset();
    return checkCurrentApp();
  }

  const auto app_name = ParseCurrentAppName(response);
  if (app_name == BitcoinAppName()) {
    return sendPendingCommand();
  }
  if (IsDashboardName(app_name)) {
    return sendOpenApp();
  }
  return sendCloseApp();
}

LedgerStep LedgerSession::completeCloseApp(const ApduResponse& response) {
  if (response.status_word != SW_OK) {
    resetState();
    return FailedStep(LedgerOsStatusWordMessage(response.status_word),
                      response.status_word);
  }
  return sendOpenApp();
}

LedgerStep LedgerSession::completeOpenApp(const ApduResponse& response) {
  if (response.status_word != SW_OK) {
    resetState();
    return FailedStep(OpenAppStatusWordMessage(response.status_word,
                                              BitcoinAppName()),
                      response.status_word);
  }

  framer_.reset();
  active_command_ = ActiveCommand::NONE;
  active_interaction_ = UserInteraction::NONE;
  awaiting_response_ = false;
  awaiting_app_switch_resume_ = true;
  return AppSwitchStep();
}

LedgerStep LedgerSession::fail(const std::string& message,
                               uint16_t status_word) {
  resetState();
  return FailedStep(message, status_word);
}

void LedgerSession::resetState() {
  framer_.reset();
  active_command_ = ActiveCommand::NONE;
  pending_command_ = ActiveCommand::NONE;
  active_interaction_ = UserInteraction::NONE;
  pending_interaction_ = UserInteraction::NONE;
  pending_apdu_.reset();
  pending_psbt_.reset();
  result_ = LedgerValue{};
  continuation_context_.reset();
  has_result_ = false;
  awaiting_response_ = false;
  awaiting_app_switch_resume_ = false;
}

bool LedgerSession::canResumeAppSwitch() const {
  return pending_apdu_.has_value() && pending_command_ != ActiveCommand::NONE &&
         (awaiting_app_switch_resume_ || isAppSwitchCommand(active_command_));
}

bool LedgerSession::needsBleMtuSetup() const {
  return transport_ == LedgerTransport::BLE && !ble_mtu_setup_done_;
}

bool LedgerSession::isAppSwitchCommand(ActiveCommand command) const {
  return command == ActiveCommand::GET_APP_AND_VERSION ||
         command == ActiveCommand::CLOSE_APP ||
         command == ActiveCommand::OPEN_APP;
}

bool LedgerSession::supportsInterruptedExecution(ActiveCommand command) const {
  return command == ActiveCommand::SIGN_MESSAGE ||
         command == ActiveCommand::SIGN_PSBT ||
         command == ActiveCommand::REGISTER_WALLET ||
         command == ActiveCommand::GET_WALLET_ADDRESS;
}

}  // namespace nunchuk::ledger
