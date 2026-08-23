/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */

#ifndef NUNCHUK_JADE_TYPES_H
#define NUNCHUK_JADE_TYPES_H

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace nunchuk::jade {

enum class JadeStepType {
  WRITE,
  READ_MORE,
  CUSTOM_SERVER_APPROVAL,
  COMPLETE,
  FAILED,
};

enum class UserInteraction {
  NONE,
  SETUP_DEVICE,
  ENTER_PIN,
  VERIFY_ADDRESS,
  REGISTER_WALLET,
  SIGN_MESSAGE,
  SIGN_TRANSACTION,
  APPROVE_PINSERVER,
};

enum class JadeErrorCode {
  NONE = 0,
  INVALID_STATE = 1,
  INVALID_ARGUMENT = 2,
  INVALID_RESPONSE = 3,
  PROTOCOL = 4,
  UNSUPPORTED_FIRMWARE = 5,
  UNSUPPORTED_WALLET = 6,
  INVALID_PSBT = 7,
  WALLET_NOT_REGISTERED = 8,
  HTTP = 9,
  CUSTOM_SERVER_REJECTED = 10,
  TOR_REQUIRED = 11,
  ANTI_EXFIL = 12,
  SESSION_LOST = 13,
  DEVICE_LOCKED = 14,
  NETWORK_MISMATCH = 15,
  USER_CANCELLED = 16,
  DEVICE = 17,
};

struct JadeError {
  JadeErrorCode code = JadeErrorCode::NONE;
  std::string message;
  int device_code = 0;
  std::string device_data;
};

struct CustomPinServerInfo {
  std::vector<std::string> urls;
  std::string method;
  std::string host;
};

struct JadeStep {
  JadeStepType type = JadeStepType::READ_MORE;
  UserInteraction interaction = UserInteraction::NONE;
  std::vector<std::vector<unsigned char>> writes;
  std::optional<CustomPinServerInfo> custom_server;
  std::optional<JadeError> error;
};

enum class JadeDeviceState {
  UNKNOWN,
  LOCKED,
  UNSAVED,
  UNINITIALIZED,
  TEMPORARY,
  READY,
};

enum class JadeDeviceNetworks {
  UNKNOWN,
  MAIN,
  TEST,
  ALL,
};

struct JadeDeviceInfo {
  std::string firmware_version;
  uint32_t ota_max_chunk = 0;
  std::string config;
  std::string board_type;
  std::string features;
  std::string idf_version;
  std::string chip_features;
  std::optional<std::string> efuse_mac;
  std::optional<uint32_t> battery_status;
  JadeDeviceState state = JadeDeviceState::UNKNOWN;
  JadeDeviceNetworks networks = JadeDeviceNetworks::UNKNOWN;
  bool has_pin = false;
  bool has_pin_reported = false;
  bool firmware_upgrade_required = false;
};

struct InitializeResult {
  JadeDeviceInfo device;
};

struct GetVersionInfoResult {
  JadeDeviceInfo device;
};

struct GetExtendedPublicKeyResult {
  std::string extended_public_key;
};

struct GetMasterFingerprintResult {
  std::string master_fingerprint;
};

struct RegistrationResult {
  bool registered = false;
  std::string name;
};

struct WalletAddressOptions {
  bool change = false;
};

struct WalletAddressResult {
  std::string address;
};

struct SignMessageResult {
  std::string signature;
};

struct SignPsbtResult {
  std::string psbt;
};

using JadeValue =
    std::variant<std::monostate, InitializeResult, GetVersionInfoResult,
                 GetExtendedPublicKeyResult, GetMasterFingerprintResult,
                 RegistrationResult, WalletAddressResult, SignMessageResult,
                 SignPsbtResult>;

}  // namespace nunchuk::jade

#endif  // NUNCHUK_JADE_TYPES_H
