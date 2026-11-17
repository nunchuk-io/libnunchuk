/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */
#ifndef NUNCHUK_ONEKEY_PROTOBUF_HPP
#define NUNCHUK_ONEKEY_PROTOBUF_HPP

#include <cstdint>
#include <span>
#include <vector>
#include "utils/json.hpp"

namespace nunchuk::onekey::proto {

enum MessageType : uint16_t {
  INITIALIZE = 0,
  SUCCESS = 2,
  FAILURE = 3,
  GET_PUBLIC_KEY = 11,
  PUBLIC_KEY = 12,
  SIGN_TX = 15,
  FEATURES = 17,
  PIN_MATRIX_REQUEST = 18,
  PIN_MATRIX_ACK = 19,
  CANCEL = 20,
  TX_REQUEST = 21,
  TX_ACK = 22,
  BUTTON_REQUEST = 26,
  BUTTON_ACK = 27,
  GET_ADDRESS = 29,
  ADDRESS = 30,
  SIGN_MESSAGE = 38,
  MESSAGE_SIGNATURE = 40,
  PASSPHRASE_REQUEST = 41,
  PASSPHRASE_ACK = 42,
  GET_FEATURES = 55,
  PIN_ON_DEVICE = 10000,
  SIGN_PSBT = 10052,
  SIGNED_PSBT = 10053,
  V2_PROTOCOL_INFO_REQUEST = 60200,
  V2_PROTOCOL_INFO = 60201,
  V2_PING = 60206,
  V2_SUCCESS = 60207,
  V2_FAILURE = 60208,
  V2_DEVICE_INFO_GET = 60600,
  V2_DEVICE_INFO = 60601,
  V2_DEVICE_STATUS_GET = 60602,
  V2_DEVICE_STATUS = 60603,
  V2_SESSION_GET = 61200,
  V2_SESSION = 61201,
  V2_SESSION_ASK_PIN = 61202,
  V2_SESSION_ASK_PASSPHRASE = 61203,
};

std::vector<unsigned char> Encode(uint16_t type, const nlohmann::json& data);
nlohmann::json Decode(uint16_t type, std::span<const unsigned char> data);

}  // namespace nunchuk::onekey::proto
#endif  // NUNCHUK_ONEKEY_PROTOBUF_HPP
