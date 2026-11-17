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
};

std::vector<unsigned char> Encode(uint16_t type, const nlohmann::json& data);
nlohmann::json Decode(uint16_t type, std::span<const unsigned char> data);

}  // namespace nunchuk::onekey::proto
#endif  // NUNCHUK_ONEKEY_PROTOBUF_HPP
