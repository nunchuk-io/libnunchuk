/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
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

#ifndef NUNCHUK_BITBOX_PSBT_H
#define NUNCHUK_BITBOX_PSBT_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <psbt.h>
#include <uint256.h>

#include "utils/bitbox/protobuf.hpp"
#include "utils/bitbox/types.hpp"

namespace nunchuk {
class Wallet;
}

namespace nunchuk::bitbox {

struct PsbtInputKey {
  enum class Type {
    ECDSA,
    TAPROOT_KEY_PATH,
    TAPROOT_SCRIPT_PATH,
  };

  Type type = Type::ECDSA;
  std::vector<uint32_t> keypath;
  std::vector<unsigned char> public_key;
  std::optional<uint256> leaf_hash;
};

struct PreparedPsbt {
  PartiallySignedTransaction psbt;
  std::vector<std::vector<uint32_t>> signing_account_keypaths;
  std::vector<proto::ScriptConfigWithKeypath> script_configs;
  std::vector<proto::SignInput> inputs;
  std::vector<proto::SignOutput> outputs;
  std::vector<PsbtInputKey> keys;
};

PreparedPsbt PreparePsbt(const std::string& encoded, const Wallet& wallet,
                         const std::string& root_fingerprint,
                         const std::string& firmware_version,
                         const std::optional<std::vector<uint32_t>>&
                             account_keypath = std::nullopt);
proto::PreviousTransactionInit PreviousTransactionInit(
    const PreparedPsbt& prepared, size_t input_index);
proto::PreviousTransactionInput PreviousTransactionInput(
    const PreparedPsbt& prepared, size_t input_index, size_t previous_index);
proto::PreviousTransactionOutput PreviousTransactionOutput(
    const PreparedPsbt& prepared, size_t input_index, size_t previous_index);
void ApplyPsbtSignature(PreparedPsbt& prepared, size_t input_index,
                        std::span<const unsigned char> signature);
SignPsbtResult FinishPsbt(const PreparedPsbt& prepared);

}  // namespace nunchuk::bitbox

#endif  // NUNCHUK_BITBOX_PSBT_H
