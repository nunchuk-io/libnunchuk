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

#ifndef NUNCHUK_BITBOX_CRYPTO_H
#define NUNCHUK_BITBOX_CRYPTO_H

#include <array>
#include <span>
#include <string>
#include <vector>

namespace nunchuk::bitbox {

void SecureClear(std::span<unsigned char> value);

std::vector<unsigned char> EncodeSecp256k1Signature(
    std::span<const unsigned char> compact_signature);

std::array<unsigned char, 32> X25519PublicKey(
    std::span<const unsigned char> private_key);

bool VerifyAntiKlepto(std::span<const unsigned char> host_nonce,
                      std::span<const unsigned char> signer_commitment,
                      std::span<const unsigned char> compact_signature,
                      std::string& error);

struct AttestationResult {
  bool valid = false;
  std::string message;
};

AttestationResult VerifyAttestation(
    std::span<const unsigned char> challenge,
    std::span<const unsigned char> attestation);

}  // namespace nunchuk::bitbox

#endif  // NUNCHUK_BITBOX_CRYPTO_H
