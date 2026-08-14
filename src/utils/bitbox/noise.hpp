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

#ifndef NUNCHUK_BITBOX_NOISE_H
#define NUNCHUK_BITBOX_NOISE_H

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace nunchuk::bitbox {

class NoiseCipherState {
 public:
  NoiseCipherState() = default;
  explicit NoiseCipherState(std::span<const unsigned char> key);
  NoiseCipherState(const NoiseCipherState&) = delete;
  NoiseCipherState& operator=(const NoiseCipherState&) = delete;
  NoiseCipherState(NoiseCipherState&& other) noexcept;
  NoiseCipherState& operator=(NoiseCipherState&& other) noexcept;
  ~NoiseCipherState();

  std::vector<unsigned char> encrypt(
      std::span<const unsigned char> plaintext,
      std::span<const unsigned char> associated_data = {});
  std::vector<unsigned char> decrypt(
      std::span<const unsigned char> ciphertext,
      std::span<const unsigned char> associated_data = {});

 private:
  std::array<unsigned char, 32> key_{};
  uint64_t nonce_ = 0;
  bool has_key_ = false;
};

class NoiseHandshake {
 public:
  explicit NoiseHandshake(
      std::span<const unsigned char> static_private_key);
  NoiseHandshake(const NoiseHandshake&) = delete;
  NoiseHandshake& operator=(const NoiseHandshake&) = delete;
  ~NoiseHandshake();

  std::vector<unsigned char> start();
  std::vector<unsigned char> finish(
      std::span<const unsigned char> responder_message);

  bool complete() const;
  std::span<const unsigned char> remoteStaticPublicKey() const;
  std::span<const unsigned char> channelBinding() const;

  std::vector<unsigned char> encrypt(
      std::span<const unsigned char> plaintext);
  std::vector<unsigned char> decrypt(
      std::span<const unsigned char> ciphertext);

 private:
  void initializeSymmetric();
  void mixHash(std::span<const unsigned char> data);
  void mixKey(std::span<const unsigned char> input_key_material);
  std::vector<unsigned char> encryptAndHash(
      std::span<const unsigned char> plaintext);
  std::vector<unsigned char> decryptAndHash(
      std::span<const unsigned char> ciphertext);
  std::array<unsigned char, 32> dh(
      std::span<const unsigned char> private_key,
      std::span<const unsigned char> public_key) const;

  std::array<unsigned char, 32> static_private_key_{};
  std::array<unsigned char, 32> static_public_key_{};
  std::array<unsigned char, 32> ephemeral_private_key_{};
  std::array<unsigned char, 32> ephemeral_public_key_{};
  std::array<unsigned char, 32> remote_ephemeral_public_key_{};
  std::array<unsigned char, 32> remote_static_public_key_{};
  std::array<unsigned char, 32> chaining_key_{};
  std::array<unsigned char, 32> handshake_hash_{};
  NoiseCipherState handshake_cipher_;
  NoiseCipherState send_cipher_;
  NoiseCipherState receive_cipher_;
  bool started_ = false;
  bool complete_ = false;
};

}  // namespace nunchuk::bitbox

#endif  // NUNCHUK_BITBOX_NOISE_H
