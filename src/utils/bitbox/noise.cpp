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

#include "utils/bitbox/noise.hpp"

#include <algorithm>
#include <crypto/sha256.h>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <random.h>
#include <stdexcept>
#include <string_view>

#include "utils/bitbox/crypto.hpp"

namespace nunchuk::bitbox {
namespace {

constexpr std::string_view PROTOCOL_NAME =
    "Noise_XX_25519_ChaChaPoly_SHA256";
constexpr size_t KEY_SIZE = 32;
constexpr size_t TAG_SIZE = 16;

using CipherContext =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using Pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PkeyContext =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

void ClearSensitive(std::array<unsigned char, KEY_SIZE>& value) {
  SecureClear(value);
}

void ClearSensitive(std::vector<unsigned char>& value) {
  SecureClear(value);
}

void ClearSensitive(
    std::vector<std::array<unsigned char, KEY_SIZE>>& values) {
  for (auto& value : values) ClearSensitive(value);
}

template <typename T>
class SecureClearGuard {
 public:
  explicit SecureClearGuard(T& value) : value_(&value) {}
  SecureClearGuard(const SecureClearGuard&) = delete;
  SecureClearGuard& operator=(const SecureClearGuard&) = delete;
  ~SecureClearGuard() {
    if (value_ != nullptr) ClearSensitive(*value_);
  }

  void release() { value_ = nullptr; }

 private:
  T* value_;
};

std::array<unsigned char, KEY_SIZE> HmacSha256(
    std::span<const unsigned char> key,
    std::span<const unsigned char> message) {
  std::array<unsigned char, KEY_SIZE> result{};
  unsigned int length = result.size();
  if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
           message.data(), message.size(), result.data(), &length) == nullptr ||
      length != result.size()) {
    ClearSensitive(result);
    throw std::runtime_error("BitBox Noise HMAC failed");
  }
  return result;
}

std::vector<std::array<unsigned char, KEY_SIZE>> Hkdf(
    std::span<const unsigned char> chaining_key,
    std::span<const unsigned char> input_key_material, size_t outputs) {
  if (outputs == 0 || outputs > 3) {
    throw std::invalid_argument("BitBox Noise HKDF output count is invalid");
  }
  auto temporary_key = HmacSha256(chaining_key, input_key_material);
  SecureClearGuard temporary_key_guard(temporary_key);
  std::vector<std::array<unsigned char, KEY_SIZE>> result;
  SecureClearGuard result_guard(result);
  result.reserve(outputs);
  std::vector<unsigned char> input;
  SecureClearGuard input_guard(input);
  for (size_t i = 1; i <= outputs; ++i) {
    input.clear();
    if (!result.empty()) {
      input.insert(input.end(), result.back().begin(), result.back().end());
    }
    input.push_back(static_cast<unsigned char>(i));
    result.push_back(HmacSha256(temporary_key, input));
  }
  result_guard.release();
  return result;
}

std::array<unsigned char, 12> NoiseNonce(uint64_t nonce) {
  std::array<unsigned char, 12> result{};
  for (size_t i = 0; i < sizeof(nonce); ++i) {
    result[4 + i] = static_cast<unsigned char>(nonce >> (8 * i));
  }
  return result;
}

std::vector<unsigned char> ChaChaEncrypt(
    std::span<const unsigned char> key, uint64_t nonce,
    std::span<const unsigned char> associated_data,
    std::span<const unsigned char> plaintext) {
  CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!context ||
      EVP_EncryptInit_ex(context.get(), EVP_chacha20_poly1305(), nullptr,
                         nullptr, nullptr) != 1) {
    throw std::runtime_error("BitBox Noise cipher initialization failed");
  }
  const auto iv = NoiseNonce(nonce);
  if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_IVLEN, iv.size(),
                          nullptr) != 1 ||
      EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(),
                         iv.data()) != 1) {
    throw std::runtime_error("BitBox Noise cipher key setup failed");
  }

  int aad_written = 0;
  if (!associated_data.empty() &&
      EVP_EncryptUpdate(context.get(), nullptr, &aad_written,
                        associated_data.data(), associated_data.size()) != 1) {
    throw std::runtime_error("BitBox Noise associated-data encryption failed");
  }

  std::vector<unsigned char> result(plaintext.size() + TAG_SIZE);
  int written = 0;
  int output_length = 0;
  if (!plaintext.empty() &&
      EVP_EncryptUpdate(context.get(), result.data(), &written,
                        plaintext.data(), plaintext.size()) != 1) {
    throw std::runtime_error("BitBox Noise encryption failed");
  }
  output_length += written;
  if (EVP_EncryptFinal_ex(context.get(), result.data() + output_length,
                          &written) != 1) {
    throw std::runtime_error("BitBox Noise encryption finalization failed");
  }
  output_length += written;
  if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_GET_TAG, TAG_SIZE,
                          result.data() + output_length) != 1) {
    throw std::runtime_error("BitBox Noise authentication tag failed");
  }
  result.resize(output_length + TAG_SIZE);
  return result;
}

std::vector<unsigned char> ChaChaDecrypt(
    std::span<const unsigned char> key, uint64_t nonce,
    std::span<const unsigned char> associated_data,
    std::span<const unsigned char> ciphertext) {
  if (ciphertext.size() < TAG_SIZE) {
    throw std::runtime_error("BitBox Noise ciphertext is too short");
  }
  const auto body = ciphertext.first(ciphertext.size() - TAG_SIZE);
  const auto tag = ciphertext.last(TAG_SIZE);
  CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!context ||
      EVP_DecryptInit_ex(context.get(), EVP_chacha20_poly1305(), nullptr,
                         nullptr, nullptr) != 1) {
    throw std::runtime_error("BitBox Noise cipher initialization failed");
  }
  const auto iv = NoiseNonce(nonce);
  if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_IVLEN, iv.size(),
                          nullptr) != 1 ||
      EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(),
                         iv.data()) != 1) {
    throw std::runtime_error("BitBox Noise cipher key setup failed");
  }

  int aad_written = 0;
  if (!associated_data.empty() &&
      EVP_DecryptUpdate(context.get(), nullptr, &aad_written,
                        associated_data.data(), associated_data.size()) != 1) {
    throw std::runtime_error("BitBox Noise associated-data decryption failed");
  }

  // ChaCha20-Poly1305 does not emit bytes during finalization, but keep one
  // byte available so the EVP output pointer is valid for an empty payload.
  std::vector<unsigned char> result(body.size() + 1);
  int written = 0;
  int output_length = 0;
  if (!body.empty() &&
      EVP_DecryptUpdate(context.get(), result.data(), &written, body.data(),
                        body.size()) != 1) {
    throw std::runtime_error("BitBox Noise decryption failed");
  }
  output_length += written;
  if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_TAG, tag.size(),
                          const_cast<unsigned char*>(tag.data())) != 1 ||
      EVP_DecryptFinal_ex(context.get(), result.data() + output_length,
                          &written) != 1) {
    throw std::runtime_error("BitBox Noise authentication failed");
  }
  output_length += written;
  result.resize(output_length);
  return result;
}

}  // namespace

NoiseCipherState::NoiseCipherState(std::span<const unsigned char> key) {
  if (key.size() != key_.size()) {
    throw std::invalid_argument("BitBox Noise key must be 32 bytes");
  }
  std::copy(key.begin(), key.end(), key_.begin());
  has_key_ = true;
}

NoiseCipherState::NoiseCipherState(NoiseCipherState&& other) noexcept
    : key_(other.key_), nonce_(other.nonce_), has_key_(other.has_key_) {
  ClearSensitive(other.key_);
  other.nonce_ = 0;
  other.has_key_ = false;
}

NoiseCipherState& NoiseCipherState::operator=(
    NoiseCipherState&& other) noexcept {
  if (this != &other) {
    ClearSensitive(key_);
    key_ = other.key_;
    nonce_ = other.nonce_;
    has_key_ = other.has_key_;
    ClearSensitive(other.key_);
    other.nonce_ = 0;
    other.has_key_ = false;
  }
  return *this;
}

NoiseCipherState::~NoiseCipherState() { ClearSensitive(key_); }

std::vector<unsigned char> NoiseCipherState::encrypt(
    std::span<const unsigned char> plaintext,
    std::span<const unsigned char> associated_data) {
  if (!has_key_) {
    return std::vector<unsigned char>(plaintext.begin(), plaintext.end());
  }
  if (nonce_ == std::numeric_limits<uint64_t>::max()) {
    throw std::runtime_error("BitBox Noise nonce exhausted");
  }
  auto result = ChaChaEncrypt(key_, nonce_, associated_data, plaintext);
  ++nonce_;
  return result;
}

std::vector<unsigned char> NoiseCipherState::decrypt(
    std::span<const unsigned char> ciphertext,
    std::span<const unsigned char> associated_data) {
  if (!has_key_) {
    return std::vector<unsigned char>(ciphertext.begin(), ciphertext.end());
  }
  if (nonce_ == std::numeric_limits<uint64_t>::max()) {
    throw std::runtime_error("BitBox Noise nonce exhausted");
  }
  auto result = ChaChaDecrypt(key_, nonce_, associated_data, ciphertext);
  ++nonce_;
  return result;
}

NoiseHandshake::NoiseHandshake(
    std::span<const unsigned char> static_private_key) {
  if (static_private_key.size() != static_private_key_.size()) {
    throw std::invalid_argument("BitBox Noise static key must be 32 bytes");
  }
  std::copy(static_private_key.begin(), static_private_key.end(),
            static_private_key_.begin());
  static_public_key_ = X25519PublicKey(static_private_key_);
  initializeSymmetric();
}

NoiseHandshake::~NoiseHandshake() {
  ClearSensitive(static_private_key_);
  ClearSensitive(ephemeral_private_key_);
  ClearSensitive(chaining_key_);
}

void NoiseHandshake::initializeSymmetric() {
  static_assert(PROTOCOL_NAME.size() == KEY_SIZE);
  std::copy(PROTOCOL_NAME.begin(), PROTOCOL_NAME.end(),
            handshake_hash_.begin());
  chaining_key_ = handshake_hash_;
  const auto prologue = std::span<const unsigned char>(
      reinterpret_cast<const unsigned char*>(PROTOCOL_NAME.data()),
      PROTOCOL_NAME.size());
  mixHash(prologue);
}

std::vector<unsigned char> NoiseHandshake::start() {
  if (started_) {
    throw std::logic_error("BitBox Noise handshake is already started");
  }
  GetStrongRandBytes(ephemeral_private_key_);
  ephemeral_public_key_ = X25519PublicKey(ephemeral_private_key_);
  mixHash(ephemeral_public_key_);
  auto payload = encryptAndHash({});
  std::vector<unsigned char> result(ephemeral_public_key_.begin(),
                                    ephemeral_public_key_.end());
  result.insert(result.end(), payload.begin(), payload.end());
  started_ = true;
  return result;
}

std::vector<unsigned char> NoiseHandshake::finish(
    std::span<const unsigned char> responder_message) {
  if (!started_ || complete_) {
    throw std::logic_error("BitBox Noise handshake is not awaiting message 2");
  }
  constexpr size_t MIN_RESPONDER_MESSAGE_SIZE = KEY_SIZE + 48 + TAG_SIZE;
  if (responder_message.size() < MIN_RESPONDER_MESSAGE_SIZE) {
    throw std::runtime_error("BitBox Noise message 2 has an invalid length");
  }

  std::copy_n(responder_message.begin(), KEY_SIZE,
              remote_ephemeral_public_key_.begin());
  mixHash(remote_ephemeral_public_key_);
  {
    auto shared = dh(ephemeral_private_key_, remote_ephemeral_public_key_);
    SecureClearGuard shared_guard(shared);
    mixKey(shared);
  }

  const auto encrypted_static = responder_message.subspan(KEY_SIZE, 48);
  const auto remote_static = decryptAndHash(encrypted_static);
  if (remote_static.size() != KEY_SIZE) {
    throw std::runtime_error("BitBox Noise remote static key is invalid");
  }
  std::copy(remote_static.begin(), remote_static.end(),
            remote_static_public_key_.begin());
  {
    auto shared = dh(ephemeral_private_key_, remote_static_public_key_);
    SecureClearGuard shared_guard(shared);
    mixKey(shared);
  }

  // The official BitBox clients consume and ignore the responder's Noise
  // application payload before sending message 3 with an empty payload.
  decryptAndHash(responder_message.subspan(KEY_SIZE + 48));

  auto result = encryptAndHash(static_public_key_);
  {
    auto shared = dh(static_private_key_, remote_ephemeral_public_key_);
    SecureClearGuard shared_guard(shared);
    mixKey(shared);
  }
  const auto final_payload = encryptAndHash({});
  result.insert(result.end(), final_payload.begin(), final_payload.end());

  auto split = Hkdf(chaining_key_, {}, 2);
  SecureClearGuard split_guard(split);
  send_cipher_ = NoiseCipherState(split[0]);
  receive_cipher_ = NoiseCipherState(split[1]);
  complete_ = true;
  ClearSensitive(ephemeral_private_key_);
  return result;
}

bool NoiseHandshake::complete() const { return complete_; }

std::span<const unsigned char> NoiseHandshake::remoteStaticPublicKey() const {
  if (!complete_) {
    throw std::logic_error("BitBox Noise handshake is not complete");
  }
  return remote_static_public_key_;
}

std::span<const unsigned char> NoiseHandshake::channelBinding() const {
  if (!complete_) {
    throw std::logic_error("BitBox Noise handshake is not complete");
  }
  return handshake_hash_;
}

std::vector<unsigned char> NoiseHandshake::encrypt(
    std::span<const unsigned char> plaintext) {
  if (!complete_) {
    throw std::logic_error("BitBox Noise handshake is not complete");
  }
  return send_cipher_.encrypt(plaintext);
}

std::vector<unsigned char> NoiseHandshake::decrypt(
    std::span<const unsigned char> ciphertext) {
  if (!complete_) {
    throw std::logic_error("BitBox Noise handshake is not complete");
  }
  return receive_cipher_.decrypt(ciphertext);
}

void NoiseHandshake::mixHash(std::span<const unsigned char> data) {
  std::vector<unsigned char> input(handshake_hash_.begin(),
                                   handshake_hash_.end());
  input.insert(input.end(), data.begin(), data.end());
  CSHA256().Write(input.data(), input.size()).Finalize(handshake_hash_.data());
  ClearSensitive(input);
}

void NoiseHandshake::mixKey(
    std::span<const unsigned char> input_key_material) {
  auto outputs = Hkdf(chaining_key_, input_key_material, 2);
  SecureClearGuard outputs_guard(outputs);
  chaining_key_ = outputs[0];
  handshake_cipher_ = NoiseCipherState(outputs[1]);
}

std::vector<unsigned char> NoiseHandshake::encryptAndHash(
    std::span<const unsigned char> plaintext) {
  auto ciphertext = handshake_cipher_.encrypt(plaintext, handshake_hash_);
  mixHash(ciphertext);
  return ciphertext;
}

std::vector<unsigned char> NoiseHandshake::decryptAndHash(
    std::span<const unsigned char> ciphertext) {
  auto plaintext = handshake_cipher_.decrypt(ciphertext, handshake_hash_);
  mixHash(ciphertext);
  return plaintext;
}

std::array<unsigned char, 32> NoiseHandshake::dh(
    std::span<const unsigned char> private_key,
    std::span<const unsigned char> public_key) const {
  if (private_key.size() != KEY_SIZE || public_key.size() != KEY_SIZE) {
    throw std::invalid_argument("BitBox Noise DH key has an invalid length");
  }
  Pkey private_pkey(EVP_PKEY_new_raw_private_key(
                        EVP_PKEY_X25519, nullptr, private_key.data(),
                        private_key.size()),
                    EVP_PKEY_free);
  Pkey public_pkey(EVP_PKEY_new_raw_public_key(
                       EVP_PKEY_X25519, nullptr, public_key.data(),
                       public_key.size()),
                   EVP_PKEY_free);
  if (!private_pkey || !public_pkey) {
    throw std::runtime_error("BitBox Noise X25519 key import failed");
  }
  PkeyContext context(EVP_PKEY_CTX_new(private_pkey.get(), nullptr),
                      EVP_PKEY_CTX_free);
  std::array<unsigned char, KEY_SIZE> result{};
  size_t result_size = result.size();
  if (!context || EVP_PKEY_derive_init(context.get()) != 1 ||
      EVP_PKEY_derive_set_peer(context.get(), public_pkey.get()) != 1 ||
      EVP_PKEY_derive(context.get(), result.data(), &result_size) != 1 ||
      result_size != result.size()) {
    throw std::runtime_error("BitBox Noise X25519 derivation failed");
  }
  if (std::all_of(result.begin(), result.end(),
                  [](unsigned char value) { return value == 0; })) {
    throw std::runtime_error("BitBox Noise X25519 shared secret is zero");
  }
  return result;
}

}  // namespace nunchuk::bitbox
