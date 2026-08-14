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

#include "utils/bitbox/crypto.hpp"

#include <algorithm>
#include <crypto/sha256.h>
#include <hash.h>
#include <memory>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <secp256k1.h>
#include <stdexcept>
#include <string_view>
#include <support/cleanse.h>
#include <util/strencodings.h>
#include <vector>

namespace nunchuk::bitbox {
namespace {

constexpr size_t HASH_SIZE = 32;
constexpr size_t COMPACT_SIGNATURE_SIZE = 64;
constexpr size_t DER_SIGNATURE_MAX_SIZE = 72;
constexpr size_t ATTESTATION_SIZE = 256;

constexpr std::string_view ATTESTATION_ROOTS[] = {
#include "utils/bitbox/attestation_roots.inc"
};

using Pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using MdContext =
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using Bignum = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

struct SecpContextDeleter {
  void operator()(secp256k1_context* context) const {
    secp256k1_context_destroy(context);
  }
};

using SecpContext =
    std::unique_ptr<secp256k1_context, SecpContextDeleter>;

// DER SubjectPublicKeyInfo prefix for a 65-byte uncompressed P-256 point.
constexpr std::array<unsigned char, 26> P256_SPKI_PREFIX{
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};

const secp256k1_context* GetSecpContext() {
  static const SecpContext context(
      secp256k1_context_create(SECP256K1_CONTEXT_NONE));
  return context.get();
}

std::vector<unsigned char> EncodeP256PublicKey(
    std::span<const unsigned char> public_key) {
  if (public_key.size() != 65 || public_key[0] != 0x04) return {};
  std::vector<unsigned char> result;
  result.reserve(P256_SPKI_PREFIX.size() + public_key.size());
  result.insert(result.end(), P256_SPKI_PREFIX.begin(),
                P256_SPKI_PREFIX.end());
  result.insert(result.end(), public_key.begin(), public_key.end());
  return result;
}

std::vector<unsigned char> EncodeCompactEcdsaSignature(
    std::span<const unsigned char> signature, bool normalize) {
  if (signature.size() != COMPACT_SIGNATURE_SIZE) return {};
  const auto* context = GetSecpContext();
  if (!context) return {};
  secp256k1_ecdsa_signature parsed;
  if (secp256k1_ecdsa_signature_parse_compact(
          context, &parsed, signature.data()) != 1) {
    return {};
  }
  secp256k1_ecdsa_signature normalized;
  const auto* encoded = &parsed;
  if (normalize) {
    secp256k1_ecdsa_signature_normalize(context, &normalized, &parsed);
    encoded = &normalized;
  }
  std::vector<unsigned char> result(DER_SIGNATURE_MAX_SIZE);
  size_t result_size = result.size();
  if (secp256k1_ecdsa_signature_serialize_der(
          context, result.data(), &result_size, encoded) != 1) {
    return {};
  }
  result.resize(result_size);
  return result;
}

bool VerifySecp256k1(std::span<const unsigned char> public_key,
                     std::span<const unsigned char> message,
                     std::span<const unsigned char> signature) {
  if (signature.size() != COMPACT_SIGNATURE_SIZE) return false;
  const auto* context = GetSecpContext();
  if (!context) return false;

  secp256k1_pubkey parsed_public_key;
  secp256k1_ecdsa_signature parsed_signature;
  if (secp256k1_ec_pubkey_parse(context, &parsed_public_key,
                                public_key.data(), public_key.size()) != 1 ||
      secp256k1_ecdsa_signature_parse_compact(
          context, &parsed_signature, signature.data()) != 1) {
    return false;
  }

  // libsecp256k1 verifies only low-S signatures. The BitBox attestation
  // format accepts either ECDSA form, like the official SDK's verifier.
  secp256k1_ecdsa_signature normalized_signature;
  secp256k1_ecdsa_signature_normalize(
      context, &normalized_signature, &parsed_signature);
  std::array<unsigned char, HASH_SIZE> digest{};
  CSHA256().Write(message.data(), message.size()).Finalize(digest.data());
  return secp256k1_ecdsa_verify(context, &normalized_signature,
                                digest.data(), &parsed_public_key) == 1;
}

bool VerifyP256(std::span<const unsigned char> public_key,
                std::span<const unsigned char> message,
                std::span<const unsigned char> signature) {
  const auto encoded_key = EncodeP256PublicKey(public_key);
  // DER serialization only encodes r and s. The P-256 order is smaller than
  // the secp256k1 order, so valid P-256 values also parse here. Do not apply
  // secp256k1 low-S normalization to a P-256 signature.
  const auto encoded_signature =
      EncodeCompactEcdsaSignature(signature, false);
  if (encoded_key.empty() || encoded_signature.empty()) return false;

  const unsigned char* input = encoded_key.data();
  Pkey key(d2i_PUBKEY(nullptr, &input, encoded_key.size()), EVP_PKEY_free);
  if (!key || input != encoded_key.data() + encoded_key.size()) return false;
  MdContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  return context &&
         EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr,
                              key.get()) == 1 &&
         EVP_DigestVerify(context.get(), encoded_signature.data(),
                          encoded_signature.size(), message.data(),
                          message.size()) == 1;
}

std::vector<unsigned char> FindAttestationRoot(
    std::span<const unsigned char> identifier) {
  if (identifier.size() != HASH_SIZE) return {};
  for (const auto root_hex : ATTESTATION_ROOTS) {
    auto root = ParseHex(root_hex);
    std::array<unsigned char, HASH_SIZE> hash{};
    CSHA256().Write(root.data(), root.size()).Finalize(hash.data());
    if (std::equal(hash.begin(), hash.end(), identifier.begin())) {
      return root;
    }
  }
  return {};
}

}  // namespace

std::vector<unsigned char> EncodeSecp256k1Signature(
    std::span<const unsigned char> compact_signature) {
  return EncodeCompactEcdsaSignature(compact_signature, true);
}

void SecureClear(std::span<unsigned char> value) {
  if (!value.empty()) memory_cleanse(value.data(), value.size());
}

std::array<unsigned char, HASH_SIZE> X25519PublicKey(
    std::span<const unsigned char> private_key) {
  if (private_key.size() != HASH_SIZE) {
    throw std::invalid_argument("BitBox X25519 private key must be 32 bytes");
  }
  Pkey key(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                         private_key.data(),
                                         private_key.size()),
           EVP_PKEY_free);
  std::array<unsigned char, HASH_SIZE> result{};
  size_t result_size = result.size();
  if (!key || EVP_PKEY_get_raw_public_key(key.get(), result.data(),
                                          &result_size) != 1 ||
      result_size != result.size()) {
    throw std::runtime_error("BitBox X25519 public-key derivation failed");
  }
  return result;
}

bool VerifyAntiKlepto(std::span<const unsigned char> host_nonce,
                      std::span<const unsigned char> signer_commitment,
                      std::span<const unsigned char> compact_signature,
                      std::string& error) {
  if (host_nonce.size() != HASH_SIZE || signer_commitment.size() != 33 ||
      compact_signature.size() != COMPACT_SIGNATURE_SIZE) {
    error = "BitBox anti-klepto proof has invalid lengths";
    return false;
  }

  const auto* context = GetSecpContext();
  if (!context) {
    error = "BitBox anti-klepto verifier initialization failed";
    return false;
  }
  secp256k1_pubkey commitment;
  if (secp256k1_ec_pubkey_parse(context, &commitment,
                                signer_commitment.data(),
                                signer_commitment.size()) != 1) {
    error = "BitBox anti-klepto signer commitment is invalid";
    return false;
  }

  std::vector<unsigned char> tweak_input(signer_commitment.begin(),
                                         signer_commitment.end());
  tweak_input.insert(tweak_input.end(), host_nonce.begin(), host_nonce.end());
  auto tweak_hasher = TaggedHash("s2c/ecdsa/point");
  tweak_hasher.write(std::as_bytes(
      std::span<const unsigned char>(tweak_input)));
  const auto tweak = tweak_hasher.GetSHA256();
  SecureClear(tweak_input);
  if (secp256k1_ec_seckey_verify(context, tweak.begin()) != 1 ||
      secp256k1_ec_pubkey_tweak_add(context, &commitment,
                                    tweak.begin()) != 1) {
    error = "BitBox anti-klepto tweak is invalid";
    return false;
  }

  std::array<unsigned char, 33> tweaked_commitment{};
  size_t serialized_size = tweaked_commitment.size();
  if (secp256k1_ec_pubkey_serialize(
          context, tweaked_commitment.data(), &serialized_size,
          &commitment, SECP256K1_EC_COMPRESSED) != 1 ||
      serialized_size != tweaked_commitment.size()) {
    error = "BitBox anti-klepto commitment serialization failed";
    return false;
  }

  Bignum x(BN_bin2bn(tweaked_commitment.data() + 1, HASH_SIZE, nullptr),
             BN_free);
  Bignum r(BN_bin2bn(compact_signature.data(), HASH_SIZE, nullptr), BN_free);
  BIGNUM* raw_order = nullptr;
  if (BN_hex2bn(&raw_order,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141") ==
      0) {
    error = "BitBox anti-klepto curve order initialization failed";
    return false;
  }
  Bignum order(raw_order, BN_free);
  std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> bn_context(BN_CTX_new(),
                                                            BN_CTX_free);
  if (!x || !r || !order || !bn_context ||
      BN_mod(x.get(), x.get(), order.get(), bn_context.get()) != 1 ||
      BN_cmp(x.get(), r.get()) != 0) {
    error = "BitBox anti-klepto signature verification failed";
    return false;
  }
  error.clear();
  return true;
}

AttestationResult VerifyAttestation(
    std::span<const unsigned char> challenge,
    std::span<const unsigned char> attestation) {
  if (challenge.size() != HASH_SIZE) {
    return {false, "attestation challenge must be 32 bytes"};
  }
  if (attestation.size() != ATTESTATION_SIZE) {
    return {false, "attestation payload must be 256 bytes"};
  }

  const auto bootloader_hash = attestation.subspan(0, 32);
  const auto device_public_key = attestation.subspan(32, 64);
  const auto certificate = attestation.subspan(96, 64);
  const auto root_identifier = attestation.subspan(160, 32);
  const auto challenge_signature = attestation.subspan(192, 64);
  const auto root = FindAttestationRoot(root_identifier);
  if (root.empty()) {
    return {false, "unknown BitBox attestation root"};
  }

  std::vector<unsigned char> certificate_message(bootloader_hash.begin(),
                                                  bootloader_hash.end());
  certificate_message.insert(certificate_message.end(),
                             device_public_key.begin(),
                             device_public_key.end());
  if (!VerifySecp256k1(root, certificate_message, certificate)) {
    return {false, "BitBox attestation certificate is invalid"};
  }

  std::array<unsigned char, 65> uncompressed_device_key{};
  uncompressed_device_key[0] = 0x04;
  std::copy(device_public_key.begin(), device_public_key.end(),
            uncompressed_device_key.begin() + 1);
  if (!VerifyP256(uncompressed_device_key, challenge,
                  challenge_signature)) {
    return {false, "BitBox attestation challenge signature is invalid"};
  }
  return {true, "BitBox manufacturer attestation verified"};
}

}  // namespace nunchuk::bitbox
