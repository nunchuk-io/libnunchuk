/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (c) 2020 Enigmo.
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * libnunchuk is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libnunchuk. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NUNCHUK_SILENTPAYMENT_H
#define NUNCHUK_SILENTPAYMENT_H

#include <compat/endian.h>
#include <nunchuk.h>
#include <pubkey.h>
#include <key.h>
#include <script/script.h>
#include <script/solver.h>
#include <bech32.h>
#include <crypto/sha256.h>
#include <util/strencodings.h>
#include <uint256.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_schnorrsig.h>
#include <addresstype.h>
#include <key_io.h>
#include <openssl/bn.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cstring>

namespace {

// Check if an address is a Silent Payment address (sp1... or tsp1...)
inline bool IsSilentPaymentAddress(const std::string& address, nunchuk::Chain chain) {
  std::string prefix = (chain == nunchuk::Chain::MAIN) ? "sp1" : "tsp1";
  if (address.length() < prefix.length()) return false;
  std::string addr_lower = address;
  std::transform(addr_lower.begin(), addr_lower.end(), addr_lower.begin(), ::tolower);
  return addr_lower.substr(0, prefix.length()) == prefix;
}

// Minimal Bech32/Bech32m checksum verification without length limits.
// (BIP173/BIP350; adapted from Bitcoin Core's bech32 implementation.)
inline uint32_t Bech32Polymod(const std::vector<uint8_t>& values) {
  uint32_t chk = 1;
  for (uint8_t v : values) {
    uint8_t top = chk >> 25;
    chk = (chk & 0x1ffffff) << 5 ^ v;
    if (top & 1) chk ^= 0x3b6a57b2;
    if (top & 2) chk ^= 0x26508e6d;
    if (top & 4) chk ^= 0x1ea119fa;
    if (top & 8) chk ^= 0x3d4233dd;
    if (top & 16) chk ^= 0x2a1462b3;
  }
  return chk;
}

inline std::vector<uint8_t> Bech32HrpExpand(const std::string& hrp) {
  std::vector<uint8_t> ret;
  ret.reserve(hrp.size() * 2 + 1);
  for (unsigned char c : hrp) ret.push_back(c >> 5);
  ret.push_back(0);
  for (unsigned char c : hrp) ret.push_back(c & 0x1f);
  return ret;
}

inline bech32::Encoding VerifyBech32ChecksumNoLimit(const std::string& hrp, const std::vector<uint8_t>& values) {
  // Checksum needs at least 6 values.
  if (values.size() < bech32::CHECKSUM_SIZE) return bech32::Encoding::INVALID;

  std::vector<uint8_t> enc = Bech32HrpExpand(hrp);
  enc.insert(enc.end(), values.begin(), values.end());
  const uint32_t check = Bech32Polymod(enc);

  // Encoding constants per BIP173/BIP350.
  if (check == 1) return bech32::Encoding::BECH32;
  if (check == 0x2bc830a3) return bech32::Encoding::BECH32M;
  return bech32::Encoding::INVALID;
}

// Structure to hold decoded Silent Payment address keys
struct SilentPaymentKeys {
  CPubKey B_scan;  // Scan public key (33 bytes)
  CPubKey B_m;     // Spend public key (33 bytes)
  
  bool IsValid() const {
    return B_scan.IsValid() && B_m.IsValid();
  }
};

// Helper function to decode bech32m without length limit (for Silent Payment addresses)
// This is needed because Silent Payment addresses can be longer than 90 chars
// We manually decode and verify checksum (BIP173/BIP350) without length limits.
inline bech32::DecodeResult DecodeBech32MNoLimit(const std::string& str) {
  bech32::DecodeResult result;
  
  // Check characters
  bool lower = false, upper = false;
  for (size_t i = 0; i < str.size(); ++i) {
    unsigned char c = str[i];
    if (c >= 'a' && c <= 'z') {
      if (upper) return result;  // Mixed case
      lower = true;
    } else if (c >= 'A' && c <= 'Z') {
      if (lower) return result;  // Mixed case
      upper = true;
    } else if (c < 33 || c > 126) {
      return result;  // Invalid character
    }
  }
  
  // Find separator
  size_t pos = str.rfind('1');
  if (pos == std::string::npos || pos == 0 || pos + 6 >= str.size()) {
    return result;
  }
  
  // Decode data
  const int8_t CHARSET_REV[128] = {
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
      -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
       1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
      -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
       1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
  };
  
  std::vector<uint8_t> values(str.size() - 1 - pos);
  for (size_t i = 0; i < str.size() - 1 - pos; ++i) {
    unsigned char c = str[i + pos + 1];
    if (c >= 128) return result;
    int8_t rev = CHARSET_REV[c];
    if (rev == -1) return result;
    values[i] = rev;
  }
  
  // Extract HRP
  std::string hrp;
  hrp.reserve(pos);
  for (size_t i = 0; i < pos; ++i) {
    unsigned char c = str[i];
    hrp += (c >= 'A' && c <= 'Z') ? (c - 'A' + 'a') : c;
  }
  
  const bech32::Encoding enc = VerifyBech32ChecksumNoLimit(hrp, values);
  if (enc == bech32::Encoding::INVALID) return result;

  // Return payload without checksum.
  std::vector<uint8_t> data(values.begin(), values.end() - bech32::CHECKSUM_SIZE);
  if (data.empty()) return result;

  result.encoding = enc;
  result.hrp = hrp;
  result.data = std::move(data);
  return result;
}

// Decode Silent Payment address according to BIP-352
// Format: [version byte] + B_scan (33 bytes) + B_m (33 bytes) = 67 bytes total
// Returns keys with invalid pubkeys if decode fails
// Note: Silent Payment addresses can be longer than 90 chars, so we use a custom decode
inline SilentPaymentKeys DecodeSilentPaymentAddress(const std::string& address, nunchuk::Chain chain) {
  SilentPaymentKeys keys;
  std::string expected_hrp = (chain == nunchuk::Chain::MAIN) ? "sp" : "tsp";

  // BIP-352 recommends capping Silent Payment address length to 1023 characters.
  // This matches Bech32 checksum design assumptions (BIP173) and avoids pathological inputs.
  if (address.size() > 1023) {
    return keys;
  }
  
  // Try standard decode first
  auto dec = bech32::Decode(address, bech32::CharLimit::BECH32);

  // If it failed (likely due to length > 90), use custom decode
  if (dec.encoding == bech32::Encoding::INVALID || dec.hrp != expected_hrp) {
    // Address is likely longer than 90 chars, use custom decode
    dec = DecodeBech32MNoLimit(address);
    // Debug: check what custom decode returned
    if (dec.encoding == bech32::Encoding::INVALID || dec.hrp != expected_hrp) {
      // Still failed, return empty keys
      return keys;
    }
  }
  
  if (dec.encoding != bech32::Encoding::BECH32M || dec.hrp != expected_hrp) {
    return keys;
  }

  if (dec.data.empty()) {
    return keys;
  }
  
  // Convert from 5-bit groups to bytes
  // Silent Payment address format: [version] + B_scan (33 bytes) + B_m (33 bytes)
  std::vector<unsigned char> data_bytes;
  data_bytes.reserve((dec.data.size() * 5) / 8);
  if (!ConvertBits<5, 8, false>([&](unsigned char c) { data_bytes.push_back(c); }, dec.data.begin() + 1, dec.data.end())) {
    return keys;
  }
  
  if (data_bytes.size() != 66) {    
    return keys;
  }
  
  // Skip version byte (data_bytes[0]), extract B_scan and B_m
  std::vector<unsigned char> B_scan_bytes(data_bytes.begin(), data_bytes.begin() + 33);
  std::vector<unsigned char> B_m_bytes(data_bytes.begin() + 33, data_bytes.end());
  
  keys.B_scan = CPubKey(B_scan_bytes);
  keys.B_m = CPubKey(B_m_bytes);
  
  if (!keys.B_scan.IsValid() || !keys.B_m.IsValid()) {
    keys.B_scan = CPubKey();
    keys.B_m = CPubKey();
  }
  
  return keys;
}

std::string ToHex(const std::vector<unsigned char>& bytes) {
  std::ostringstream oss;
  for (unsigned char byte : bytes) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(byte);
  }
  return oss.str();
}

// Calculate input hash according to BIP-352
// input_hash = TaggedHash("BIP0352/Inputs", outpoint_L || (a_sum·G))
// where outpoint_L is the lexicographically smallest outpoint
// and a_sum·G is the public key corresponding to the sum of all input private keys
inline uint256 CalculateInputHash(
    const std::vector<nunchuk::UnspentOutput>& inputs,
    const CPubKey& sum_pubkey) {
  if (inputs.empty() || !sum_pubkey.IsValid() || !sum_pubkey.IsCompressed()) {
    return uint256();
  }
  
  // Find lexicographically smallest outpoint (outpoint_L)
  // According to BIP-352: outpoints are sorted by their serialized bytes.
  // Serialization: txid (32 bytes, little-endian) || vout (4 bytes, little-endian).
  std::vector<std::pair<std::vector<unsigned char>, std::pair<uint256, uint32_t>>> outpoints_serialized;
  for (const auto& input : inputs) {
    uint256 txid;
    auto txid_opt = uint256::FromHex(input.get_txid());
    if (!txid_opt) {
      return uint256();
    }
    txid = *txid_opt;

    std::vector<unsigned char> serialized;
    serialized.reserve(36);
    serialized.insert(serialized.end(), txid.begin(), txid.end());  // 32 bytes, LE
    uint32_t vout = input.get_vout();
    serialized.push_back(static_cast<unsigned char>(vout & 0xFF));
    serialized.push_back(static_cast<unsigned char>((vout >> 8) & 0xFF));
    serialized.push_back(static_cast<unsigned char>((vout >> 16) & 0xFF));
    serialized.push_back(static_cast<unsigned char>((vout >> 24) & 0xFF));

    outpoints_serialized.push_back({serialized, {txid, input.get_vout()}});
  }
  
  // Sort by serialized bytes (lexicographically)
  std::sort(outpoints_serialized.begin(), outpoints_serialized.end(),
    [](const auto& a, const auto& b) {
      return a.first < b.first;
    });
  
  const auto& outpoint_L = outpoints_serialized[0].second;
  
  // Hash: input_hash = TaggedHash("BIP0352/Inputs", outpoint_L || (a_sum·G))
  // TaggedHash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data)
  const std::string tag = "BIP0352/Inputs";
  CSHA256 tag_hasher;
  tag_hasher.Write((const unsigned char*)tag.data(), tag.size());
  unsigned char tag_hash[32];
  tag_hasher.Finalize(tag_hash);
  
  CSHA256 hasher;
  hasher.Write(tag_hash, 32);  // First SHA256(tag)
  hasher.Write(tag_hash, 32);  // Second SHA256(tag)
  
  // Serialize outpoint_L: txid (32 bytes, little-endian) + vout (4 bytes, little-endian)
  // Use the serialized bytes from sorting
  hasher.Write(outpoints_serialized[0].first.data(), 36);
  hasher.Write(sum_pubkey.begin(), sum_pubkey.size());

  uint256 result;
  hasher.Finalize(result.begin());
  return result;
}

inline CKey CalculateTweakedKey(const CKey& key) {
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  unsigned char key_bytes[32];
  const std::byte* key_data = key.data();
  memcpy(key_bytes, reinterpret_cast<const unsigned char*>(key_data), 32);
  
  // Apply BIP341 TapTweak for keypath spend with no script tree (BIP86-style).
  // This requires:
  //  - internal key with even Y (handled above by negating when needed)
  //  - seckey' = seckey + H_TapTweak(xonly_internal)
  secp256k1_pubkey pubkey_point;
  unsigned char pubkey_serialized[33];
  if (!secp256k1_ec_pubkey_create(ctx, &pubkey_point, key_bytes)) {
    secp256k1_context_destroy(ctx);
    throw std::runtime_error("Failed to create pubkey point");
  }
  // Serialize to get y coordinate
  size_t pubkey_len = 33;
  if (!secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkey_len, &pubkey_point, SECP256K1_EC_COMPRESSED)) {
    secp256k1_context_destroy(ctx);
    throw std::runtime_error("Failed to serialize pubkey");
  }
  // Check if y coordinate is odd (0x03 prefix = odd y, 0x02 = even y)
  if (pubkey_serialized[0] == 0x03) {
    // Odd y coordinate, negate the private key
    if (!secp256k1_ec_seckey_negate(ctx, key_bytes)) {
      secp256k1_context_destroy(ctx);
      throw std::runtime_error("Failed to negate private key");
    }
    // Update pubkey_serialized to match the negated key (same X, even Y)
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey_point, key_bytes)) {
      secp256k1_context_destroy(ctx);
      throw std::runtime_error("Failed to update pubkey_serialized");
    }
    pubkey_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkey_len, &pubkey_point, SECP256K1_EC_COMPRESSED)) {
      secp256k1_context_destroy(ctx);
      throw std::runtime_error("Failed to serialize pubkey");
    }
  }

  CPubKey internal_pubkey{pubkey_serialized};
  XOnlyPubKey xonly_internal{internal_pubkey};
  uint256 tweak = xonly_internal.ComputeTapTweakHash(nullptr);
  if (!secp256k1_ec_seckey_tweak_add(ctx, key_bytes, tweak.begin())) {
    secp256k1_context_destroy(ctx);
    throw std::runtime_error("Failed to add tweak to private key");
  }
  secp256k1_context_destroy(ctx);
  CKey tweaked_key;
  tweaked_key.Set(key_bytes, key_bytes + 32, true);
  return tweaked_key;
}

// Derive Silent Payment output public keys according to BIP-352
// Returns vector of derived output public keys (taproot x-only pubkeys)
inline std::vector<XOnlyPubKey> DeriveSilentPaymentOutputs(
    const CPubKey& B_scan,  // Silent Payment scan public key
    const CPubKey& B_m,     // Silent Payment spend public key
    const std::vector<CKey>& input_privkeys,  // Input private keys
    const std::vector<nunchuk::UnspentOutput>& inputs,
    const std::vector<bool>& is_taproot_inputs,  // Whether each input is taproot
    size_t num_outputs,
    size_t starting_k = 0) {  // Starting value for k (for multiple B_m with same B_scan)
  std::vector<XOnlyPubKey> outputs;
  if (!B_scan.IsValid() || !B_m.IsValid() || input_privkeys.empty() || 
      inputs.empty() || num_outputs == 0 ||
      is_taproot_inputs.size() != input_privkeys.size()) {
    return outputs;
  }
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  
  // Calculate sum of input private keys: a_sum = sum(a_i) mod n
  // According to BIP-352: if input is x-only pubkey with odd y, negate the private key
  //
  // IMPORTANT: secp256k1_ec_seckey_tweak_add() fails if the *intermediate* sum hits 0 (invalid seckey),
  // we therefore sum all eligible input keys modulo curve order (n) using big-integer
  // arithmetic and only reject if the final sum is 0.
  unsigned char a_sum[32] = {0};
  // secp256k1 curve order n (32-byte big-endian):
  // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  static const unsigned char SECP256K1_ORDER_BE[32] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
      0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
      0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
  };

  BN_CTX* bn_ctx = BN_CTX_new();
  if (bn_ctx == nullptr) {
    secp256k1_context_destroy(ctx);
    return outputs;
  }

  BN_CTX_start(bn_ctx);
  BIGNUM* bn_order = BN_CTX_get(bn_ctx);
  BIGNUM* bn_sum = BN_CTX_get(bn_ctx);
  BIGNUM* bn_key = BN_CTX_get(bn_ctx);
  if (bn_order == nullptr || bn_sum == nullptr || bn_key == nullptr) {
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    secp256k1_context_destroy(ctx);
    return outputs;
  }

  if (BN_bin2bn(SECP256K1_ORDER_BE, 32, bn_order) == nullptr) {
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    secp256k1_context_destroy(ctx);
    return outputs;
  }

  BN_zero(bn_sum);
  // Best-effort: ask OpenSSL to use constant-time operations for this value.
  BN_set_flags(bn_sum, BN_FLG_CONSTTIME);
  for (size_t i = 0; i < input_privkeys.size(); i++) {
    const auto& key = input_privkeys[i];
    if (!key.IsValid()) {
      BN_CTX_end(bn_ctx);
      BN_CTX_free(bn_ctx);
      secp256k1_context_destroy(ctx);
      return outputs;
    }
    
    // Get the key bytes
    unsigned char key_bytes[32];
    const std::byte* key_data = key.data();
    memcpy(key_bytes, reinterpret_cast<const unsigned char*>(key_data), 32);
    
    // According to BIP-352: if input is x-only pubkey (taproot) with odd y, negate the private key
    // We need to check the y coordinate of the pubkey derived from the private key, not from scriptPubKey
    if (i < is_taproot_inputs.size() && is_taproot_inputs[i]) {
      // Derive pubkey from private key to check y coordinate
      secp256k1_pubkey pubkey_point;
      if (!secp256k1_ec_pubkey_create(ctx, &pubkey_point, key_bytes)) {
        secp256k1_context_destroy(ctx);
        return outputs;
      }
      // Serialize to get y coordinate
      unsigned char pubkey_serialized[33];
      size_t pubkey_len = 33;
      if (!secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkey_len, &pubkey_point, SECP256K1_EC_COMPRESSED)) {
        secp256k1_context_destroy(ctx);
        return outputs;
      }
      // Check if y coordinate is odd (0x03 prefix = odd y, 0x02 = even y)
      if (pubkey_serialized[0] == 0x03) {
        // Odd y coordinate, negate the private key
        if (!secp256k1_ec_seckey_negate(ctx, key_bytes)) {
          BN_CTX_end(bn_ctx);
          BN_CTX_free(bn_ctx);
          secp256k1_context_destroy(ctx);
          return outputs;
        }
      }
    }
    
    // Validate seckey bytes before BN math (must be in [1, n-1]).
    if (!secp256k1_ec_seckey_verify(ctx, key_bytes)) {
      BN_CTX_end(bn_ctx);
      BN_CTX_free(bn_ctx);
      secp256k1_context_destroy(ctx);
      return outputs;
    }

    if (BN_bin2bn(key_bytes, 32, bn_key) == nullptr) {
      BN_CTX_end(bn_ctx);
      BN_CTX_free(bn_ctx);
      secp256k1_context_destroy(ctx);
      return outputs;
    }
    // bn_sum = (bn_sum + bn_key) mod n
    int ok = BN_mod_add(bn_sum, bn_sum, bn_key, bn_order, bn_ctx);
    if (ok != 1) {
      BN_CTX_end(bn_ctx);
      BN_CTX_free(bn_ctx);
      secp256k1_context_destroy(ctx);
      return outputs;
    }
  }

  // Reject final sum == 0 (invalid seckey) per BIP-352.
  if (BN_is_zero(bn_sum)) {
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    secp256k1_context_destroy(ctx);
    return outputs;
  }
  if (BN_bn2binpad(bn_sum, a_sum, 32) != 32) {
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    secp256k1_context_destroy(ctx);
    return outputs;
  }
  BN_CTX_end(bn_ctx);
  BN_CTX_free(bn_ctx);
  
  // Calculate a_sum·G (public key corresponding to sum of private keys)
  secp256k1_pubkey sum_pubkey_point;
  if (!secp256k1_ec_pubkey_create(ctx, &sum_pubkey_point, a_sum)) {
    secp256k1_context_destroy(ctx);
    return outputs;
  }
  // Serialize sum public key - need uncompressed for input hash
  unsigned char sum_pubkey_uncompressed[65];
  size_t sum_pubkey_len = 65;
  secp256k1_ec_pubkey_serialize(ctx, sum_pubkey_uncompressed, &sum_pubkey_len, &sum_pubkey_point, SECP256K1_EC_UNCOMPRESSED);
  // Also get compressed for CPubKey
  unsigned char sum_pubkey_compressed[33];
  size_t sum_pubkey_compressed_len = 33;
  secp256k1_ec_pubkey_serialize(ctx, sum_pubkey_compressed, &sum_pubkey_compressed_len, &sum_pubkey_point, SECP256K1_EC_COMPRESSED);
  CPubKey sum_pubkey(sum_pubkey_compressed);
  // Check if a_sum is zero (should fail per BIP-352)
  // This is already checked by secp256k1_ec_seckey_verify and secp256k1_ec_pubkey_create above
  // If sum_pubkey is invalid, we've already returned
  // Calculate input_hash = TaggedHash("BIP0352/Inputs", outpoint_L || (a_sum·G))
  // Note: CalculateInputHash expects uncompressed pubkey
  uint256 input_hash = CalculateInputHash(inputs, sum_pubkey);
  if (input_hash.IsNull()) {
    secp256k1_context_destroy(ctx);
    return outputs;
  }

  // Calculate input_hash * a_sum mod n
  // First multiply a_sum by input_hash
  unsigned char input_hash_bytes[32];
  memcpy(input_hash_bytes, input_hash.begin(), 32);
  if (!secp256k1_ec_seckey_tweak_mul(ctx, a_sum, input_hash_bytes)) {
    secp256k1_context_destroy(ctx);
    return outputs;
  }
  // Parse B_scan as secp256k1_pubkey
  secp256k1_pubkey B_scan_point;
  if (!secp256k1_ec_pubkey_parse(ctx, &B_scan_point, B_scan.begin(), B_scan.size())) {
    secp256k1_context_destroy(ctx);
    return outputs;
  }
  // Calculate shared_point = input_hash * a_sum * B_scan (point multiplication)
  // According to BIP-352: ecdh_shared_secret = input_hash * a_sum * B_scan
  // Multiply B_scan by a_sum (which is now input_hash * a_sum)
  secp256k1_pubkey shared_point = B_scan_point;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &shared_point, a_sum)) {
    secp256k1_context_destroy(ctx);
    return outputs;
  }
  // Serialize shared_point for hashing - must be uncompressed (65 bytes) per BIP-352
  unsigned char shared_point_bytes[33];
  size_t shared_point_len = 33;
  secp256k1_ec_pubkey_serialize(ctx, shared_point_bytes, &shared_point_len, &shared_point, SECP256K1_EC_COMPRESSED);
  // Parse B_m as secp256k1_pubkey
  secp256k1_pubkey B_m_point;
  if (!secp256k1_ec_pubkey_parse(ctx, &B_m_point, B_m.begin(), B_m.size())) {
    secp256k1_context_destroy(ctx);
    return outputs;
  }

  // For each output k, calculate: t_k = hash(shared_point || k), P_km = B_m + t_k * G
  // According to BIP-352: t_k = TaggedHash("BIP0352/SharedSecret", ecdh_shared_secret || k)
  // and P_km = B_m + t_k * G
  // TaggedHash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data)
  for (size_t i = 0; i < num_outputs; i++) {
    size_t k = starting_k + i;
    // TaggedHash("BIP0352/SharedSecret", shared_point || k)
    // First, compute SHA256(tag) where tag = "BIP0352/SharedSecret"
    const std::string tag = "BIP0352/SharedSecret";
    CSHA256 tag_hasher;
    tag_hasher.Write((const unsigned char*)tag.data(), tag.size());
    unsigned char tag_hash[32];
    tag_hasher.Finalize(tag_hash);
    
    // Now compute TaggedHash: SHA256(tag_hash || tag_hash || data)
    CSHA256 hasher;
    hasher.Write(tag_hash, 32);  // First SHA256(tag)
    hasher.Write(tag_hash, 32);  // Second SHA256(tag)
    hasher.Write(shared_point_bytes, 33);  // ecdh_shared_secret (uncompressed, 65 bytes)
    
    // Append k as 4-byte big-endian integer (ser_uint32)
    uint32_t k_be = htobe32_internal(static_cast<uint32_t>(k));
    hasher.Write((unsigned char*)&k_be, 4);  // k (4 bytes)
    
    uint256 t_k;
    hasher.Finalize(t_k.begin());
    // Check if t_k is 0 or >= curve order (improbable but must be handled per BIP-352)
    // Verify t_k is a valid private key (this checks if it's < curve order and != 0)
    unsigned char t_k_bytes[32];
    memcpy(t_k_bytes, t_k.begin(), 32);
    if (!secp256k1_ec_seckey_verify(ctx, t_k_bytes)) {
      // If t_k >= curve order or == 0, this is very rare, skip this output
      continue;
    }

    // Calculate t_k * G
    secp256k1_pubkey t_k_G;
    if (!secp256k1_ec_pubkey_create(ctx, &t_k_G, t_k_bytes)) {
      continue;
    }
    // Calculate P_km = B_m + t_k * G (according to BIP-352)
    const secp256k1_pubkey* pubkeys[2] = {&B_m_point, &t_k_G};
    secp256k1_pubkey P_km;
    if (!secp256k1_ec_pubkey_combine(ctx, &P_km, pubkeys, 2)) {
      continue;
    }
    // Convert to x-only pubkey for taproot
    // unsigned char P_km_bytes[33];
    // size_t P_km_len = 33;
    // secp256k1_ec_pubkey_serialize(ctx, P_km_bytes, &P_km_len, &P_km, SECP256K1_EC_COMPRESSED);
    // XOnlyPubKey xonly_pubkey(P_km_bytes);

    CPubKey result;
    size_t clen = CPubKey::SIZE;
    secp256k1_ec_pubkey_serialize(ctx, (unsigned char*)result.begin(), &clen, &P_km, SECP256K1_EC_COMPRESSED);
    XOnlyPubKey xonly_pubkey(result);

    if (!xonly_pubkey.IsNull()) {
      outputs.push_back(xonly_pubkey);
    }
  }
  
  secp256k1_context_destroy(ctx);
  return outputs;
}

// Create taproot address from x-only public key
inline std::string CreateTaprootAddress(const XOnlyPubKey& xonly_pubkey, nunchuk::Chain chain) {
  WitnessV1Taproot taproot(xonly_pubkey);
  return EncodeDestination(taproot);
}

// Encode Silent Payment address according to BIP-352
// Format: [version byte] + B_scan (33 bytes) + B_m (33 bytes) = 67 bytes total
inline std::string EncodeSilentPaymentAddress(const CPubKey& B_scan, const CPubKey& B_m, nunchuk::Chain chain, int version = 0) {
  if (!B_scan.IsValid() || !B_m.IsValid() || !B_scan.IsCompressed() || !B_m.IsCompressed()) {
    return "";
  }
  
  std::string hrp = (chain == nunchuk::Chain::MAIN) ? "sp" : "tsp";
  
  // Prepare data: version + B_scan + B_m
  std::vector<unsigned char> data_bytes;
  data_bytes.insert(data_bytes.end(), B_scan.begin(), B_scan.end());
  data_bytes.insert(data_bytes.end(), B_m.begin(), B_m.end());
  
  // Convert from 8-bit bytes to 5-bit groups
  std::vector<uint8_t> data_5bit;
  data_5bit.reserve((data_bytes.size() * 8 + 4) / 5);
  data_5bit.push_back(static_cast<unsigned char>(version));
  if (!ConvertBits<8, 5, true>([&](int v) { data_5bit.push_back(v); }, data_bytes.begin(), data_bytes.end())) {
    return "";
  }
  
  return bech32::Encode(bech32::Encoding::BECH32M, hrp, data_5bit);
}

}  // namespace

// Public API wrapper functions for use in other translation units
namespace nunchuk {
namespace silentpayment {

// Wrapper for SilentPaymentKeys
struct SilentPaymentKeys {
  CPubKey B_scan;
  CPubKey B_m;
  
  bool IsValid() const {
    return B_scan.IsValid() && B_m.IsValid();
  }
};

// Wrapper functions
inline bool IsSilentPaymentAddress(const std::string& address, Chain chain) {
  return ::IsSilentPaymentAddress(address, chain);
}

inline SilentPaymentKeys DecodeSilentPaymentAddress(const std::string& address, Chain chain) {
  auto keys = ::DecodeSilentPaymentAddress(address, chain);
  SilentPaymentKeys result;
  result.B_scan = keys.B_scan;
  result.B_m = keys.B_m;
  return result;
}

inline std::string EncodeSilentPaymentAddress(const CPubKey& B_scan, const CPubKey& B_m, Chain chain, int version = 0) {
  return ::EncodeSilentPaymentAddress(B_scan, B_m, chain, version);
}

inline std::vector<XOnlyPubKey> DeriveSilentPaymentOutputs(
    const CPubKey& B_scan,
    const CPubKey& B_m,
    const std::vector<CKey>& input_privkeys,
    const std::vector<UnspentOutput>& inputs,
    const std::vector<bool>& is_taproot_inputs,
    size_t num_outputs,
    size_t starting_k = 0) {
  return ::DeriveSilentPaymentOutputs(B_scan, B_m, input_privkeys, inputs, is_taproot_inputs, num_outputs, starting_k);
}

inline std::string CreateTaprootAddress(const XOnlyPubKey& xonly_pubkey, Chain chain) {
  return ::CreateTaprootAddress(xonly_pubkey, chain);
}

// Derive taproot recipient addresses for a set of Silent Payment recipients, grouped
// by B_scan with k incrementing across the group (BIP-352).
//
// Returns: map from original Silent Payment address -> derived taproot address.
// Non-silent-payment outputs are ignored.
inline std::map<std::string, std::string> DeriveSilentPaymentTaprootAddresses(
    const std::map<std::string, Amount>& outputs,
    Chain chain,
    const std::vector<UnspentOutput>& inputs,
    const std::vector<CKey>& input_privkeys,
    const std::vector<bool>& is_taproot_inputs) {
  std::map<std::string, std::string> derived_by_original;
  std::map<CPubKey, size_t> next_k_by_scan;

  for (const auto& output : outputs) {
    if (!::IsSilentPaymentAddress(output.first, chain)) continue;
    auto keys = ::DecodeSilentPaymentAddress(output.first, chain);
    if (!keys.IsValid()) continue;

    size_t k = next_k_by_scan[keys.B_scan]++;
    auto derived_outputs = ::DeriveSilentPaymentOutputs(
        keys.B_scan, keys.B_m, input_privkeys, inputs, is_taproot_inputs, 1, k);
    if (derived_outputs.empty()) continue;

    derived_by_original[output.first] =
        ::CreateTaprootAddress(derived_outputs[0], chain);
  }

  return derived_by_original;
}

}  // namespace silentpayment
}  // namespace nunchuk

#endif  // NUNCHUK_SILENTPAYMENT_H

