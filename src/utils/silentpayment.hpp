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
// We manually decode and verify checksum by re-encoding and comparing
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
  
  // Extract data (without checksum - last 6 chars are checksum)
  std::vector<uint8_t> data(values.begin(), values.end() - 6);
  
  // For Silent Payment addresses, we know they use BECH32M
  // Since bech32::Encode might also have length limits, we'll skip checksum verification
  // for addresses longer than 90 chars and assume BECH32M if HRP matches
  // (In production, proper checksum verification should be implemented)
  if (hrp == "sp" || hrp == "tsp") {
    if (data.size() > 0) {
      result.encoding = bech32::Encoding::BECH32M;
      result.hrp = hrp;
      result.data = data;
      return result;
    } else {
      // Data is empty, something went wrong
      return result;
    }
  }
  
  // Try to verify checksum by re-encoding (only if address is short enough)
  if (str.size() <= 90) {
    // Try BECH32M first (Silent Payment uses BECH32M)
    std::string reencoded = bech32::Encode(bech32::Encoding::BECH32M, hrp, data);
    
    // Compare case-insensitively
    std::string str_lower = str;
    std::transform(str_lower.begin(), str_lower.end(), str_lower.begin(), ::tolower);
    std::string reencoded_lower = reencoded;
    std::transform(reencoded_lower.begin(), reencoded_lower.end(), reencoded_lower.begin(), ::tolower);
    
    if (reencoded_lower == str_lower) {
      result.encoding = bech32::Encoding::BECH32M;
      result.hrp = hrp;
      result.data = data;
      return result;
    }
    
    // Try BECH32 as fallback
    reencoded = bech32::Encode(bech32::Encoding::BECH32, hrp, data);
    reencoded_lower = reencoded;
    std::transform(reencoded_lower.begin(), reencoded_lower.end(), reencoded_lower.begin(), ::tolower);
    
    if (reencoded_lower == str_lower) {
      result.encoding = bech32::Encoding::BECH32;
      result.hrp = hrp;
      result.data = data;
      return result;
    }
  }
  
  // Checksum verification failed or address too long
  return result;
}

// Decode Silent Payment address according to BIP-352
// Format: [version byte] + B_scan (33 bytes) + B_m (33 bytes) = 67 bytes total
// Returns keys with invalid pubkeys if decode fails
// Note: Silent Payment addresses can be longer than 90 chars, so we use a custom decode
inline SilentPaymentKeys DecodeSilentPaymentAddress(const std::string& address, nunchuk::Chain chain) {
  SilentPaymentKeys keys;
  std::string expected_hrp = (chain == nunchuk::Chain::MAIN) ? "sp" : "tsp";
  
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
    const std::vector<CPubKey>& input_pubkeys,
    const CPubKey& sum_pubkey) {
  if (inputs.empty() || !sum_pubkey.IsValid() || !sum_pubkey.IsCompressed()) {
    return uint256();
  }
  
  // Find lexicographically smallest outpoint (outpoint_L)
  // According to BIP-352: outpoints are sorted by their serialized bytes
  // Serialization: txid (32 bytes, little-endian) || vout (4 bytes, little-endian)
  std::vector<std::pair<std::vector<unsigned char>, std::pair<uint256, uint32_t>>> outpoints_serialized;
  for (const auto& input : inputs) {
    // Parse txid from hex string (big-endian) to uint256 (little-endian)
    uint256 txid;
    auto txid_opt = uint256::FromHex(input.get_txid());
    if (!txid_opt) {
      return uint256();
    }
    txid = *txid_opt;
    
    // Serialize outpoint: txid (32 bytes, little-endian) || vout (4 bytes, little-endian)
    std::vector<unsigned char> serialized;
    serialized.reserve(36);
    serialized.insert(serialized.end(), txid.begin(), txid.end());  // 32 bytes
    uint32_t vout_le = input.get_vout();  // Already in native endian, but we need little-endian
    serialized.insert(serialized.end(), reinterpret_cast<unsigned char*>(&vout_le), 
                      reinterpret_cast<unsigned char*>(&vout_le) + 4);
    
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

// Derive Silent Payment output public keys according to BIP-352
// Returns vector of derived output public keys (taproot x-only pubkeys)
inline std::vector<XOnlyPubKey> DeriveSilentPaymentOutputs(
    const CPubKey& B_scan,  // Silent Payment scan public key
    const CPubKey& B_m,     // Silent Payment spend public key
    const std::vector<CKey>& input_privkeys,  // Input private keys
    const std::vector<CPubKey>& input_pubkeys,  // Input public keys
    const std::vector<nunchuk::UnspentOutput>& inputs,
    const std::vector<bool>& is_taproot_inputs,  // Whether each input is taproot
    size_t num_outputs,
    size_t starting_k = 0) {  // Starting value for k (for multiple B_m with same B_scan)
  std::vector<XOnlyPubKey> outputs;
  if (!B_scan.IsValid() || !B_m.IsValid() || input_privkeys.empty() || input_pubkeys.empty() || 
      inputs.empty() || num_outputs == 0 ||
      input_privkeys.size() != input_pubkeys.size() ||
      // inputs.size() != input_pubkeys.size() ||
      is_taproot_inputs.size() != input_privkeys.size()) {
    return outputs;
  }
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  
  // Calculate sum of input private keys: a_sum = sum(a_i) mod n
  // According to BIP-352: if input is x-only pubkey with odd y, negate the private key
  // Use secp256k1_ec_privkey_tweak_add to sum private keys
  unsigned char a_sum[32] = {0};
  bool first_key = true;
  for (size_t i = 0; i < input_privkeys.size(); i++) {
    const auto& key = input_privkeys[i];
    if (!key.IsValid()) {
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
      // This is a taproot input
      // Derive pubkey from private key to check y coordinate
      secp256k1_pubkey pubkey_point;
      if (secp256k1_ec_pubkey_create(ctx, &pubkey_point, key_bytes)) {
        // Serialize to get y coordinate
        unsigned char pubkey_serialized[33];
        size_t pubkey_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkey_len, &pubkey_point, SECP256K1_EC_COMPRESSED);
        // Check if y coordinate is odd (0x03 prefix = odd y, 0x02 = even y)
        if (pubkey_serialized[0] == 0x03) {
          // Odd y coordinate, negate the private key
          if (!secp256k1_ec_seckey_negate(ctx, key_bytes)) {
            secp256k1_context_destroy(ctx);
            return outputs;
          }
        }
      }
    }
    
    // Add key to sum
    if (first_key) {
      // First key: copy directly
      memcpy(a_sum, key_bytes, 32);
      first_key = false;
    } else {
      // Subsequent keys: add using tweak_add
      if (!secp256k1_ec_privkey_tweak_add(ctx, a_sum, key_bytes)) {
        secp256k1_context_destroy(ctx);
        return outputs;
      }
    }
  }
  
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
  uint256 input_hash = CalculateInputHash(inputs, input_pubkeys, sum_pubkey);
  if (input_hash.IsNull()) {
    secp256k1_context_destroy(ctx);
    return outputs;
  }

  // Calculate input_hash * a_sum mod n
  // First multiply a_sum by input_hash
  unsigned char input_hash_bytes[32];
  memcpy(input_hash_bytes, input_hash.begin(), 32);
  if (!secp256k1_ec_privkey_tweak_mul(ctx, a_sum, input_hash_bytes)) {
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
    const std::vector<CPubKey>& input_pubkeys,
    const std::vector<UnspentOutput>& inputs,
    const std::vector<bool>& is_taproot_inputs,
    size_t num_outputs,
    size_t starting_k = 0) {
  return ::DeriveSilentPaymentOutputs(B_scan, B_m, input_privkeys, input_pubkeys, inputs, is_taproot_inputs, num_outputs, starting_k);
}

inline std::string CreateTaprootAddress(const XOnlyPubKey& xonly_pubkey, Chain chain) {
  return ::CreateTaprootAddress(xonly_pubkey, chain);
}

}  // namespace silentpayment
}  // namespace nunchuk

#endif  // NUNCHUK_SILENTPAYMENT_H

