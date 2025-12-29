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

// Decode Silent Payment address to public key
// Returns empty CPubKey if invalid
inline CPubKey DecodeSilentPaymentAddress(const std::string& address, nunchuk::Chain chain) {
  std::string expected_hrp = (chain == nunchuk::Chain::MAIN) ? "sp" : "tsp";
  
  auto dec = bech32::Decode(address);
  if (dec.encoding != bech32::Encoding::BECH32M || dec.hrp != expected_hrp) {
    return CPubKey();
  }
  
  if (dec.data.empty()) {
    return CPubKey();
  }
  
  // Convert from 5-bit groups to bytes
  std::vector<unsigned char> data_bytes;
  data_bytes.reserve(((dec.data.size() - 1) * 5) / 8);
  if (!ConvertBits<5, 8, false>([&](unsigned char c) { data_bytes.push_back(c); }, dec.data.begin() + 1, dec.data.end())) {
    return CPubKey();
  }
  
  // Silent Payment address should contain a 33-byte public key
  if (data_bytes.size() != 33) {
    return CPubKey();
  }
  
  CPubKey pubkey(data_bytes);
  if (!pubkey.IsValid()) {
    return CPubKey();
  }
  
  return pubkey;
}

// Calculate input hash according to BIP-352
// input_hash = hash(outpoint_L || (a_sum·G))
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
  std::vector<std::pair<uint256, uint32_t>> outpoints;
  for (const auto& input : inputs) {
    uint256 txid;
    txid.SetHexDeprecated(input.get_txid());
    outpoints.push_back({txid, input.get_vout()});
  }
  
  // Sort to find smallest outpoint (compare txid first, then vout)
  std::sort(outpoints.begin(), outpoints.end(), 
    [](const std::pair<uint256, uint32_t>& a, const std::pair<uint256, uint32_t>& b) {
      // Compare txid (uint256 comparison)
      for (int i = 31; i >= 0; i--) {
        if (a.first.begin()[i] < b.first.begin()[i]) return true;
        if (a.first.begin()[i] > b.first.begin()[i]) return false;
      }
      // If txids are equal, compare vout (little-endian)
      return a.second < b.second;
    });
  
  const auto& outpoint_L = outpoints[0];
  
  // Hash: input_hash = hash(outpoint_L || (a_sum·G))
  CSHA256 hasher;
  // Serialize outpoint_L: txid (32 bytes) + vout (4 bytes, little-endian)
  hasher.Write(outpoint_L.first.begin(), 32);
  hasher.Write((unsigned char*)&outpoint_L.second, 4);
  
  // Serialize sum public key (a_sum·G) - compressed, 33 bytes
  hasher.Write(sum_pubkey.begin(), 33);
  
  uint256 result;
  hasher.Finalize(result.begin());
  return result;
}

// Derive Silent Payment output public keys according to BIP-352
// Returns vector of derived output public keys (taproot x-only pubkeys)
inline std::vector<XOnlyPubKey> DeriveSilentPaymentOutputs(
    const CPubKey& B,  // Silent Payment address public key
    const std::vector<CKey>& input_privkeys,  // Input private keys
    const std::vector<CPubKey>& input_pubkeys,  // Input public keys
    const std::vector<nunchuk::UnspentOutput>& inputs,
    size_t num_outputs) {
  std::vector<XOnlyPubKey> outputs;
  
  if (!B.IsValid() || input_privkeys.empty() || input_pubkeys.empty() || 
      inputs.empty() || num_outputs == 0 ||
      input_privkeys.size() != input_pubkeys.size() ||
      inputs.size() != input_pubkeys.size()) {
    return outputs;
  }
  
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  
  // Calculate sum of input private keys: a_sum = sum(a_i) mod n
  // Use secp256k1_ec_privkey_tweak_add to sum private keys
  unsigned char a_sum[32] = {0};
  bool first_key = true;
  for (const auto& key : input_privkeys) {
    if (!key.IsValid()) {
      secp256k1_context_destroy(ctx);
      return outputs;
    }
    if (first_key) {
      // First key: copy directly
      const std::byte* key_data = key.data();
      memcpy(a_sum, reinterpret_cast<const unsigned char*>(key_data), 32);
      first_key = false;
    } else {
      // Subsequent keys: add using tweak_add
      const std::byte* key_data = key.data();
      if (!secp256k1_ec_privkey_tweak_add(ctx, a_sum, reinterpret_cast<const unsigned char*>(key_data))) {
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
  
  // Serialize sum public key
  unsigned char sum_pubkey_bytes[33];
  size_t sum_pubkey_len = 33;
  secp256k1_ec_pubkey_serialize(ctx, sum_pubkey_bytes, &sum_pubkey_len, &sum_pubkey_point, SECP256K1_EC_COMPRESSED);
  CPubKey sum_pubkey(sum_pubkey_bytes);
  
  // Check if a_sum is zero (should fail per BIP-352)
  // This is already checked by secp256k1_ec_seckey_verify and secp256k1_ec_pubkey_create above
  // If sum_pubkey is invalid, we've already returned
  
  // Calculate input_hash = hash(outpoint_L || (a_sum·G))
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
  
  // Parse B as secp256k1_pubkey
  secp256k1_pubkey B_point;
  if (!secp256k1_ec_pubkey_parse(ctx, &B_point, B.begin(), B.size())) {
    secp256k1_context_destroy(ctx);
    return outputs;
  }
  
  // Calculate shared_point = input_hash * a_sum * B (point multiplication)
  // Multiply B by a_sum (which is now input_hash * a_sum)
  secp256k1_pubkey shared_point = B_point;
  if (!secp256k1_ec_pubkey_tweak_mul(ctx, &shared_point, a_sum)) {
    secp256k1_context_destroy(ctx);
    return outputs;
  }
  
  // Serialize shared_point for hashing
  unsigned char shared_point_bytes[33];
  size_t shared_point_len = 33;
  secp256k1_ec_pubkey_serialize(ctx, shared_point_bytes, &shared_point_len, &shared_point, SECP256K1_EC_COMPRESSED);
  
  // For each output k, calculate: t_k = hash(shared_point || k), P_k = B + t_k * G
  for (size_t k = 0; k < num_outputs; k++) {
    // Hash: SHA256(shared_point || k) where k is 32-byte big-endian
    CSHA256 hasher;
    hasher.Write(shared_point_bytes, 33);
    
    // Append k as 32-byte big-endian integer
    unsigned char k_bytes[32] = {0};
    uint32_t k_be = htobe32(static_cast<uint32_t>(k));
    memcpy(k_bytes + 28, &k_be, 4);
    hasher.Write(k_bytes, 32);
    
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
    
    // Calculate P_k = B + t_k * G
    const secp256k1_pubkey* pubkeys[2] = {&B_point, &t_k_G};
    secp256k1_pubkey P_k;
    if (!secp256k1_ec_pubkey_combine(ctx, &P_k, pubkeys, 2)) {
      continue;
    }
    
    // Convert to x-only pubkey for taproot
    unsigned char P_k_bytes[33];
    size_t P_k_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, P_k_bytes, &P_k_len, &P_k, SECP256K1_EC_COMPRESSED);
    
    XOnlyPubKey xonly_pubkey(P_k_bytes);
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

}  // namespace

#endif  // NUNCHUK_SILENTPAYMENT_H

