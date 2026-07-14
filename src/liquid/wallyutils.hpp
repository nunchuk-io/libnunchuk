/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (c) 2026 Enigmo.
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

#ifndef NUNCHUK_WALLYUTILS_HPP
#define NUNCHUK_WALLYUTILS_HPP
#define WALLY_DISABLE_OP_CODE

#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_crypto.h>
#include <wally_elements.h>
#include <wally_script.h>
#include <wally_transaction.h>
#include <wally_transaction_members.h>

#include <util/strencodings.h>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include <map>

#include <nunchuk.h>

template <typename T>
T&& check_wally_ret(T&& ret, const char* file, int line, const char* func) {
  if (ret != WALLY_OK) {
    throw std::runtime_error(std::string("Error in ") + func + " at line " +
                             std::to_string(line) + ": " + std::to_string(ret));
  }
  return std::forward<T>(ret);
}
#define CHECK_WALLY(ret) check_wally_ret(ret, __FILE__, __LINE__, __func__)

namespace nunchuk::wally {

struct WallyConstants {
  const char* ADDRESS_FAMILY;
  const char* CONFIDENTIAL_ADDRESS_FAMILY;
  std::vector<unsigned char> USDT_ASSET_ID;
  std::vector<unsigned char> LBTC_ASSET_ID;
};

class WallyUtils {
 public:
  static void Init() { CHECK_WALLY(wally_init(0)); }

  static void Cleanup() { CHECK_WALLY(wally_cleanup(0)); }

  static WallyConstants& C() {
    static WallyConstants mainnet{
        "ex",
        "lq",
        "d27ba36598fa8f2502aefffc9c3d76f16037ba1323631ab78bc7838b991c09ce"_hex_v_u8,
        "6d521c38ec1ea15734ae22b7c46064412829c0d0579f0a713d1c04ede979026f"_hex_v_u8,
    };

    static WallyConstants testnet{
        "tex",
        "tlq",
        "a5502895799e276b4af246c821423b4ed5ec5e6b4e6df7a861606939d9a2fc38"_hex_v_u8,
        "499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c14"_hex_v_u8,
    };

    switch (nunchuk::Utils::GetChain()) {
      case nunchuk::Chain::MAIN:
        return mainnet;
      case nunchuk::Chain::TESTNET:
      case nunchuk::Chain::SIGNET:
      case nunchuk::Chain::REGTEST:
      default:
        return testnet;
    }
  }

  static std::vector<unsigned char> RandomBytes(size_t n) {
    std::vector<unsigned char> out(n);
    std::random_device rd;
    for (size_t i = 0; i < n; i++) {
      out[i] = static_cast<unsigned char>(rd());
    }
    return out;
  }

  static std::vector<unsigned char> RandomEcPrivateKey() {
    for (;;) {
      auto k = RandomBytes(EC_PRIVATE_KEY_LEN);
      if (wally_ec_private_key_verify(k.data(), k.size()) == WALLY_OK) return k;
    }
  }

  static std::string HexFromBytes(const unsigned char* data, size_t len) {
    static const char* hexdigits = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; i++) {
      out[2 * i] = hexdigits[(data[i] >> 4) & 0xF];
      out[2 * i + 1] = hexdigits[data[i] & 0xF];
    }
    return out;
  }

  static std::string GetTxid(const std::string& txHex) {
    struct wally_tx* t = nullptr;
    CHECK_WALLY(wally_tx_from_hex(
        txHex.c_str(), WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS,
        &t));
    std::vector<unsigned char> id(32);
    CHECK_WALLY(wally_tx_get_txid(t, id.data(), id.size()));
    std::reverse(id.begin(), id.end());
    std::string txid = HexFromBytes(id.data(), id.size());
    wally_tx_free(t);
    return txid;
  }

  static std::vector<unsigned char> GetBlindingPubKeyFromConfidentialAddress(
      const std::string& confAddr) {
    std::vector<unsigned char> blinding_pubkey(EC_PUBLIC_KEY_LEN);
    CHECK_WALLY(wally_confidential_addr_segwit_to_ec_public_key(
        confAddr.c_str(), C().CONFIDENTIAL_ADDRESS_FAMILY,
        blinding_pubkey.data(), blinding_pubkey.size()));
    return blinding_pubkey;
  }

  static std::vector<unsigned char> GetScriptPubkeyFromConfidentialAddress(
      const std::string& confAddr) {
    char* addr = nullptr;
    CHECK_WALLY(wally_confidential_addr_to_addr_segwit(
        confAddr.c_str(), C().CONFIDENTIAL_ADDRESS_FAMILY, C().ADDRESS_FAMILY,
        &addr));

    std::vector<unsigned char> spk(128);
    size_t spk_len = 0;
    CHECK_WALLY(wally_addr_segwit_to_bytes(addr, C().ADDRESS_FAMILY, 0,
                                           spk.data(), spk.size(), &spk_len));
    spk.resize(spk_len);
    CHECK_WALLY(wally_free_string(addr));
    return spk;
  }

  static std::vector<unsigned char> GetScriptPubkeyFromAddress(
      const std::string& address) {
    std::vector<unsigned char> spk(128);
    size_t spk_len = 0;
    CHECK_WALLY(wally_addr_segwit_to_bytes(address.c_str(), C().ADDRESS_FAMILY,
                                           0, spk.data(), spk.size(),
                                           &spk_len));
    spk.resize(spk_len);
    return spk;
  }

  static std::string GetAddressFromScriptPubkey(
      const std::vector<unsigned char>& spk) {
    char* address = nullptr;
    CHECK_WALLY(wally_addr_segwit_from_bytes(spk.data(), spk.size(),
                                             C().ADDRESS_FAMILY, 0, &address));
    std::string rs = std::string(address);
    wally_free_string(address);
    return rs;
  }
};
}  // namespace nunchuk::wally

#endif