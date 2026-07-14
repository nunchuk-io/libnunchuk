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

#ifndef NUNCHUK_WALLY_SIGNER_HPP
#define NUNCHUK_WALLY_SIGNER_HPP

#include <liquid/wallyutils.hpp>

#include <util/bip32.h>
#include <util/strencodings.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include <map>

namespace nunchuk::wally {

struct LiquidUtxos {
  std::vector<unsigned char> tx_id;                // 32 bytes (internal order)
  std::vector<unsigned char> asset_generators_in;  // 33*num
  std::vector<unsigned char> asset_ids_in;         // 32*num
  std::vector<uint64_t> values_in;                 // satoshis
  std::vector<unsigned char> abfs_in;              // 32*num
  std::vector<unsigned char> vbfs_in;              // 32*num
  std::vector<std::vector<unsigned char>> script_pubkeys_in;
  std::vector<std::vector<unsigned char>>
      value_commitments_in;  // 33 bytes each
  std::vector<uint32_t> vouts_in;
  std::vector<std::vector<unsigned char>> vins_tx_id;
  std::vector<uint32_t> vins_vout;
};

struct AddressDetail {
  std::vector<uint32_t> keypath;  // full path from master to signing key
  uint32_t index;                 // leaf index (equals keypath.back())
  std::string address;
  bool isChange;
};

class WallySigner {
 private:
  struct ext_key* master_{nullptr};
  std::vector<unsigned char> master_blinding_key_;
  std::map<std::vector<unsigned char>, AddressDetail> spk_;
  uint32_t tx_flags_ = WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS;

  using PrevoutSpendData =
      std::pair<std::vector<unsigned char>, std::vector<unsigned char>>;

  static std::string MakePrevoutMapKey(const unsigned char* txid,
                                       uint32_t vout) {
    std::string k(reinterpret_cast<const char*>(txid), WALLY_TXHASH_LEN);
    k.push_back(static_cast<char>(vout & 0xff));
    k.push_back(static_cast<char>((vout >> 8) & 0xff));
    k.push_back(static_cast<char>((vout >> 16) & 0xff));
    k.push_back(static_cast<char>((vout >> 24) & 0xff));
    return k;
  }

  static std::map<std::string, PrevoutSpendData> BuildPrevoutSpendDataMap(
      const std::vector<LiquidUtxos>& inputs) {
    std::map<std::string, PrevoutSpendData> m;
    for (const auto& u : inputs) {
      if (u.tx_id.size() != WALLY_TXHASH_LEN) {
        throw std::runtime_error(
            "LiquidUtxos.tx_id must be WALLY_TXHASH_LEN (32) bytes");
      }
      const size_t n = u.vouts_in.size();
      if (u.script_pubkeys_in.size() != n ||
          u.value_commitments_in.size() != n) {
        throw std::runtime_error(
            "LiquidUtxos script_pubkeys_in/value_commitments_in must match "
            "vouts_in length");
      }
      for (size_t k = 0; k < n; ++k) {
        std::string key = MakePrevoutMapKey(u.tx_id.data(), u.vouts_in[k]);
        PrevoutSpendData val{u.script_pubkeys_in[k], u.value_commitments_in[k]};
        auto [it, inserted] = m.emplace(key, std::move(val));
        if (!inserted) {
          if (it->second.first != u.script_pubkeys_in[k] ||
              it->second.second != u.value_commitments_in[k]) {
            throw std::runtime_error(
                "Conflicting LiquidUtxos entries for the same prevout");
          }
        }
      }
    }
    return m;
  }

  void SignTxInPlace(
      struct wally_tx* tx,
      const std::vector<std::vector<unsigned char>>& script_pubkeys_in,
      const std::vector<std::vector<unsigned char>>& value_commitments_in) {
    if (tx == nullptr) throw std::runtime_error("SignTxInPlace: tx is null");

    size_t num_inputs = 0;
    CHECK_WALLY(wally_tx_get_num_inputs(tx, &num_inputs));

    if (script_pubkeys_in.size() != num_inputs ||
        value_commitments_in.size() != num_inputs) {
      throw std::runtime_error(
          "SignTxInPlace: script_pubkeys_in/value_commitments_in size mismatch "
          "with tx inputs");
    }

    for (size_t vin = 0; vin < num_inputs; vin++) {
      const auto& utxo_script = script_pubkeys_in[vin];
      if (!spk_.contains(utxo_script)) {
        throw std::runtime_error("Signing key not found");
      }
      const auto& detail = spk_.at(utxo_script);
      const auto& [signingPrivKey, signingPubKey] =
          GetSigningKey(detail.keypath);
      std::vector<unsigned char> pubkeyhash(HASH160_LEN);
      CHECK_WALLY(wally_hash160(signingPubKey.data(), signingPubKey.size(),
                                pubkeyhash.data(), pubkeyhash.size()));
      // P2WPKH scriptPubKey: OP_0 PUSH20 <hash160(pubkey)>
      if (utxo_script.size() != 2 + HASH160_LEN || utxo_script[0] != 0x00 ||
          utxo_script[1] != HASH160_LEN ||
          std::memcmp(utxo_script.data() + 2, pubkeyhash.data(), HASH160_LEN) !=
              0) {
        throw std::runtime_error(
            "Signing key does not match input scriptPubKey");
      }

      std::vector<unsigned char> script_code(256);
      size_t script_code_len = 0;
      CHECK_WALLY(wally_scriptpubkey_p2pkh_from_bytes(
          pubkeyhash.data(), pubkeyhash.size(), 0, script_code.data(),
          script_code.size(), &script_code_len));
      script_code.resize(script_code_len);

      std::vector<unsigned char> sighash(SHA256_LEN);
      const auto& prevout_value = value_commitments_in[vin];  // 33 bytes
      CHECK_WALLY(wally_tx_get_elements_signature_hash(
          tx, vin, script_code.data(), script_code.size(), prevout_value.data(),
          prevout_value.size(), WALLY_SIGHASH_ALL, WALLY_TX_FLAG_USE_WITNESS,
          sighash.data(), sighash.size()));

      std::vector<unsigned char> sig64(EC_SIGNATURE_LEN);
      CHECK_WALLY(wally_ec_sig_from_bytes(
          signingPrivKey.data(), signingPrivKey.size(), sighash.data(),
          sighash.size(), EC_FLAG_ECDSA, sig64.data(), sig64.size()));

      CHECK_WALLY(wally_ec_sig_verify(
          signingPubKey.data(), signingPubKey.size(), sighash.data(),
          sighash.size(), EC_FLAG_ECDSA, sig64.data(), sig64.size()));

      size_t sig_der_len = 0;
      std::vector<unsigned char> sig_der(EC_SIGNATURE_DER_MAX_LEN);
      CHECK_WALLY(wally_ec_sig_to_der(sig64.data(), sig64.size(),
                                      sig_der.data(), sig_der.size(),
                                      &sig_der_len));
      sig_der.resize(sig_der_len);
      sig_der.push_back(static_cast<unsigned char>(WALLY_SIGHASH_ALL));

      struct wally_tx_witness_stack* wit = nullptr;
      CHECK_WALLY(wally_tx_witness_stack_init_alloc(2, &wit));
      CHECK_WALLY(
          wally_tx_witness_stack_add(wit, sig_der.data(), sig_der.size()));
      CHECK_WALLY(wally_tx_witness_stack_add(wit, signingPubKey.data(),
                                             signingPubKey.size()));
      CHECK_WALLY(wally_tx_set_input_witness(tx, vin, wit));
      wally_tx_witness_stack_free(wit);
    }
  }

 public:
  WallySigner(const std::string& mnemonic, const std::string& passphrase) {
    WallyUtils::Init();
    std::vector<unsigned char> seed(BIP39_SEED_LEN_512);
    CHECK_WALLY(bip39_mnemonic_to_seed512(mnemonic.c_str(), passphrase.c_str(),
                                          seed.data(), seed.size()));
    const uint32_t bip32_ver = (Utils::GetChain() == Chain::MAIN)
                                   ? BIP32_VER_MAIN_PRIVATE
                                   : BIP32_VER_TEST_PRIVATE;
    CHECK_WALLY(bip32_key_from_seed_alloc(seed.data(), seed.size(), bip32_ver,
                                          0, &master_));
    master_blinding_key_.resize(HMAC_SHA512_LEN);
    CHECK_WALLY(wally_asset_blinding_key_from_seed(
        seed.data(), seed.size(), master_blinding_key_.data(),
        master_blinding_key_.size()));
  }

  WallySigner(const WallySigner&) = delete;
  WallySigner& operator=(const WallySigner&) = delete;

  WallySigner(WallySigner&& other) noexcept
      : master_(other.master_),
        master_blinding_key_(std::move(other.master_blinding_key_)),
        spk_(std::move(other.spk_)),
        tx_flags_(other.tx_flags_) {
    other.master_ = nullptr;
  }

  WallySigner& operator=(WallySigner&& other) noexcept {
    if (this == &other) return *this;
    bip32_key_free(master_);
    master_ = other.master_;
    other.master_ = nullptr;
    master_blinding_key_ = std::move(other.master_blinding_key_);
    spk_ = std::move(other.spk_);
    tx_flags_ = other.tx_flags_;
    return *this;
  }

  ~WallySigner() { bip32_key_free(master_); }

  std::string GetMasterFingerprint() const {
    std::vector<unsigned char> fingerprint(BIP32_KEY_FINGERPRINT_LEN);
    CHECK_WALLY(bip32_key_get_fingerprint(master_, fingerprint.data(),
                                          fingerprint.size()));
    return WallyUtils::HexFromBytes(fingerprint.data(), fingerprint.size());
  }

  std::vector<AddressDetail> CacheAddresses(const std::string& path,
                                            uint32_t start_index,
                                            uint32_t end_index,
                                            bool is_change) {
    std::vector<uint32_t> keypath;
    std::string formalized = path;
    std::replace(formalized.begin(), formalized.end(), 'h', '\'');
    if (!ParseHDKeypath(formalized, keypath)) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid hd keypath");
    }
    keypath.push_back(is_change ? 1u : 0u);
    std::vector<AddressDetail> rs{};
    for (uint32_t index = start_index; index < end_index; index++) {
      keypath.push_back(index);
      std::string address = GetAddress(keypath);
      std::string confidential_address =
          GetConfidentialAddressFromAddress(address);
      AddressDetail detail{keypath, index, confidential_address, is_change};
      rs.push_back(detail);
      spk_.emplace(WallyUtils::GetScriptPubkeyFromAddress(address), detail);
      keypath.pop_back();
    }
    return rs;
  }

  std::string GetAddress(const std::vector<uint32_t>& keypath) {
    struct ext_key* derived = nullptr;
    CHECK_WALLY(bip32_key_from_parent_path_alloc(
        master_, keypath.data(), keypath.size(), BIP32_FLAG_KEY_PRIVATE,
        &derived));
    char* address = nullptr;
    CHECK_WALLY(wally_bip32_key_to_addr_segwit(
        derived, WallyUtils::C().ADDRESS_FAMILY, 0, &address));
    std::string rs = std::string(address);
    wally_free_string(address);
    bip32_key_free(derived);
    return rs;
  }

  std::string GetConfidentialAddress(const std::vector<uint32_t>& path) {
    return GetConfidentialAddressFromAddress(GetAddress(path));
  }

  // Convert a segwit (non-confidential) address belonging to this wallet to
  // its confidential address by deriving its blinding pubkey.
  std::string GetConfidentialAddressFromAddress(const std::string& address) {
    std::vector<unsigned char> script_pubkey =
        WallyUtils::GetScriptPubkeyFromAddress(address);
    std::vector<unsigned char> private_blinding_key =
        GetBlindingKey(script_pubkey);

    std::vector<unsigned char> public_blinding_key(EC_PUBLIC_KEY_LEN);
    CHECK_WALLY(wally_ec_public_key_from_private_key(
        private_blinding_key.data(), private_blinding_key.size(),
        public_blinding_key.data(), public_blinding_key.size()));

    char* conf_address = nullptr;
    CHECK_WALLY(wally_confidential_addr_from_addr_segwit(
        address.c_str(), WallyUtils::C().ADDRESS_FAMILY,
        WallyUtils::C().CONFIDENTIAL_ADDRESS_FAMILY, public_blinding_key.data(),
        public_blinding_key.size(), &conf_address));
    std::string rs = std::string(conf_address);
    wally_free_string(conf_address);
    return rs;
  }

  std::vector<unsigned char> GetBlindingKey(
      const std::vector<unsigned char>& spk) {
    std::vector<unsigned char> private_blinding_key(EC_PRIVATE_KEY_LEN);
    CHECK_WALLY(wally_asset_blinding_key_to_ec_private_key(
        master_blinding_key_.data(), master_blinding_key_.size(), spk.data(),
        spk.size(), private_blinding_key.data(), private_blinding_key.size()));
    return private_blinding_key;
  }

  std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
  GetSigningKey(const std::vector<uint32_t>& keypath) {
    if (keypath.empty()) {
      throw std::runtime_error("GetSigningKey: empty keypath");
    }
    struct ext_key* derived = nullptr;
    CHECK_WALLY(bip32_key_from_parent_path_alloc(
        master_, keypath.data(), keypath.size(), BIP32_FLAG_KEY_PRIVATE,
        &derived));

    std::vector<unsigned char> signing_priv_key(EC_PRIVATE_KEY_LEN);
    std::memcpy(signing_priv_key.data(), derived->priv_key + 1,
                EC_PRIVATE_KEY_LEN);
    std::vector<unsigned char> signing_pub_key(EC_PUBLIC_KEY_LEN);
    CHECK_WALLY(wally_ec_public_key_from_private_key(
        signing_priv_key.data(), signing_priv_key.size(),
        signing_pub_key.data(), signing_pub_key.size()));
    bip32_key_free(derived);
    return {signing_priv_key, signing_pub_key};
  }

  Transaction GetTransactionFromTx(const std::string& txHex, int height) {
    struct wally_tx* tx{nullptr};
    CHECK_WALLY(wally_tx_from_hex(txHex.c_str(), tx_flags_, &tx));
    std::vector<unsigned char> txid(32);
    CHECK_WALLY(wally_tx_get_txid(tx, txid.data(), txid.size()));
    std::reverse(txid.begin(), txid.end());

    Transaction rs;
    rs.set_txid(WallyUtils::HexFromBytes(txid.data(), txid.size()));
    rs.set_height(height);
    rs.set_lock_time(tx->locktime);
    rs.set_raw(txHex);
    bool all_signed = true;
    for (size_t vin = 0; vin < tx->num_inputs; vin++) {
      const auto& txin = tx->inputs[vin];
      std::vector<unsigned char> vin_txid(txin.txhash,
                                          txin.txhash + WALLY_TXHASH_LEN);
      std::reverse(vin_txid.begin(), vin_txid.end());
      std::string vin_txid_str =
          WallyUtils::HexFromBytes(vin_txid.data(), vin_txid.size());
      rs.add_input({vin_txid_str, txin.index, txin.sequence});
      size_t items = 0;
      CHECK_WALLY(wally_tx_get_input_witness_num_items(tx, vin, &items));
      if (items == 0) all_signed = false;
    }
    uint64_t explicit_fee_sats = 0;
    for (size_t vout = 0; vout < tx->num_outputs; vout++) {
      const auto& txout = tx->outputs[vout];
      if (IsExplicitLbtcFeeOutput(txout)) {
        uint64_t fee_out = 0;
        CHECK_WALLY(wally_tx_confidential_value_to_satoshi(
            txout.value, txout.value_len, &fee_out));
        explicit_fee_sats += fee_out;
        continue;
      }
      std::vector<unsigned char> script(txout.script,
                                        txout.script + txout.script_len);
      if (!spk_.contains(script)) {
        TxOutput output{WallyUtils::GetAddressFromScriptPubkey(script), 0};
        output.isChange = false;
        output.isReceive = false;
        output.vout = static_cast<uint32_t>(vout);
        rs.add_output(output);
        continue;
      }
      auto privateBlindingKey = GetBlindingKey(script);

      std::vector<unsigned char> nonce(txout.nonce,
                                       txout.nonce + txout.nonce_len);
      std::vector<unsigned char> rangeproof(
          txout.rangeproof, txout.rangeproof + txout.rangeproof_len);
      std::vector<unsigned char> asset_commitment(
          txout.asset, txout.asset + txout.asset_len);
      std::vector<unsigned char> value_commitment_from_tx(
          txout.value, txout.value + txout.value_len);

      // Unblind using the output nonce (ephemeral pubkey), rangeproof,
      // value+asset commitments
      std::vector<unsigned char> asset_out(ASSET_TAG_LEN);
      std::vector<unsigned char> abf_out(BLINDING_FACTOR_LEN);
      std::vector<unsigned char> vbf_out(BLINDING_FACTOR_LEN);
      uint64_t value_out = 0;

      CHECK_WALLY(wally_asset_unblind(
          nonce.data(), nonce.size(), privateBlindingKey.data(),
          privateBlindingKey.size(), rangeproof.data(), rangeproof.size(),
          value_commitment_from_tx.data(), value_commitment_from_tx.size(),
          script.data(), script.size(), asset_commitment.data(),
          asset_commitment.size(), asset_out.data(), asset_out.size(),
          abf_out.data(), abf_out.size(), vbf_out.data(), vbf_out.size(),
          &value_out));

      std::vector<unsigned char> asset_id(asset_out.begin(), asset_out.end());
      std::vector<unsigned char> asset_generator(ASSET_GENERATOR_LEN);
      CHECK_WALLY(wally_asset_generator_from_bytes(
          asset_id.data(), asset_id.size(), abf_out.data(), abf_out.size(),
          asset_generator.data(), asset_generator.size()));
      if (asset_commitment != asset_generator) {
        wally_tx_free(tx);
        throw std::runtime_error(
            "asset_generator mismatch with asset_commitment");
      }

      // Recompute and sanity-check value commitment
      std::vector<unsigned char> recomputed_value_commitment(
          ASSET_COMMITMENT_LEN);
      CHECK_WALLY(wally_asset_value_commitment(
          value_out, vbf_out.data(), vbf_out.size(), asset_generator.data(),
          asset_generator.size(), recomputed_value_commitment.data(),
          recomputed_value_commitment.size()));
      if (value_commitment_from_tx != recomputed_value_commitment) {
        wally_tx_free(tx);
        throw std::runtime_error(
            "value_commitment mismatch: unblind factors don't recompute "
            "original commitment");
      }

      AddressDetail address_detail = spk_[script];
      TxOutput output{address_detail.address, Amount(value_out)};
      output.isChange = address_detail.isChange;
      output.isReceive = true;
      output.assetId = AssetId(asset_id.begin(), asset_id.end());
      output.vout = static_cast<uint32_t>(vout);
      rs.add_output(output);
    }
    if (explicit_fee_sats > 0) {
      const size_t vsize =
          all_signed ? ComputeVsizeFromTx(tx) : ComputeSignedVsize(txHex);
      rs.set_fee(Amount(explicit_fee_sats));
      rs.set_vsize(static_cast<int>(vsize));
      if (vsize > 0) {
        rs.set_fee_rate(Amount(explicit_fee_sats * 1000 / vsize));
      }
    }
    if (height == 0) {
      rs.set_status(TransactionStatus::PENDING_CONFIRMATION);
    } else if (height == -2) {
      rs.set_status(TransactionStatus::NETWORK_REJECTED);
    } else if (height == -1) {
      rs.set_status(all_signed ? TransactionStatus::READY_TO_BROADCAST
                               : TransactionStatus::PENDING_SIGNATURES);
    } else if (height > 0) {
      rs.set_status(TransactionStatus::CONFIRMED);
    }

    wally_tx_free(tx);
    return rs;
  }

  // Synthetic LBTC UTXO for fee estimation (e.g. when LBTC cannot cover the fee).
  LiquidUtxos MakeDummyLbtcUtxo(uint64_t value) const {
    if (spk_.empty()) {
      throw std::runtime_error("No wallet addresses available for dummy UTXO");
    }
    const auto& LBTC = WallyUtils::C().LBTC_ASSET_ID;
    LiquidUtxos u;
    u.tx_id = WallyUtils::RandomBytes(WALLY_TXHASH_LEN);
    u.vouts_in = {0};
    u.asset_ids_in.assign(LBTC.begin(), LBTC.end());
    u.values_in = {std::max<uint64_t>(value, 1)};
    u.abfs_in = WallyUtils::RandomBytes(32);
    u.vbfs_in = WallyUtils::RandomBytes(32);
    u.asset_generators_in.resize(ASSET_GENERATOR_LEN);
    CHECK_WALLY(wally_asset_generator_from_bytes(
        u.asset_ids_in.data(), u.asset_ids_in.size(), u.abfs_in.data(),
        u.abfs_in.size(), u.asset_generators_in.data(),
        u.asset_generators_in.size()));
    u.script_pubkeys_in = {spk_.begin()->first};
    u.value_commitments_in.resize(1);
    u.value_commitments_in[0].resize(ASSET_COMMITMENT_LEN);
    CHECK_WALLY(wally_asset_value_commitment(
        u.values_in[0], u.vbfs_in.data(), u.vbfs_in.size(),
        u.asset_generators_in.data(), u.asset_generators_in.size(),
        u.value_commitments_in[0].data(), u.value_commitments_in[0].size()));
    return u;
  }

  LiquidUtxos GetUtxosFromTx(const std::string& txHex,
                             const std::string& address = {}) {
    LiquidUtxos out;
    struct wally_tx* tx{nullptr};
    CHECK_WALLY(wally_tx_from_hex(txHex.c_str(), tx_flags_, &tx));

    out.tx_id.resize(32);
    CHECK_WALLY(wally_tx_get_txid(tx, out.tx_id.data(), out.tx_id.size()));

    size_t num_inputs = 0;
    CHECK_WALLY(wally_tx_get_num_inputs(tx, &num_inputs));
    out.vins_tx_id.resize(num_inputs);
    out.vins_vout.resize(num_inputs);
    for (size_t vin = 0; vin < num_inputs; vin++) {
      const auto& txin = tx->inputs[vin];
      out.vins_tx_id[vin] = std::vector<unsigned char>(
          txin.txhash, txin.txhash + WALLY_TXHASH_LEN);
      out.vins_vout[vin] = txin.index;
    }

    size_t num_outputs = 0;
    CHECK_WALLY(wally_tx_get_num_outputs(tx, &num_outputs));
    for (size_t vout = 0; vout < num_outputs; vout++) {
      const auto& txout = tx->outputs[vout];
      std::vector<unsigned char> script(txout.script,
                                        txout.script + txout.script_len);
      if (!spk_.contains(script)) continue;
      if (!address.empty() && spk_[script].address != address) continue;
      auto privateBlindingKey = GetBlindingKey(script);

      std::vector<unsigned char> nonce(txout.nonce,
                                       txout.nonce + txout.nonce_len);
      std::vector<unsigned char> rangeproof(
          txout.rangeproof, txout.rangeproof + txout.rangeproof_len);
      std::vector<unsigned char> asset_commitment(
          txout.asset, txout.asset + txout.asset_len);
      std::vector<unsigned char> value_commitment_from_tx(
          txout.value, txout.value + txout.value_len);

      // Unblind using the output nonce (ephemeral pubkey), rangeproof,
      // value+asset commitments
      std::vector<unsigned char> asset_out(ASSET_TAG_LEN);
      std::vector<unsigned char> abf_out(BLINDING_FACTOR_LEN);
      std::vector<unsigned char> vbf_out(BLINDING_FACTOR_LEN);
      uint64_t value_out = 0;

      CHECK_WALLY(wally_asset_unblind(
          nonce.data(), nonce.size(), privateBlindingKey.data(),
          privateBlindingKey.size(), rangeproof.data(), rangeproof.size(),
          value_commitment_from_tx.data(), value_commitment_from_tx.size(),
          script.data(), script.size(), asset_commitment.data(),
          asset_commitment.size(), asset_out.data(), asset_out.size(),
          abf_out.data(), abf_out.size(), vbf_out.data(), vbf_out.size(),
          &value_out));

      std::vector<unsigned char> asset_id(asset_out.begin(), asset_out.end());
      std::vector<unsigned char> asset_generator(ASSET_GENERATOR_LEN);
      CHECK_WALLY(wally_asset_generator_from_bytes(
          asset_id.data(), asset_id.size(), abf_out.data(), abf_out.size(),
          asset_generator.data(), asset_generator.size()));
      if (asset_commitment != asset_generator) {
        wally_tx_free(tx);
        throw std::runtime_error(
            "asset_generator mismatch with asset_commitment");
      }

      // Recompute and sanity-check value commitment
      std::vector<unsigned char> recomputed_value_commitment(
          ASSET_COMMITMENT_LEN);
      CHECK_WALLY(wally_asset_value_commitment(
          value_out, vbf_out.data(), vbf_out.size(), asset_generator.data(),
          asset_generator.size(), recomputed_value_commitment.data(),
          recomputed_value_commitment.size()));
      if (value_commitment_from_tx != recomputed_value_commitment) {
        wally_tx_free(tx);
        throw std::runtime_error(
            "value_commitment mismatch: unblind factors don't recompute "
            "original commitment");
      }

      out.asset_generators_in.insert(out.asset_generators_in.end(),
                                     asset_generator.begin(),
                                     asset_generator.end());
      out.asset_ids_in.insert(out.asset_ids_in.end(), asset_id.begin(),
                              asset_id.end());
      out.values_in.push_back(value_out);
      out.abfs_in.insert(out.abfs_in.end(), abf_out.begin(), abf_out.end());
      out.vbfs_in.insert(out.vbfs_in.end(), vbf_out.begin(), vbf_out.end());
      out.script_pubkeys_in.push_back(script);
      out.value_commitments_in.push_back(value_commitment_from_tx);
      out.vouts_in.push_back(static_cast<uint32_t>(vout));
    }

    wally_tx_free(tx);
    return out;
  }

  // Returns true iff every input of `tx_hex` has a non-empty witness stack.
  //
  // CreateTx leaves the witness empty on all inputs; SignTx fills the witness
  // (sig + pubkey for P2WPKH) on all of them. So "all witnesses non-empty"
  // is a reliable signal that the tx has been signed by this signer flow.
  //
  // Note: this only checks witness presence, not signature validity. It also
  // assumes a witness-based script type (P2WPKH/P2WSH). A legacy P2PKH input
  // would put its signature in scriptSig, which this check does not consider.
  static bool IsTxSigned(const std::string& tx_hex) {
    struct wally_tx* tx = nullptr;
    CHECK_WALLY(wally_tx_from_hex(
        tx_hex.c_str(), WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS,
        &tx));

    size_t num_inputs = 0;
    CHECK_WALLY(wally_tx_get_num_inputs(tx, &num_inputs));
    if (num_inputs == 0) {
      wally_tx_free(tx);
      return false;
    }

    bool all_signed = true;
    for (size_t vin = 0; vin < num_inputs; ++vin) {
      size_t items = 0;
      CHECK_WALLY(wally_tx_get_input_witness_num_items(tx, vin, &items));
      if (items == 0) {
        all_signed = false;
        break;
      }
    }
    wally_tx_free(tx);
    return all_signed;
  }

  using AssetDestinations = std::map<AssetId, std::map<std::string, Amount>>;

  // Build and blind a Liquid transaction; returns unsigned hex (no witness
  // signatures). Use SignTx(hex, inputs) when ready to sign.
  //
  // - `destinations`: per-asset map of confidential-address -> amount.
  //   Multiple assets and multiple recipients per asset are supported.
  // - `changeConfAddr`: receives leftover for every asset (including LBTC fee
  //   change). Required whenever any asset has a non-zero remainder.
  // - `feeSats`: explicit LBTC fee. LBTC inputs must cover feeSats plus any
  //   LBTC destinations.
  //
  // Layout of the resulting tx outputs:
  //   vout 0          : explicit LBTC fee (unblinded)
  //   then per asset  : recipient outputs (in `destinations` order),
  //                     followed by a change output if leftover > 0.
  std::string CreateTx(const std::vector<LiquidUtxos>& inputs,
                       const AssetDestinations& destinations,
                       const std::string& changeConfAddr, uint64_t feeSats) {
    if (inputs.empty()) throw std::runtime_error("inputs must be non-empty");
    if (destinations.empty())
      throw std::runtime_error("destinations must be non-empty");

    const std::vector<unsigned char> ZERO32(32, 0);
    const auto& LBTC = WallyUtils::C().LBTC_ASSET_ID;

    // Per-input view derived from inputs[].
    struct InputInfo {
      std::vector<unsigned char> tx_id;  // 32
      uint32_t vout;
      std::vector<unsigned char> asset_id;   // 32
      std::vector<unsigned char> asset_gen;  // ASSET_GENERATOR_LEN (33)
      uint64_t value;
      std::vector<unsigned char> abf;  // 32
      std::vector<unsigned char> vbf;  // 32
    };
    std::vector<InputInfo> all_inputs;

    for (const auto& u : inputs) {
      if (u.tx_id.size() != WALLY_TXHASH_LEN) {
        throw std::runtime_error("LiquidUtxos.tx_id must be 32 bytes");
      }
      const size_t k_count = u.vouts_in.size();
      if (u.asset_ids_in.size() != k_count * 32 ||
          u.values_in.size() != k_count || u.abfs_in.size() != k_count * 32 ||
          u.vbfs_in.size() != k_count * 32 ||
          u.asset_generators_in.size() != k_count * ASSET_GENERATOR_LEN) {
        throw std::runtime_error(
            "LiquidUtxos blinding arrays size mismatch with vouts_in");
      }
      for (size_t k = 0; k < k_count; ++k) {
        InputInfo ii;
        ii.tx_id = u.tx_id;
        ii.vout = u.vouts_in[k];
        ii.asset_id.assign(u.asset_ids_in.begin() + k * 32,
                           u.asset_ids_in.begin() + (k + 1) * 32);
        ii.asset_gen.assign(
            u.asset_generators_in.begin() + k * ASSET_GENERATOR_LEN,
            u.asset_generators_in.begin() + (k + 1) * ASSET_GENERATOR_LEN);
        ii.value = u.values_in[k];
        ii.abf.assign(u.abfs_in.begin() + k * 32,
                      u.abfs_in.begin() + (k + 1) * 32);
        ii.vbf.assign(u.vbfs_in.begin() + k * 32,
                      u.vbfs_in.begin() + (k + 1) * 32);
        all_inputs.push_back(std::move(ii));
      }
    }

    if (all_inputs.empty()) {
      throw std::runtime_error("No spendable outputs found in LiquidUtxos");
    }

    // Group input indices by asset id.
    std::map<AssetId, std::vector<size_t>> asset_input_idx;
    for (size_t i = 0; i < all_inputs.size(); ++i) {
      asset_input_idx[all_inputs[i].asset_id].push_back(i);
    }

    // Per-asset plan: totals, destinations, change.
    struct AssetPlan {
      uint64_t total_in = 0;
      uint64_t total_dest = 0;
      uint64_t fee_part = 0;  // feeSats only for LBTC, else 0
      uint64_t change = 0;
      bool has_change = false;
      // (addr, amount) preserved in addr-sorted order from the input map.
      std::vector<std::pair<std::string, uint64_t>> dests;
    };
    std::map<AssetId, AssetPlan> plans;

    for (const auto& [asset, idxs] : asset_input_idx) {
      AssetPlan p;
      for (auto i : idxs) p.total_in += all_inputs[i].value;
      plans.emplace(asset, std::move(p));
    }

    for (const auto& [asset, addr_amount] : destinations) {
      if (asset.size() != 32) {
        throw std::runtime_error("Asset id must be 32 bytes");
      }
      if (addr_amount.empty()) {
        throw std::runtime_error("Empty destination map for an asset");
      }
      auto it = plans.find(asset);
      if (it == plans.end()) {
        throw std::runtime_error(
            "No inputs found for one of the destination assets");
      }
      AssetPlan& p = it->second;
      for (const auto& [addr, amt] : addr_amount) {
        if (amt == 0) {
          throw std::runtime_error("Destination amount must be > 0");
        }
        if (addr.empty()) {
          throw std::runtime_error("Destination address must be non-empty");
        }
        p.total_dest += amt;
        p.dests.emplace_back(addr, amt);
      }
    }

    if (!plans.contains(LBTC)) {
      throw std::runtime_error("No LBTC inputs available to pay fee");
    }
    plans[LBTC].fee_part = feeSats;

    for (auto& [asset, p] : plans) {
      const uint64_t out_total = p.total_dest + p.fee_part;
      if (out_total > p.total_in) {
        throw std::runtime_error(
            "Insufficient inputs for an asset (destinations + fee exceed "
            "inputs)");
      }
      p.change = p.total_in - out_total;
      p.has_change = p.change > 0;
      if (p.has_change && changeConfAddr.empty()) {
        throw std::runtime_error(
            "changeConfAddr is required: an asset has a non-zero remainder");
      }
      // Need at least one blinded output per asset to balance random input
      // vbfs; the explicit fee output is unblinded so it doesn't count.
      const bool has_blinded_out = !p.dests.empty() || p.has_change;
      if (!has_blinded_out) {
        throw std::runtime_error(
            "Asset has confidential inputs but no blinded outputs to balance "
            "(provide a destination or accept change for this asset)");
      }
    }

    // Build the planned output list.
    struct PlannedOutput {
      AssetId asset_id;
      uint64_t value;
      std::string conf_addr;  // unused when explicit_fee
      bool explicit_fee;
      std::vector<unsigned char> abf;  // 32 (ZERO32 when explicit_fee)
      std::vector<unsigned char> vbf;  // 32 (filled later for last per-asset)
    };
    std::vector<PlannedOutput> outs;

    {
      PlannedOutput fee_out;
      fee_out.asset_id = LBTC;
      fee_out.value = feeSats;
      fee_out.explicit_fee = true;
      fee_out.abf = ZERO32;
      fee_out.vbf = ZERO32;
      outs.push_back(std::move(fee_out));
    }

    for (const auto& [asset, p] : plans) {
      for (const auto& [addr, amt] : p.dests) {
        PlannedOutput o;
        o.asset_id = asset;
        o.value = amt;
        o.conf_addr = addr;
        o.explicit_fee = false;
        o.abf = WallyUtils::RandomBytes(32);
        o.vbf = WallyUtils::RandomBytes(32);
        outs.push_back(std::move(o));
      }
      if (p.has_change) {
        PlannedOutput o;
        o.asset_id = asset;
        o.value = p.change;
        o.conf_addr = changeConfAddr;
        o.explicit_fee = false;
        o.abf = WallyUtils::RandomBytes(32);
        o.vbf = WallyUtils::RandomBytes(32);
        outs.push_back(std::move(o));
      }
    }

    // For each asset, the last blinded output absorbs the residual vbf.
    std::map<AssetId, std::vector<size_t>> asset_blinded_outs;
    for (size_t i = 0; i < outs.size(); ++i) {
      if (!outs[i].explicit_fee) {
        asset_blinded_outs[outs[i].asset_id].push_back(i);
      }
    }

    auto recompute_asset_vbf_final = [&](const AssetId& asset) {
      const auto& blinded_idxs = asset_blinded_outs.at(asset);
      const auto& input_idxs = asset_input_idx.at(asset);

      std::vector<uint64_t> values;
      std::vector<unsigned char> abfs;
      std::vector<unsigned char> vbfs;
      for (auto i : input_idxs) {
        values.push_back(all_inputs[i].value);
        abfs.insert(abfs.end(), all_inputs[i].abf.begin(),
                    all_inputs[i].abf.end());
        vbfs.insert(vbfs.end(), all_inputs[i].vbf.begin(),
                    all_inputs[i].vbf.end());
      }
      const size_t num_inputs_a = input_idxs.size();

      if (asset == LBTC) {
        values.push_back(feeSats);
        abfs.insert(abfs.end(), ZERO32.begin(), ZERO32.end());
        vbfs.insert(vbfs.end(), ZERO32.begin(), ZERO32.end());
      }
      for (size_t k = 0; k < blinded_idxs.size(); ++k) {
        const auto& planned = outs[blinded_idxs[k]];
        values.push_back(planned.value);
        abfs.insert(abfs.end(), planned.abf.begin(), planned.abf.end());
        if (k + 1 < blinded_idxs.size()) {
          vbfs.insert(vbfs.end(), planned.vbf.begin(), planned.vbf.end());
        }
      }

      std::vector<unsigned char> vbf_final(32, 0);
      CHECK_WALLY(wally_asset_final_vbf(
          values.data(), values.size(), num_inputs_a, abfs.data(), abfs.size(),
          vbfs.data(), vbfs.size(), vbf_final.data(), vbf_final.size()));
      outs[blinded_idxs.back()].vbf = vbf_final;
    };

    for (const auto& [asset, _] : asset_blinded_outs) {
      recompute_asset_vbf_final(asset);
    }

    // Surjection proof candidates: all inputs in their tx order.
    std::vector<unsigned char> surj_asset_ids;
    std::vector<unsigned char> surj_abfs;
    std::vector<unsigned char> surj_asset_gens;
    surj_asset_ids.reserve(all_inputs.size() * 32);
    surj_abfs.reserve(all_inputs.size() * 32);
    surj_asset_gens.reserve(all_inputs.size() * ASSET_GENERATOR_LEN);
    for (const auto& ii : all_inputs) {
      surj_asset_ids.insert(surj_asset_ids.end(), ii.asset_id.begin(),
                            ii.asset_id.end());
      surj_abfs.insert(surj_abfs.end(), ii.abf.begin(), ii.abf.end());
      surj_asset_gens.insert(surj_asset_gens.end(), ii.asset_gen.begin(),
                             ii.asset_gen.end());
    }

    struct wally_tx* output_tx = nullptr;
    CHECK_WALLY(
        wally_tx_init_alloc(2, 0, all_inputs.size(), outs.size(), &output_tx));

    for (size_t out_idx = 0; out_idx < outs.size(); ++out_idx) {
      PlannedOutput& o = outs[out_idx];
      if (o.explicit_fee) {
        std::vector<unsigned char> fee_asset(1 + 32);
        fee_asset[0] = 0x01;
        std::memcpy(fee_asset.data() + 1, o.asset_id.data(), 32);
        std::vector<unsigned char> fee_value(
            WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN);
        CHECK_WALLY(wally_tx_confidential_value_from_satoshi(
            o.value, fee_value.data(), fee_value.size()));
        CHECK_WALLY(wally_tx_add_elements_raw_output(
            output_tx, nullptr, 0, fee_asset.data(), fee_asset.size(),
            fee_value.data(), fee_value.size(), nullptr, 0, nullptr, 0, nullptr,
            0, 0));
        continue;
      }

      const auto blinding_pubkey =
          WallyUtils::GetBlindingPubKeyFromConfidentialAddress(o.conf_addr);
      const auto script_pubkey =
          WallyUtils::GetScriptPubkeyFromConfidentialAddress(o.conf_addr);

      bool output_built = false;
      std::vector<unsigned char> generator(ASSET_GENERATOR_LEN);
      std::vector<unsigned char> value_commitment_out(ASSET_COMMITMENT_LEN);
      std::vector<unsigned char> eph_pub(EC_PUBLIC_KEY_LEN);
      std::vector<unsigned char> rangeproof;
      std::vector<unsigned char> surj;

      for (int asset_attempt = 0; asset_attempt < 100 && !output_built;
           ++asset_attempt) {
        if (asset_attempt > 0) {
          o.abf = WallyUtils::RandomBytes(32);
          recompute_asset_vbf_final(o.asset_id);
        }

        if (wally_asset_generator_from_bytes(
                o.asset_id.data(), o.asset_id.size(), o.abf.data(),
                o.abf.size(), generator.data(), generator.size()) != WALLY_OK) {
          continue;
        }
        if (wally_asset_value_commitment(
                o.value, o.vbf.data(), o.vbf.size(), generator.data(),
                generator.size(), value_commitment_out.data(),
                value_commitment_out.size()) != WALLY_OK) {
          continue;
        }

        for (int range_attempt = 0; range_attempt < 100 && !output_built;
             ++range_attempt) {
          auto eph_priv = WallyUtils::RandomEcPrivateKey();
          if (wally_ec_public_key_from_private_key(
                  eph_priv.data(), eph_priv.size(), eph_pub.data(),
                  eph_pub.size()) != WALLY_OK) {
            continue;
          }

          rangeproof.assign(ASSET_RANGEPROOF_MAX_LEN, 0);
          size_t rangeproof_len = 0;
          if (wally_asset_rangeproof(
                  o.value, blinding_pubkey.data(), blinding_pubkey.size(),
                  eph_priv.data(), eph_priv.size(), o.asset_id.data(),
                  o.asset_id.size(), o.abf.data(), o.abf.size(), o.vbf.data(),
                  o.vbf.size(), value_commitment_out.data(),
                  value_commitment_out.size(), script_pubkey.data(),
                  script_pubkey.size(), generator.data(), generator.size(), 1,
                  0, 36, rangeproof.data(), rangeproof.size(),
                  &rangeproof_len) != WALLY_OK) {
            continue;
          }
          rangeproof.resize(rangeproof_len);

          surj.assign(ASSET_SURJECTIONPROOF_MAX_LEN, 0);
          size_t surj_len = ASSET_SURJECTIONPROOF_MAX_LEN;
          int surj_ret = WALLY_ERROR;
          for (int surj_attempt = 0; surj_attempt < 100 && surj_ret != WALLY_OK;
               ++surj_attempt) {
            auto surj_entropy = WallyUtils::RandomBytes(32);
            surj_len = ASSET_SURJECTIONPROOF_MAX_LEN;
            surj_ret = wally_asset_surjectionproof(
                o.asset_id.data(), o.asset_id.size(), o.abf.data(),
                o.abf.size(), generator.data(), generator.size(),
                surj_entropy.data(), surj_entropy.size(), surj_asset_ids.data(),
                surj_asset_ids.size(), surj_abfs.data(), surj_abfs.size(),
                surj_asset_gens.data(), surj_asset_gens.size(), surj.data(),
                surj.size(), &surj_len);
          }
          if (surj_ret != WALLY_OK) continue;

          surj.resize(surj_len);
          CHECK_WALLY(wally_tx_add_elements_raw_output(
              output_tx, script_pubkey.data(), script_pubkey.size(),
              generator.data(), generator.size(), value_commitment_out.data(),
              value_commitment_out.size(), eph_pub.data(), eph_pub.size(),
              surj.data(), surj.size(), rangeproof.data(), rangeproof.size(),
              0));
          output_built = true;
        }
      }

      if (!output_built) {
        throw std::runtime_error(
            "Failed to build confidential Liquid output after retries");
      }
    }

    for (const auto& ii : all_inputs) {
      CHECK_WALLY(wally_tx_add_elements_raw_input(
          output_tx, ii.tx_id.data(), ii.tx_id.size(), ii.vout, 0xffffffff,
          nullptr, 0,  // script + script_len
          nullptr,     // witness
          nullptr, 0,  // nonce + nonce_len
          nullptr, 0,  // entropy + entropy_len
          nullptr, 0,  // issuance_amount + issuance_amount_len
          nullptr, 0,  // inflation_keys + inflation_keys_len
          nullptr, 0,  // issuance_amount_rangeproof + len
          nullptr, 0,  // inflation_keys_rangeproof + len
          nullptr,     // pegin_witness
          0));         // flags
    }

    char* txhex = nullptr;
    CHECK_WALLY(wally_tx_to_hex(output_tx, tx_flags_, &txhex));
    std::string txHexOut(txhex);
    wally_free_string(txhex);
    wally_tx_free(output_tx);
    return txHexOut;
  }

  // Signs an unsigned Liquid hex transaction produced by CreateTx.
  //
  // Elements confidential sighash requires each input's previous confidential
  // value commitment; that data is not present in the spending tx hex, so we
  // rebuild script_pubkey + value_commitment by matching each vin's (txid,
  // vout) against `inputs` (the same LiquidUtxos vector passed to CreateTx).
  std::string SignTx(const std::string& tx_hex,
                     const std::vector<LiquidUtxos>& inputs) {
    std::map<std::string, PrevoutSpendData> prevouts =
        BuildPrevoutSpendDataMap(inputs);

    struct wally_tx* tx = nullptr;
    CHECK_WALLY(wally_tx_from_hex(tx_hex.c_str(), tx_flags_, &tx));

    size_t num_inputs = 0;
    CHECK_WALLY(wally_tx_get_num_inputs(tx, &num_inputs));

    std::vector<std::vector<unsigned char>> script_pubkeys_in;
    std::vector<std::vector<unsigned char>> value_commitments_in;
    script_pubkeys_in.reserve(num_inputs);
    value_commitments_in.reserve(num_inputs);

    for (size_t vin = 0; vin < num_inputs; ++vin) {
      std::vector<unsigned char> txhash(WALLY_TXHASH_LEN);
      CHECK_WALLY(
          wally_tx_get_input_txhash(tx, vin, txhash.data(), txhash.size()));
      size_t vout_index = 0;
      CHECK_WALLY(wally_tx_get_input_index(tx, vin, &vout_index));
      const auto vout_u32 = static_cast<uint32_t>(vout_index);

      const std::string key = MakePrevoutMapKey(txhash.data(), vout_u32);
      auto it = prevouts.find(key);
      if (it == prevouts.end()) {
        wally_tx_free(tx);
        throw std::runtime_error(
            "SignTx: no LiquidUtxos match for input vin=" +
            std::to_string(vin) +
            " (need same UTXO set used when building the unsigned tx)");
      }
      script_pubkeys_in.push_back(it->second.first);
      value_commitments_in.push_back(it->second.second);
    }

    SignTxInPlace(tx, script_pubkeys_in, value_commitments_in);

    char* out_hex = nullptr;
    CHECK_WALLY(wally_tx_to_hex(tx, tx_flags_, &out_hex));
    std::string signed_hex(out_hex);
    wally_free_string(out_hex);
    wally_tx_free(tx);
    return signed_hex;
  }

  // Build a base64-serialized PSET (Elements PSBT) directly from the high level
  // transaction intent (same parameters as CreateTx) and embed the UTXO spend
  // data needed for signing (scriptPubKey + Elements value commitment).
  //
  // The resulting PSET can be signed later with SignPsbt(pset_base64) without
  // passing the LiquidUtxos again.
  std::string CreatePsbt(const std::vector<LiquidUtxos>& inputs,
                         const AssetDestinations& destinations,
                         const std::string& changeConfAddr, uint64_t feeSats) {
    // Reuse the existing tx builder to ensure identical output layout/blinding.
    const std::string unsigned_hex =
        CreateTx(inputs, destinations, changeConfAddr, feeSats);

    struct wally_tx* tx = nullptr;
    CHECK_WALLY(wally_tx_from_hex(unsigned_hex.c_str(), tx_flags_, &tx));

    struct wally_psbt* psbt = nullptr;
    CHECK_WALLY(wally_psbt_from_tx(tx, WALLY_PSBT_VERSION_2,
                                   WALLY_PSBT_INIT_PSET, &psbt));

    // Populate witness_utxo for each input with the prevout scriptPubKey and
    // confidential value commitment needed for Elements signature hashing.
    // We don't need rangeproof/nonce for signing; value_commitment is enough.
    std::map<std::string, PrevoutSpendData> prevouts =
        BuildPrevoutSpendDataMap(inputs);

    size_t num_inputs = 0;
    CHECK_WALLY(wally_tx_get_num_inputs(tx, &num_inputs));
    for (size_t vin = 0; vin < num_inputs; ++vin) {
      std::vector<unsigned char> txhash(WALLY_TXHASH_LEN);
      CHECK_WALLY(
          wally_tx_get_input_txhash(tx, vin, txhash.data(), txhash.size()));
      size_t vout_index = 0;
      CHECK_WALLY(wally_tx_get_input_index(tx, vin, &vout_index));
      const auto vout_u32 = static_cast<uint32_t>(vout_index);

      const std::string key = MakePrevoutMapKey(txhash.data(), vout_u32);
      auto it = prevouts.find(key);
      if (it == prevouts.end()) {
        wally_psbt_free(psbt);
        wally_tx_free(tx);
        throw std::runtime_error(
            "CreatePsbt: no LiquidUtxos match for input vin=" +
            std::to_string(vin));
      }

      const auto& spk = it->second.first;
      const auto& value_commitment = it->second.second;
      if (value_commitment.size() != ASSET_COMMITMENT_LEN) {
        wally_psbt_free(psbt);
        wally_tx_free(tx);
        throw std::runtime_error(
            "CreatePsbt: value_commitment must be 33 bytes for vin=" +
            std::to_string(vin));
      }

      // We also set the asset commitment (generator) if we can infer it from
      // LiquidUtxos; it's not required for signing, but keeps witness_utxo
      // Elements-shaped.
      std::vector<unsigned char> asset_commitment(ASSET_GENERATOR_LEN, 0);
      bool have_asset_commitment = false;
      for (const auto& u : inputs) {
        if (u.tx_id.size() != WALLY_TXHASH_LEN) continue;
        if (MakePrevoutMapKey(u.tx_id.data(), vout_u32) != key) continue;
        for (size_t k = 0; k < u.vouts_in.size(); ++k) {
          if (u.vouts_in[k] != vout_u32) continue;
          const size_t off = k * ASSET_GENERATOR_LEN;
          if (u.asset_generators_in.size() >= off + ASSET_GENERATOR_LEN) {
            asset_commitment.assign(
                u.asset_generators_in.begin() + off,
                u.asset_generators_in.begin() + off + ASSET_GENERATOR_LEN);
            have_asset_commitment = true;
          }
          break;
        }
      }
      if (!have_asset_commitment) {
        // Leave as zeros; Elements txout parser isn't needed for signing here.
      }

      struct wally_tx_output out{};
      out.script = const_cast<unsigned char*>(spk.data());
      out.script_len = spk.size();
      out.value = const_cast<unsigned char*>(value_commitment.data());
      out.value_len = value_commitment.size();
      out.asset = const_cast<unsigned char*>(asset_commitment.data());
      out.asset_len = asset_commitment.size();
      out.nonce = nullptr;
      out.nonce_len = 0;
      out.surjectionproof = nullptr;
      out.surjectionproof_len = 0;
      out.rangeproof = nullptr;
      out.rangeproof_len = 0;

      CHECK_WALLY(wally_psbt_set_input_witness_utxo(psbt, vin, &out));
    }

    char* out_b64 = nullptr;
    CHECK_WALLY(wally_psbt_to_base64(psbt, 0, &out_b64));
    std::string b64(out_b64);
    wally_free_string(out_b64);
    wally_psbt_free(psbt);
    wally_tx_free(tx);
    return b64;
  }

  // Sign a base64-serialized PSET using spend data embedded in each input's
  // witness_utxo (scriptPubKey + value commitment). This is the preferred
  // flow when the PSET was created by CreatePsbt(inputs, ...).
  std::string SignPsbt(const std::string& pset_base64) {
    struct wally_psbt* psbt = nullptr;
    CHECK_WALLY(wally_psbt_from_base64(pset_base64.c_str(),
                                       WALLY_PSBT_PARSE_FLAG_STRICT, &psbt));
    if (psbt == nullptr) {
      throw std::runtime_error("SignPsbt: invalid PSBT (null)");
    }

    struct wally_tx* tx = nullptr;
    CHECK_WALLY(wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL, &tx));
    if (tx == nullptr) {
      wally_psbt_free(psbt);
      throw std::runtime_error("SignPsbt: could not extract non-final tx");
    }

    size_t num_inputs = 0;
    CHECK_WALLY(wally_tx_get_num_inputs(tx, &num_inputs));

    size_t psbt_inputs = 0;
    CHECK_WALLY(wally_psbt_get_num_inputs(psbt, &psbt_inputs));
    if (psbt_inputs != num_inputs) {
      wally_tx_free(tx);
      wally_psbt_free(psbt);
      throw std::runtime_error("SignPsbt: psbt inputs mismatch with tx inputs");
    }

    std::vector<std::vector<unsigned char>> script_pubkeys_in;
    std::vector<std::vector<unsigned char>> value_commitments_in;
    script_pubkeys_in.reserve(num_inputs);
    value_commitments_in.reserve(num_inputs);

    for (size_t vin = 0; vin < num_inputs; ++vin) {
      struct wally_tx_output* wit_utxo = nullptr;
      CHECK_WALLY(
          wally_psbt_get_input_witness_utxo_alloc(psbt, vin, &wit_utxo));
      if (wit_utxo == nullptr || wit_utxo->script == nullptr ||
          wit_utxo->value == nullptr) {
        if (wit_utxo) wally_tx_output_free(wit_utxo);
        wally_tx_free(tx);
        wally_psbt_free(psbt);
        throw std::runtime_error(
            "SignPsbt: missing witness_utxo/script/value for vin=" +
            std::to_string(vin) +
            " (create the PSET with CreatePsbt(inputs, ...) or provide spend "
            "data)");
      }
      std::vector<unsigned char> spk(wit_utxo->script,
                                     wit_utxo->script + wit_utxo->script_len);
      std::vector<unsigned char> vc(wit_utxo->value,
                                    wit_utxo->value + wit_utxo->value_len);
      wally_tx_output_free(wit_utxo);

      if (vc.size() != ASSET_COMMITMENT_LEN) {
        wally_tx_free(tx);
        wally_psbt_free(psbt);
        throw std::runtime_error(
            "SignPsbt: witness_utxo value must be 33-byte Elements commitment "
            "for vin=" +
            std::to_string(vin));
      }
      script_pubkeys_in.push_back(std::move(spk));
      value_commitments_in.push_back(std::move(vc));
    }

    SignTxInPlace(tx, script_pubkeys_in, value_commitments_in);

    for (size_t vin = 0; vin < num_inputs; ++vin) {
      const auto* wit = tx->inputs[vin].witness;
      if (!wit) {
        wally_tx_free(tx);
        wally_psbt_free(psbt);
        throw std::runtime_error(
            "SignPsbt: missing witness after signing at vin=" +
            std::to_string(vin));
      }
      struct wally_tx_witness_stack* wit_clone = nullptr;
      CHECK_WALLY(wally_tx_witness_stack_clone_alloc(wit, &wit_clone));
      CHECK_WALLY(wally_psbt_set_input_final_witness(psbt, vin, wit_clone));
      wally_tx_witness_stack_free(wit_clone);
    }
    wally_tx_free(tx);

    CHECK_WALLY(wally_psbt_finalize(psbt, 0));

    char* out_b64 = nullptr;
    CHECK_WALLY(wally_psbt_to_base64(psbt, 0, &out_b64));
    std::string signed_b64(out_b64);
    wally_free_string(out_b64);
    wally_psbt_free(psbt);
    return signed_b64;
  }

  // P2WPKH witness weight units, per signed input:
  //   1   (witness item count = 2)
  // + 1   (sig length byte) + 72 (DER sig + sighash byte, avg/upper bound)
  // + 1   (pubkey length byte) + 33 (compressed pubkey)
  // = 108 WU
  static constexpr size_t kP2WPKHWitnessWU = 108;

  // Elements explicit LBTC fee output (see CreateTx): empty script, explicit
  // asset prefix, unblinded value.
  static bool IsExplicitLbtcFeeOutput(const struct wally_tx_output& txout) {
    if (txout.script_len != 0) return false;
    if (txout.asset_len != WALLY_TX_ASSET_CT_ASSET_LEN) return false;
    if (txout.asset[0] != WALLY_TX_ASSET_CT_EXPLICIT_PREFIX) return false;
    if (txout.value_len != WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN) return false;
    const auto& lbtc = WallyUtils::C().LBTC_ASSET_ID;
    if (lbtc.size() != WALLY_TX_ASSET_TAG_LEN) return false;
    return std::memcmp(txout.asset + 1, lbtc.data(), WALLY_TX_ASSET_TAG_LEN) ==
           0;
  }

  // Vsize of an on-wire tx (witness already present). Applies Elements
  // discount.
  static size_t ComputeVsizeFromTx(struct wally_tx* tx) {
    size_t weight = 0;
    CHECK_WALLY(wally_tx_get_weight(tx, &weight));
    size_t discount = 0;
    CHECK_WALLY(wally_tx_get_elements_weight_discount(tx, 0, &discount));
    if (discount > weight) discount = weight;
    weight -= discount;
    size_t vsize = 0;
    CHECK_WALLY(wally_tx_vsize_from_weight(weight, &vsize));
    return vsize;
  }

  // Compute the vsize (vbytes) of a hypothetical *signed* tx given an unsigned
  // hex (witness stacks empty). Adds `witness_wu_per_input` weight units for
  // every input, then applies the Elements confidential-output discount, then
  // converts to vsize. Default witness size assumes P2WPKH on every input.
  static size_t ComputeSignedVsize(
      const std::string& unsigned_tx_hex,
      size_t witness_wu_per_input = kP2WPKHWitnessWU) {
    constexpr uint32_t kTxFlags =
        WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS;
    struct wally_tx* tx = nullptr;
    CHECK_WALLY(wally_tx_from_hex(unsigned_tx_hex.c_str(), kTxFlags, &tx));

    size_t weight = 0;
    CHECK_WALLY(wally_tx_get_weight(tx, &weight));

    size_t num_inputs = 0;
    CHECK_WALLY(wally_tx_get_num_inputs(tx, &num_inputs));
    weight += num_inputs * witness_wu_per_input;

    size_t discount = 0;
    CHECK_WALLY(wally_tx_get_elements_weight_discount(tx, 0, &discount));
    if (discount > weight) discount = weight;
    weight -= discount;

    size_t vsize = 0;
    CHECK_WALLY(wally_tx_vsize_from_weight(weight, &vsize));
    wally_tx_free(tx);
    return vsize;
  }

  // Fee from virtual size and feerate in sat/kvB (satoshis per 1000 vbytes).
  // Liquid defaults are often quoted as e.g. 0.1 sat/vB (= 100 sat/kvB).
  // Uses ceiling integer math so small txs still pay at least the proportional
  // fee.
  static uint64_t FeeSatsFromVsizeAndKvBRate(size_t vsize,
                                             uint64_t fee_rate_sat_per_kvb) {
    return (static_cast<uint64_t>(vsize) * fee_rate_sat_per_kvb + 999) / 1000;
  }

  // Estimate the vsize of the would-be-signed Liquid tx that CreateTx +
  // SignTx would produce for the given inputs/destinations/changeConfAddr.
  //
  // `feeSatsHint` is the placeholder fee used while building the throw-away
  // unsigned tx. Its value almost never affects vsize, *except* when changing
  // it would add or remove a change output (e.g. when LBTC inputs ≈ feeSats).
  // Pass an approximate target fee if your situation is on that boundary;
  // for typical wallets the default of 1 sat is fine.
  size_t EstimateSignedVsize(const std::vector<LiquidUtxos>& inputs,
                             const AssetDestinations& destinations,
                             const std::string& changeConfAddr,
                             uint64_t feeSatsHint = 1,
                             size_t witness_wu_per_input = kP2WPKHWitnessWU) {
    const std::string placeholder_hex =
        CreateTx(inputs, destinations, changeConfAddr, feeSatsHint);
    return ComputeSignedVsize(placeholder_hex, witness_wu_per_input);
  }

  // Convenience: fee in sats from estimated signed vsize and feerate sat/kvB.
  // See EstimateSignedVsize for caveats on `feeSatsHint`.
  uint64_t EstimateFee(const std::vector<LiquidUtxos>& inputs,
                       const AssetDestinations& destinations,
                       const std::string& changeConfAddr,
                       uint64_t fee_rate_sat_per_kvb, uint64_t feeSatsHint = 1,
                       size_t witness_wu_per_input = kP2WPKHWitnessWU) {
    const size_t vsize =
        EstimateSignedVsize(inputs, destinations, changeConfAddr, feeSatsHint,
                            witness_wu_per_input);
    return FeeSatsFromVsizeAndKvBRate(vsize, fee_rate_sat_per_kvb);
  }
};
}  // namespace nunchuk::wally

#endif  // NUNCHUK_WALLY_SIGNER_HPP