#include <wally.hpp>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_crypto.h>
#include <wally_elements.h>
#include <wally_script.h>
#include <wally_transaction.h>
#include <wally_transaction_members.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

} // namespace

namespace wally::detail {
int check_ret(const char* func_name, int ret) {
    if (ret != WALLY_OK) {
        throw std::runtime_error(std::string("Error in ") + func_name + ": " + std::to_string(ret));
    }
    return ret;
}
} // namespace wally::detail

namespace {

inline int check_ret(const char* func_name, int ret) { return wally::detail::check_ret(func_name, ret); }

std::vector<unsigned char> rand_bytes(size_t n) {
    std::vector<unsigned char> out(n);
    std::random_device rd;
    for (size_t i = 0; i < n; i++) out[i] = static_cast<unsigned char>(rd());
    return out;
}

std::vector<unsigned char> rand_ec_private_key() {
    for (;;) {
        auto k = rand_bytes(EC_PRIVATE_KEY_LEN);
        if (wally_ec_private_key_verify(k.data(), k.size()) == WALLY_OK) return k;
    }
}

std::string read_text_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Failed to open file: " + path);
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
    return s;
}

std::string read_first_existing(const std::vector<std::string>& candidates) {
    for (const auto& p : candidates) {
        std::ifstream f(p);
        if (f.good()) return read_text_file(p);
    }
    throw std::runtime_error("None of the candidate files exist");
}

std::string hex_from_bytes(const unsigned char* data, size_t len) {
    static const char* hexdigits = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = hexdigits[(data[i] >> 4) & 0xF];
        out[2 * i + 1] = hexdigits[data[i] & 0xF];
    }
    return out;
}

std::vector<unsigned char> bytes_from_hex(const std::string& hex) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    if (hex.size() % 2) throw std::runtime_error("Invalid hex length");
    std::vector<unsigned char> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); i++) {
        int hi = nibble(hex[2 * i]);
        int lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) throw std::runtime_error("Invalid hex character");
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return out;
}

struct UtxoSet {
    struct wally_tx* tx{nullptr};
    std::vector<unsigned char> prevTxid; // 32 bytes (internal order)

    std::vector<unsigned char> asset_generators_in; // 33*num
    std::vector<unsigned char> asset_ids_in;        // 32*num
    std::vector<uint64_t> values_in;                // satoshis
    std::vector<unsigned char> abfs_in;             // 32*num
    std::vector<unsigned char> vbfs_in;             // 32*num
    std::vector<std::vector<unsigned char>> script_pubkeys_in;
    std::vector<std::vector<unsigned char>> value_commitments_in; // 33 bytes each
    std::vector<uint32_t> vouts_in;
};

UtxoSet getConfidentialUtxosFromTx(const std::string& txHex,
                                  const std::vector<unsigned char>& ourScriptPubKey,
                                  const std::vector<unsigned char>& privateBlindingKey) {
    UtxoSet out;

    const uint32_t txflags = WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS;
    check_ret("wally_tx_from_hex", wally_tx_from_hex(txHex.c_str(), txflags, &out.tx));

    out.prevTxid.resize(32);
    check_ret("wally_tx_get_txid", wally_tx_get_txid(out.tx, out.prevTxid.data(), out.prevTxid.size()));

    size_t num_outputs = 0;
    check_ret("wally_tx_get_num_outputs", wally_tx_get_num_outputs(out.tx, &num_outputs));

    for (size_t vout = 0; vout < num_outputs; vout++) {
        // libwally exposes `struct wally_tx`/`struct wally_tx_output`, so just read members.
        const auto& txout = out.tx->outputs[vout];
        if (!txout.script || txout.script_len != ourScriptPubKey.size()) continue;
        if (std::memcmp(txout.script, ourScriptPubKey.data(), ourScriptPubKey.size()) != 0) continue;

        std::vector<unsigned char> nonce(txout.nonce, txout.nonce + txout.nonce_len);
        std::vector<unsigned char> rangeproof(txout.rangeproof, txout.rangeproof + txout.rangeproof_len);
        std::vector<unsigned char> asset_commitment(txout.asset, txout.asset + txout.asset_len);
        std::vector<unsigned char> value_commitment_from_tx(txout.value, txout.value + txout.value_len);

        // Unblind using the output nonce (ephemeral pubkey), rangeproof, value+asset commitments
        std::vector<unsigned char> asset_out(ASSET_TAG_LEN);
        std::vector<unsigned char> abf_out(BLINDING_FACTOR_LEN);
        std::vector<unsigned char> vbf_out(BLINDING_FACTOR_LEN);
        uint64_t value_out = 0;

        check_ret("wally_asset_unblind",
                  wally_asset_unblind(nonce.data(), nonce.size(),
                                      privateBlindingKey.data(), privateBlindingKey.size(),
                                      rangeproof.data(), rangeproof.size(),
                                      value_commitment_from_tx.data(), value_commitment_from_tx.size(),
                                      ourScriptPubKey.data(), ourScriptPubKey.size(),
                                      asset_commitment.data(), asset_commitment.size(),
                                      asset_out.data(), asset_out.size(),
                                      abf_out.data(), abf_out.size(),
                                      vbf_out.data(), vbf_out.size(),
                                      &value_out));

        // Auto-detect asset-id byte order expected by generator_from_bytes by matching generator to the txout asset commitment
        std::vector<unsigned char> asset_id_a(asset_out.begin(), asset_out.end());
        std::vector<unsigned char> asset_id_b(asset_out.rbegin(), asset_out.rend());

        std::vector<unsigned char> gen_a(ASSET_GENERATOR_LEN);
        std::vector<unsigned char> gen_b(ASSET_GENERATOR_LEN);
        check_ret("wally_asset_generator_from_bytes(a)",
                  wally_asset_generator_from_bytes(asset_id_a.data(), asset_id_a.size(),
                                                   abf_out.data(), abf_out.size(),
                                                   gen_a.data(), gen_a.size()));
        check_ret("wally_asset_generator_from_bytes(b)",
                  wally_asset_generator_from_bytes(asset_id_b.data(), asset_id_b.size(),
                                                   abf_out.data(), abf_out.size(),
                                                   gen_b.data(), gen_b.size()));

        const bool a_matches = (asset_commitment.size() == gen_a.size() &&
                                std::memcmp(asset_commitment.data(), gen_a.data(), gen_a.size()) == 0);
        const bool b_matches = (asset_commitment.size() == gen_b.size() &&
                                std::memcmp(asset_commitment.data(), gen_b.data(), gen_b.size()) == 0);
        if (!a_matches && !b_matches) {
            wally_tx_free(out.tx);
            throw std::runtime_error("asset_generator mismatch with asset_commitment (asset_id byte order unknown)");
        }
        const auto& asset_id = a_matches ? asset_id_a : asset_id_b;
        const auto& asset_generator = a_matches ? gen_a : gen_b;

        // Recompute and sanity-check value commitment
        std::vector<unsigned char> recomputed_value_commitment(ASSET_COMMITMENT_LEN);
        check_ret("wally_asset_value_commitment",
                  wally_asset_value_commitment(value_out,
                                               vbf_out.data(), vbf_out.size(),
                                               asset_generator.data(), asset_generator.size(),
                                               recomputed_value_commitment.data(), recomputed_value_commitment.size()));
        if (value_commitment_from_tx.size() != recomputed_value_commitment.size() ||
            std::memcmp(value_commitment_from_tx.data(), recomputed_value_commitment.data(), recomputed_value_commitment.size()) != 0) {
            wally_tx_free(out.tx);
            throw std::runtime_error("value_commitment mismatch: unblind factors don't recompute original commitment");
        }

        out.asset_generators_in.insert(out.asset_generators_in.end(), asset_generator.begin(), asset_generator.end());
        out.asset_ids_in.insert(out.asset_ids_in.end(), asset_id.begin(), asset_id.end());
        out.values_in.push_back(value_out);
        out.abfs_in.insert(out.abfs_in.end(), abf_out.begin(), abf_out.end());
        out.vbfs_in.insert(out.vbfs_in.end(), vbf_out.begin(), vbf_out.end());
        out.script_pubkeys_in.push_back(ourScriptPubKey);
        out.value_commitments_in.push_back(value_commitment_from_tx);
        out.vouts_in.push_back(static_cast<uint32_t>(vout));
    }

    return out;
}

struct SendResult {
    std::string txHex;
    std::string txid; // display (big-endian)
};

struct ConfidentialDestDecomp {
    std::vector<unsigned char> blinding_pubkey; // EC_PUBLIC_KEY_LEN
    std::vector<unsigned char> script_pubkey;   // segwit script bytes
};

ConfidentialDestDecomp confidential_addr_to_dest_decomp(const std::string& confAddr,
                                                         const std::string& confAddrFamily,
                                                         const std::string& addrFamily) {
    ConfidentialDestDecomp out;
    out.blinding_pubkey.resize(EC_PUBLIC_KEY_LEN);
    check_ret("wally_confidential_addr_segwit_to_ec_public_key",
              wally_confidential_addr_segwit_to_ec_public_key(confAddr.c_str(), confAddrFamily.c_str(),
                                                              out.blinding_pubkey.data(), out.blinding_pubkey.size()));

    char* non_conf_addr = nullptr;
    check_ret("wally_confidential_addr_to_addr_segwit",
              wally_confidential_addr_to_addr_segwit(confAddr.c_str(), confAddrFamily.c_str(), addrFamily.c_str(), &non_conf_addr));

    size_t spk_len = 0;
    out.script_pubkey.resize(128);
    check_ret("wally_addr_segwit_to_bytes",
              wally_addr_segwit_to_bytes(non_conf_addr, addrFamily.c_str(), 0,
                                         out.script_pubkey.data(), out.script_pubkey.size(), &spk_len));
    out.script_pubkey.resize(spk_len);
    wally_free_string(non_conf_addr);
    return out;
}

SendResult sendAssetToConfidentialAddresses(const std::vector<std::string>& prevTxHexes,
                                              const std::vector<unsigned char>& ourScriptPubKey,
                                              const std::vector<unsigned char>& privateBlindingKey,
                                              const std::vector<std::string>& destinationConfAddrs,
                                              const std::string& feeChangeConfAddr, // empty => no fee change output
                                              uint64_t feeSats,
                                              const std::vector<unsigned char>& assetIdToSend, // 32 bytes
                                              const std::vector<unsigned char>& feeAssetId,     // 32 bytes
                                              const std::string& addrFamily,
                                              const std::string& confAddrFamily,
                                              const std::vector<unsigned char>& signingPrivKey,
                                              const std::vector<unsigned char>& signingPubKey) {
    if (prevTxHexes.empty()) throw std::runtime_error("prevTxHexes must be non-empty");
    if (destinationConfAddrs.empty()) throw std::runtime_error("destinationConfAddrs must be non-empty");
    if (assetIdToSend.size() != 32 || feeAssetId.size() != 32) throw std::runtime_error("assetIdToSend/feeAssetId must be 32 bytes");

    const std::vector<unsigned char> EMPTY;
    const std::vector<unsigned char> ZERO32(32, 0);

    std::vector<UtxoSet> utxos;
    utxos.reserve(prevTxHexes.size());
    for (const auto& hex : prevTxHexes) {
        utxos.push_back(getConfidentialUtxosFromTx(hex, ourScriptPubKey, privateBlindingKey));
    }

    // Merge
    std::vector<unsigned char> asset_generators_in;
    std::vector<unsigned char> asset_ids_in;
    std::vector<uint64_t> values_in;
    std::vector<unsigned char> abfs_in;
    std::vector<unsigned char> vbfs_in;
    std::vector<std::vector<unsigned char>> script_pubkeys_in;
    std::vector<std::vector<unsigned char>> value_commitments_in;
    std::vector<uint32_t> vouts_in;
    std::vector<std::vector<unsigned char>> input_prev_txid_for_vin;

    for (auto& u : utxos) {
        asset_generators_in.insert(asset_generators_in.end(), u.asset_generators_in.begin(), u.asset_generators_in.end());
        asset_ids_in.insert(asset_ids_in.end(), u.asset_ids_in.begin(), u.asset_ids_in.end());
        values_in.insert(values_in.end(), u.values_in.begin(), u.values_in.end());
        abfs_in.insert(abfs_in.end(), u.abfs_in.begin(), u.abfs_in.end());
        vbfs_in.insert(vbfs_in.end(), u.vbfs_in.begin(), u.vbfs_in.end());
        script_pubkeys_in.insert(script_pubkeys_in.end(), u.script_pubkeys_in.begin(), u.script_pubkeys_in.end());
        value_commitments_in.insert(value_commitments_in.end(), u.value_commitments_in.begin(), u.value_commitments_in.end());
        vouts_in.insert(vouts_in.end(), u.vouts_in.begin(), u.vouts_in.end());

        // One prevTxid per input (matching JS: u.vouts_in.map(() => u.prevTxid))
        for (size_t k = 0; k < u.vouts_in.size(); k++) input_prev_txid_for_vin.push_back(u.prevTxid);
    }

    const size_t num_inputs = values_in.size();
    if (num_inputs == 0) throw std::runtime_error("No spendable outputs found in prev tx(s) for our script_pubkey");

    // Determine which input indices are transfer-fee based on asset ids
    const bool feeAssetSame = std::memcmp(assetIdToSend.data(), feeAssetId.data(), 32) == 0;
    std::vector<size_t> transferIdx;
    std::vector<size_t> feeIdx;
    transferIdx.reserve(num_inputs);
    feeIdx.reserve(num_inputs);

    for (size_t vin = 0; vin < num_inputs; vin++) {
        const unsigned char* id = asset_ids_in.data() + vin * 32;
        if (std::memcmp(id, assetIdToSend.data(), 32) == 0) transferIdx.push_back(vin);
        if (std::memcmp(id, feeAssetId.data(), 32) == 0) feeIdx.push_back(vin);
    }

    if (transferIdx.empty()) {
        throw std::runtime_error("No inputs found for assetIdToSend");
    }

    if (feeAssetSame) {
        feeIdx = transferIdx;
    } else {
        if (feeIdx.empty()) throw std::runtime_error("No inputs found for feeAssetId");
    }

    // Ensure there are no other assets besides transfer and fee assets
    std::vector<char> used(num_inputs, 0);
    for (auto i : transferIdx) used[i] = 1;
    for (auto i : feeIdx) used[i] = 1;
    for (size_t vin = 0; vin < num_inputs; vin++) {
        if (!used[vin]) throw std::runtime_error("Mixed assets present beyond assetIdToSend/feeAssetId; this example does not support it");
    }

    uint64_t transferTotalIn = 0;
    uint64_t feeTotalIn = 0;
    for (auto i : transferIdx) transferTotalIn += values_in[i];
    for (auto i : feeIdx) feeTotalIn += values_in[i];

    if (feeAssetSame) {
        if (transferTotalIn <= feeSats) throw std::runtime_error("Input amount is not enough to pay fee");
    } else {
        if (feeTotalIn < feeSats) throw std::runtime_error("Fee inputs are not enough to pay feeSats");
    }

    // Split recipient outputs
    const size_t n = destinationConfAddrs.size();
    uint64_t remaining = 0;
    if (feeAssetSame) remaining = transferTotalIn - feeSats;
    else remaining = transferTotalIn;

    std::vector<uint64_t> output_values;
    output_values.reserve(n);
    uint64_t perOut = remaining / static_cast<uint64_t>(n);
    uint64_t sum = 0;
    for (size_t i = 0; i + 1 < n; i++) {
        output_values.push_back(perOut);
        sum += perOut;
    }
    output_values.push_back(remaining - sum);

    const uint64_t feeRemaining = (feeAssetSame ? 0 : (feeTotalIn - feeSats));

    // Decompose destinations
    std::vector<ConfidentialDestDecomp> dests;
    dests.reserve(n);
    for (const auto& confAddr : destinationConfAddrs) {
        dests.push_back(confidential_addr_to_dest_decomp(confAddr, confAddrFamily, addrFamily));
    }

    // fee change optional decomposition
    const bool createFeeChange = (!feeAssetSame && feeRemaining > 0 && !feeChangeConfAddr.empty());
    ConfidentialDestDecomp feeChangeDest;
    if (!feeAssetSame && feeRemaining > 0 && feeChangeConfAddr.empty()) {
        throw std::runtime_error("feeChangeConfAddr is required when feeRemaining > 0 and feeAsset != assetIdToSend");
    }
    if (createFeeChange) {
        feeChangeDest = confidential_addr_to_dest_decomp(feeChangeConfAddr, confAddrFamily, addrFamily);
    }

    // Blinding factors for recipients:
    std::vector<std::vector<unsigned char>> abfs_recipient(n, std::vector<unsigned char>(32));
    std::vector<std::vector<unsigned char>> vbfs_recipient_all(n, std::vector<unsigned char>(32));

    for (size_t i = 0; i < n; i++) abfs_recipient[i] = rand_bytes(32);
    for (size_t i = 0; i + 1 < n; i++) vbfs_recipient_all[i] = rand_bytes(32);

    // Build transfer arrays for asset_final_vbf
    std::vector<uint64_t> transfer_values_in;
    transfer_values_in.reserve(transferIdx.size());
    std::vector<unsigned char> transfer_abfs_in;
    std::vector<unsigned char> transfer_vbfs_in;
    for (auto idx : transferIdx) {
        transfer_values_in.push_back(values_in[idx]);
        transfer_abfs_in.insert(transfer_abfs_in.end(), abfs_in.begin() + idx * 32, abfs_in.begin() + (idx + 1) * 32);
        transfer_vbfs_in.insert(transfer_vbfs_in.end(), vbfs_in.begin() + idx * 32, vbfs_in.begin() + (idx + 1) * 32);
    }

    // Prepare asset_final_vbf for transfer recipients
    std::vector<uint64_t> transfer_values_for_vbf = transfer_values_in;
    if (feeAssetSame) transfer_values_for_vbf.push_back(feeSats);
    transfer_values_for_vbf.insert(transfer_values_for_vbf.end(), output_values.begin(), output_values.end());

    std::vector<unsigned char> transfer_abfs_for_vbf = transfer_abfs_in;
    std::vector<unsigned char> transfer_vbfs_for_vbf = transfer_vbfs_in;
    if (feeAssetSame) transfer_abfs_for_vbf.insert(transfer_abfs_for_vbf.end(), ZERO32.begin(), ZERO32.end());
    // recipients abfs
    for (size_t i = 0; i < n; i++) {
        transfer_abfs_for_vbf.insert(transfer_abfs_for_vbf.end(), abfs_recipient[i].begin(), abfs_recipient[i].end());
    }
    if (feeAssetSame) transfer_vbfs_for_vbf.insert(transfer_vbfs_for_vbf.end(), ZERO32.begin(), ZERO32.end());
    // recipients vbf except last
    for (size_t i = 0; i + 1 < n; i++) {
        transfer_vbfs_for_vbf.insert(transfer_vbfs_for_vbf.end(), vbfs_recipient_all[i].begin(), vbfs_recipient_all[i].end());
    }

    std::vector<unsigned char> vbf_final(32, 0);
    check_ret("wally_asset_final_vbf(transfer)",
              wally_asset_final_vbf(transfer_values_for_vbf.data(), transfer_values_for_vbf.size(),
                                    transferIdx.size(),
                                    transfer_abfs_for_vbf.data(), transfer_abfs_for_vbf.size(),
                                    transfer_vbfs_for_vbf.data(), transfer_vbfs_for_vbf.size(),
                                    vbf_final.data(), vbf_final.size()));
    vbfs_recipient_all[n - 1] = vbf_final;

    // Prepare fee change blinding factors if needed
    std::vector<unsigned char> feeChange_abf(32, 0);
    std::vector<unsigned char> feeChange_vbf(32, 0);
    std::vector<unsigned char> fee_abfs_in;
    std::vector<unsigned char> fee_vbfs_in;
    std::vector<uint64_t> fee_values_in;

    if (createFeeChange) {
        for (auto idx : feeIdx) {
            fee_values_in.push_back(values_in[idx]);
            fee_abfs_in.insert(fee_abfs_in.end(), abfs_in.begin() + idx * 32, abfs_in.begin() + (idx + 1) * 32);
            fee_vbfs_in.insert(fee_vbfs_in.end(), vbfs_in.begin() + idx * 32, vbfs_in.begin() + (idx + 1) * 32);
        }
        feeChange_abf = rand_bytes(32);

        // feeChange_vbf equation: values = feeValuesIn + [feeSats, feeRemaining]
        std::vector<uint64_t> fee_values_for_vbf = fee_values_in;
        fee_values_for_vbf.push_back(feeSats);
        fee_values_for_vbf.push_back(feeRemaining);

        std::vector<unsigned char> fee_abfs_for_vbf = fee_abfs_in;
        fee_abfs_for_vbf.insert(fee_abfs_for_vbf.end(), ZERO32.begin(), ZERO32.end()); // explicit fee output abf=0
        fee_abfs_for_vbf.insert(fee_abfs_for_vbf.end(), feeChange_abf.begin(), feeChange_abf.end());

        std::vector<unsigned char> fee_vbfs_for_vbf = fee_vbfs_in;
        fee_vbfs_for_vbf.insert(fee_vbfs_for_vbf.end(), ZERO32.begin(), ZERO32.end()); // explicit fee output vbf=0

        check_ret("wally_asset_final_vbf(fee change)",
                  wally_asset_final_vbf(fee_values_for_vbf.data(), fee_values_for_vbf.size(),
                                        feeIdx.size(),
                                        fee_abfs_for_vbf.data(), fee_abfs_for_vbf.size(),
                                        fee_vbfs_for_vbf.data(), fee_vbfs_for_vbf.size(),
                                        feeChange_vbf.data(), feeChange_vbf.size()));
    }

    // Build inputIdxCombined (vin order) and combined arrays for surjectionproof
    std::vector<size_t> inputIdxCombined = transferIdx;
    if (!feeAssetSame) inputIdxCombined.insert(inputIdxCombined.end(), feeIdx.begin(), feeIdx.end());
    const size_t num_inputs_combined = inputIdxCombined.size();

    std::vector<std::vector<unsigned char>> combined_input_prev_txid_for_vin;
    std::vector<uint32_t> combined_vouts_in;
    std::vector<std::vector<unsigned char>> combined_script_pubkeys_in;
    std::vector<std::vector<unsigned char>> combined_value_commitments_in;
    combined_input_prev_txid_for_vin.reserve(num_inputs_combined);
    combined_vouts_in.reserve(num_inputs_combined);
    combined_script_pubkeys_in.reserve(num_inputs_combined);
    combined_value_commitments_in.reserve(num_inputs_combined);

    for (auto idx : inputIdxCombined) {
        combined_input_prev_txid_for_vin.push_back(input_prev_txid_for_vin[idx]);
        combined_vouts_in.push_back(vouts_in[idx]);
        combined_script_pubkeys_in.push_back(script_pubkeys_in[idx]);
        combined_value_commitments_in.push_back(value_commitments_in[idx]);
    }

    std::vector<unsigned char> combined_asset_ids_in_for_surj;
    std::vector<unsigned char> combined_abfs_in_for_surj;
    std::vector<unsigned char> combined_asset_generators_in_for_surj;
    combined_asset_ids_in_for_surj.reserve(num_inputs_combined * 32);
    combined_abfs_in_for_surj.reserve(num_inputs_combined * 32);
    combined_asset_generators_in_for_surj.reserve(num_inputs_combined * ASSET_GENERATOR_LEN);

    for (auto idx : inputIdxCombined) {
        combined_asset_ids_in_for_surj.insert(combined_asset_ids_in_for_surj.end(),
                                             asset_ids_in.begin() + idx * 32, asset_ids_in.begin() + (idx + 1) * 32);
        combined_abfs_in_for_surj.insert(combined_abfs_in_for_surj.end(),
                                         abfs_in.begin() + idx * 32, abfs_in.begin() + (idx + 1) * 32);
        combined_asset_generators_in_for_surj.insert(combined_asset_generators_in_for_surj.end(),
                                                       asset_generators_in.begin() + idx * ASSET_GENERATOR_LEN,
                                                       asset_generators_in.begin() + (idx + 1) * ASSET_GENERATOR_LEN);
    }

    // Create tx
    const size_t num_outputs = 1 + n + (createFeeChange ? 1 : 0);
    struct wally_tx* output_tx = nullptr;
    check_ret("wally_tx_init_alloc",
              wally_tx_init_alloc(2, 0, num_inputs_combined, num_outputs, &output_tx));

    // Fee output explicit (vout0)
    std::vector<unsigned char> fee_asset(1 + 32);
    fee_asset[0] = 0x01;
    std::memcpy(fee_asset.data() + 1, feeAssetId.data(), 32);

    std::vector<unsigned char> fee_value(WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN);
    check_ret("wally_tx_confidential_value_from_satoshi",
              wally_tx_confidential_value_from_satoshi(feeSats, fee_value.data(), fee_value.size()));

    check_ret("wally_tx_add_elements_raw_output(fee)",
              wally_tx_add_elements_raw_output(output_tx,
                                                nullptr, 0,
                                                fee_asset.data(), fee_asset.size(),
                                                fee_value.data(), fee_value.size(),
                                                nullptr, 0,
                                                nullptr, 0,
                                                nullptr, 0,
                                                0));

    // Recipient outputs (transfer asset)
    for (size_t i = 0; i < n; i++) {
        const uint64_t value = output_values[i];
        const auto& abf = abfs_recipient[i];
        const auto& vbf = vbfs_recipient_all[i];
        const auto& blinding_pubkey = dests[i].blinding_pubkey;
        const auto& script_pubkey = dests[i].script_pubkey;

        std::vector<unsigned char> generator(ASSET_GENERATOR_LEN);
        check_ret("wally_asset_generator_from_bytes(transfer)",
                  wally_asset_generator_from_bytes(assetIdToSend.data(), assetIdToSend.size(),
                                                   abf.data(), abf.size(),
                                                   generator.data(), generator.size()));

        std::vector<unsigned char> value_commitment_out(ASSET_COMMITMENT_LEN);
        check_ret("wally_asset_value_commitment(transfer)",
                  wally_asset_value_commitment(value,
                                               vbf.data(), vbf.size(),
                                               generator.data(), generator.size(),
                                               value_commitment_out.data(), value_commitment_out.size()));

        auto eph_priv = rand_ec_private_key();
        std::vector<unsigned char> eph_pub(EC_PUBLIC_KEY_LEN);
        check_ret("wally_ec_public_key_from_private_key(ephemeral)",
                  wally_ec_public_key_from_private_key(eph_priv.data(), eph_priv.size(),
                                                       eph_pub.data(), eph_pub.size()));

        std::vector<unsigned char> rangeproof(ASSET_RANGEPROOF_MAX_LEN);
        size_t rangeproof_len = 0;
        check_ret("wally_asset_rangeproof(transfer)",
                  wally_asset_rangeproof(value,
                                         blinding_pubkey.data(), blinding_pubkey.size(),
                                         eph_priv.data(), eph_priv.size(),
                                         assetIdToSend.data(), assetIdToSend.size(),
                                         abf.data(), abf.size(),
                                         vbf.data(), vbf.size(),
                                         value_commitment_out.data(), value_commitment_out.size(),
                                         script_pubkey.data(), script_pubkey.size(),
                                         generator.data(), generator.size(),
                                         1, 0, 36,
                                         rangeproof.data(), rangeproof.size(),
                                         &rangeproof_len));
        rangeproof.resize(rangeproof_len);

        std::vector<unsigned char> surj(ASSET_SURJECTIONPROOF_MAX_LEN);
        size_t surj_len = ASSET_SURJECTIONPROOF_MAX_LEN;
        auto surj_entropy = rand_bytes(32);
        check_ret("wally_asset_surjectionproof(transfer)",
                  wally_asset_surjectionproof(assetIdToSend.data(), assetIdToSend.size(),
                                              abf.data(), abf.size(),
                                              generator.data(), generator.size(),
                                              surj_entropy.data(), surj_entropy.size(),
                                              combined_asset_ids_in_for_surj.data(), combined_asset_ids_in_for_surj.size(),
                                              combined_abfs_in_for_surj.data(), combined_abfs_in_for_surj.size(),
                                              combined_asset_generators_in_for_surj.data(), combined_asset_generators_in_for_surj.size(),
                                              surj.data(), surj.size(),
                                              &surj_len));
        surj.resize(surj_len);

        check_ret("wally_tx_add_elements_raw_output(recipient)",
                  wally_tx_add_elements_raw_output(output_tx,
                                                    script_pubkey.data(), script_pubkey.size(),
                                                    generator.data(), generator.size(),
                                                    value_commitment_out.data(), value_commitment_out.size(),
                                                    eph_pub.data(), eph_pub.size(),
                                                    surj.data(), surj.size(),
                                                    rangeproof.data(), rangeproof.size(),
                                                    0));
    }

    // Fee change output (if any)
    if (createFeeChange) {
        std::vector<unsigned char> generator(ASSET_GENERATOR_LEN);
        check_ret("wally_asset_generator_from_bytes(fee change)",
                  wally_asset_generator_from_bytes(feeAssetId.data(), feeAssetId.size(),
                                                   feeChange_abf.data(), feeChange_abf.size(),
                                                   generator.data(), generator.size()));

        std::vector<unsigned char> value_commitment_out(ASSET_COMMITMENT_LEN);
        check_ret("wally_asset_value_commitment(fee change)",
                  wally_asset_value_commitment(feeRemaining,
                                               feeChange_vbf.data(), feeChange_vbf.size(),
                                               generator.data(), generator.size(),
                                               value_commitment_out.data(), value_commitment_out.size()));

        auto eph_priv = rand_ec_private_key();
        std::vector<unsigned char> eph_pub(EC_PUBLIC_KEY_LEN);
        check_ret("wally_ec_public_key_from_private_key(ephemeral fee change)",
                  wally_ec_public_key_from_private_key(eph_priv.data(), eph_priv.size(),
                                                       eph_pub.data(), eph_pub.size()));

        std::vector<unsigned char> rangeproof(ASSET_RANGEPROOF_MAX_LEN);
        size_t rangeproof_len = 0;
        check_ret("wally_asset_rangeproof(fee change)",
                  wally_asset_rangeproof(feeRemaining,
                                         feeChangeDest.blinding_pubkey.data(), feeChangeDest.blinding_pubkey.size(),
                                         eph_priv.data(), eph_priv.size(),
                                         feeAssetId.data(), feeAssetId.size(),
                                         feeChange_abf.data(), feeChange_abf.size(),
                                         feeChange_vbf.data(), feeChange_vbf.size(),
                                         value_commitment_out.data(), value_commitment_out.size(),
                                         feeChangeDest.script_pubkey.data(), feeChangeDest.script_pubkey.size(),
                                         generator.data(), generator.size(),
                                         1, 0, 36,
                                         rangeproof.data(), rangeproof.size(),
                                         &rangeproof_len));
        rangeproof.resize(rangeproof_len);

        std::vector<unsigned char> surj(ASSET_SURJECTIONPROOF_MAX_LEN);
        size_t surj_len = ASSET_SURJECTIONPROOF_MAX_LEN;
        auto surj_entropy = rand_bytes(32);
        check_ret("wally_asset_surjectionproof(fee change)",
                  wally_asset_surjectionproof(feeAssetId.data(), feeAssetId.size(),
                                              feeChange_abf.data(), feeChange_abf.size(),
                                              generator.data(), generator.size(),
                                              surj_entropy.data(), surj_entropy.size(),
                                              combined_asset_ids_in_for_surj.data(), combined_asset_ids_in_for_surj.size(),
                                              combined_abfs_in_for_surj.data(), combined_abfs_in_for_surj.size(),
                                              combined_asset_generators_in_for_surj.data(), combined_asset_generators_in_for_surj.size(),
                                              surj.data(), surj.size(),
                                              &surj_len));
        surj.resize(surj_len);

        check_ret("wally_tx_add_elements_raw_output(fee change)",
                  wally_tx_add_elements_raw_output(output_tx,
                                                    feeChangeDest.script_pubkey.data(), feeChangeDest.script_pubkey.size(),
                                                    generator.data(), generator.size(),
                                                    value_commitment_out.data(), value_commitment_out.size(),
                                                    eph_pub.data(), eph_pub.size(),
                                                    surj.data(), surj.size(),
                                                    rangeproof.data(), rangeproof.size(),
                                                    0));
    }

    // Inputs spending prevouts
    for (size_t vin = 0; vin < num_inputs_combined; vin++) {
        const auto& prevTxid = combined_input_prev_txid_for_vin[vin];
        check_ret("wally_tx_add_elements_raw_input",
                  wally_tx_add_elements_raw_input(output_tx,
                                                  prevTxid.data(), prevTxid.size(),
                                                  combined_vouts_in[vin],
                                                  0xffffffff,
                                                  nullptr, 0, // script + script_len
                                                  nullptr,    // witness
                                                  nullptr, 0, // nonce + nonce_len
                                                  nullptr, 0, // entropy + entropy_len
                                                  nullptr, 0, // issuance_amount + issuance_amount_len
                                                  nullptr, 0, // inflation_keys + inflation_keys_len
                                                  nullptr, 0, // issuance_amount_rangeproof + issuance_amount_rangeproof_len
                                                  nullptr, 0, // inflation_keys_rangeproof + inflation_keys_rangeproof_len
                                                  nullptr,    // pegin_witness
                                                  0));         // flags
    }

    // Sign P2WPKH (all inputs)
    std::vector<unsigned char> pubkeyhash(HASH160_LEN);
    check_ret("wally_hash160",
              wally_hash160(signingPubKey.data(), signingPubKey.size(), pubkeyhash.data(), pubkeyhash.size()));

    std::vector<unsigned char> script_code(256);
    size_t script_code_len = 0;
    check_ret("wally_scriptpubkey_p2pkh_from_bytes",
              wally_scriptpubkey_p2pkh_from_bytes(pubkeyhash.data(), pubkeyhash.size(),
                                                  0,
                                                  script_code.data(), script_code.size(),
                                                  &script_code_len));
    script_code.resize(script_code_len);

    for (size_t vin = 0; vin < num_inputs_combined; vin++) {
        const auto& utxo_script = combined_script_pubkeys_in[vin];
        const unsigned char* expected_ptr = utxo_script.data() + 2;
        if (utxo_script.size() < 2 + HASH160_LEN) throw std::runtime_error("unexpected utxo script length");
        if (std::memcmp(expected_ptr, pubkeyhash.data(), HASH160_LEN) != 0) {
            throw std::runtime_error("Signing key mismatch for vin");
        }

        std::vector<unsigned char> sighash(SHA256_LEN);
        const auto& prevout_value = combined_value_commitments_in[vin]; // 33 bytes
        check_ret("wally_tx_get_elements_signature_hash",
                  wally_tx_get_elements_signature_hash(output_tx,
                                                        vin,
                                                        script_code.data(), script_code.size(),
                                                        prevout_value.data(), prevout_value.size(),
                                                        WALLY_SIGHASH_ALL,
                                                        WALLY_TX_FLAG_USE_WITNESS,
                                                        sighash.data(), sighash.size()));

        std::vector<unsigned char> sig64(EC_SIGNATURE_LEN);
        check_ret("wally_ec_sig_from_bytes",
                  wally_ec_sig_from_bytes(signingPrivKey.data(), signingPrivKey.size(),
                                          sighash.data(), sighash.size(),
                                          EC_FLAG_ECDSA,
                                          sig64.data(), sig64.size()));

        check_ret("wally_ec_sig_verify",
                  wally_ec_sig_verify(signingPubKey.data(), signingPubKey.size(),
                                      sighash.data(), sighash.size(),
                                      EC_FLAG_ECDSA,
                                      sig64.data(), sig64.size()));

        // Convert to DER and append hash type
        size_t sig_der_len = 0;
        std::vector<unsigned char> sig_der(EC_SIGNATURE_DER_MAX_LEN);
        check_ret("wally_ec_sig_to_der",
                  wally_ec_sig_to_der(sig64.data(), sig64.size(),
                                      sig_der.data(), sig_der.size(),
                                      &sig_der_len));
        sig_der.resize(sig_der_len);
        sig_der.push_back(static_cast<unsigned char>(WALLY_SIGHASH_ALL));

        struct wally_tx_witness_stack* wit = nullptr;
        check_ret("wally_tx_witness_stack_init_alloc",
                  wally_tx_witness_stack_init_alloc(2, &wit));
        check_ret("wally_tx_witness_stack_add(sig)",
                  wally_tx_witness_stack_add(wit, sig_der.data(), sig_der.size()));
        check_ret("wally_tx_witness_stack_add(pub)",
                  wally_tx_witness_stack_add(wit, signingPubKey.data(), signingPubKey.size()));
        check_ret("wally_tx_set_input_witness",
                  wally_tx_set_input_witness(output_tx, vin, wit));
        wally_tx_witness_stack_free(wit);
    }

    // Serialize
    char* txhex = nullptr;
    check_ret("wally_tx_to_hex",
              wally_tx_to_hex(output_tx,
                              WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS,
                              &txhex));
    std::string txHexOut(txhex);
    wally_free_string(txhex);

    std::vector<unsigned char> txid_internal(32);
    check_ret("wally_tx_get_txid(out)",
              wally_tx_get_txid(output_tx, txid_internal.data(), txid_internal.size()));
    std::reverse(txid_internal.begin(), txid_internal.end());

    std::string txid = hex_from_bytes(txid_internal.data(), txid_internal.size());

    wally_tx_free(output_tx);
    for (auto& u : utxos) {
        if (u.tx) wally_tx_free(u.tx);
    }
    return {txHexOut, txid};
}

SendResult sendLbtcToConfidentialAddresses(const std::vector<std::string>& prevTxHexes,
                                          const std::vector<unsigned char>& ourScriptPubKey,
                                          const std::vector<unsigned char>& privateBlindingKey,
                                          const std::vector<std::string>& destinationConfAddrs,
                                          uint64_t feeSats,
                                          const std::string& addrFamily,
                                          const std::string& confAddrFamily,
                                          const std::vector<unsigned char>& signingPrivKey,
                                          const std::vector<unsigned char>& signingPubKey) {
    if (prevTxHexes.empty()) throw std::runtime_error("prevTxHexes must be non-empty");
    if (destinationConfAddrs.empty()) throw std::runtime_error("destinationConfAddrs must be non-empty");

    std::vector<UtxoSet> utxos;
    utxos.reserve(prevTxHexes.size());
    for (const auto& hex : prevTxHexes) utxos.push_back(getConfidentialUtxosFromTx(hex, ourScriptPubKey, privateBlindingKey));

    // Merge
    std::vector<unsigned char> asset_generators_in;
    std::vector<unsigned char> asset_ids_in;
    std::vector<uint64_t> values_in;
    std::vector<unsigned char> abfs_in;
    std::vector<unsigned char> vbfs_in;
    std::vector<std::vector<unsigned char>> script_pubkeys_in;
    std::vector<std::vector<unsigned char>> value_commitments_in;
    std::vector<uint32_t> vouts_in;
    std::vector<std::vector<unsigned char>> input_prev_txid_for_vin;

    for (auto& u : utxos) {
        asset_generators_in.insert(asset_generators_in.end(), u.asset_generators_in.begin(), u.asset_generators_in.end());
        asset_ids_in.insert(asset_ids_in.end(), u.asset_ids_in.begin(), u.asset_ids_in.end());
        values_in.insert(values_in.end(), u.values_in.begin(), u.values_in.end());
        abfs_in.insert(abfs_in.end(), u.abfs_in.begin(), u.abfs_in.end());
        vbfs_in.insert(vbfs_in.end(), u.vbfs_in.begin(), u.vbfs_in.end());
        script_pubkeys_in.insert(script_pubkeys_in.end(), u.script_pubkeys_in.begin(), u.script_pubkeys_in.end());
        value_commitments_in.insert(value_commitments_in.end(), u.value_commitments_in.begin(), u.value_commitments_in.end());
        vouts_in.insert(vouts_in.end(), u.vouts_in.begin(), u.vouts_in.end());
        for (size_t i = 0; i < u.vouts_in.size(); i++) input_prev_txid_for_vin.push_back(u.prevTxid);
    }

    const size_t num_inputs = values_in.size();
    if (num_inputs == 0) throw std::runtime_error("No spendable outputs found in prev tx(s) for our script_pubkey");

    unsigned __int128 total_in = 0;
    for (auto v : values_in) total_in += v;
    if (total_in <= feeSats) throw std::runtime_error("Input amount is not enough to pay fee");
    const uint64_t remaining = static_cast<uint64_t>(total_in - feeSats);

    // All inputs must be same asset id (32-byte chunks)
    if (asset_ids_in.size() != 32 * num_inputs) throw std::runtime_error("asset_ids_in size mismatch");
    for (size_t i = 1; i < num_inputs; i++) {
        if (std::memcmp(asset_ids_in.data(), asset_ids_in.data() + 32 * i, 32) != 0) {
            throw std::runtime_error("Inputs are not the same asset; this example only supports single-asset LBTC spends");
        }
    }
    const unsigned char* output_asset_id = asset_ids_in.data(); // 32 bytes

    // Split remaining equally across recipients; last output gets remainder
    const size_t n = destinationConfAddrs.size();
    std::vector<uint64_t> output_values;
    output_values.reserve(n);
    const uint64_t perOut = remaining / static_cast<uint64_t>(n);
    uint64_t sum = 0;
    for (size_t i = 0; i + 1 < n; i++) {
        output_values.push_back(perOut);
        sum += perOut;
    }
    output_values.push_back(remaining - sum);

    // Decompose destination confidential addresses into (blinding_pubkey, script_pubkey)
    struct DestDecomp { std::vector<unsigned char> blinding_pubkey; std::vector<unsigned char> script_pubkey; };
    std::vector<DestDecomp> dests;
    dests.reserve(n);
    for (const auto& confAddr : destinationConfAddrs) {
        DestDecomp d;
        d.blinding_pubkey.resize(EC_PUBLIC_KEY_LEN);
        check_ret("wally_confidential_addr_segwit_to_ec_public_key",
                  wally_confidential_addr_segwit_to_ec_public_key(confAddr.c_str(), confAddrFamily.c_str(),
                                                                  d.blinding_pubkey.data(), d.blinding_pubkey.size()));

        char* non_conf = nullptr;
        check_ret("wally_confidential_addr_to_addr_segwit",
                  wally_confidential_addr_to_addr_segwit(confAddr.c_str(), confAddrFamily.c_str(), addrFamily.c_str(), &non_conf));

        // scriptpubkey bytes
        d.script_pubkey.resize(128);
        size_t spk_len = 0;
        check_ret("wally_addr_segwit_to_bytes",
                  wally_addr_segwit_to_bytes(non_conf, addrFamily.c_str(), 0, d.script_pubkey.data(), d.script_pubkey.size(), &spk_len));
        d.script_pubkey.resize(spk_len);

        wally_free_string(non_conf);
        dests.push_back(std::move(d));
    }

    // Fee output is explicit: asset = 0x01 || asset_id, value = confidential_value_from_satoshi(fee), nonce/surj/range = empty
    std::vector<unsigned char> fee_asset(1 + 32);
    fee_asset[0] = 0x01;
    std::memcpy(fee_asset.data() + 1, output_asset_id, 32);
    std::vector<unsigned char> fee_value(WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN);
    check_ret("wally_tx_confidential_value_from_satoshi",
              wally_tx_confidential_value_from_satoshi(feeSats, fee_value.data(), fee_value.size()));

    // Blinding factors for outputs: fee (abf=0, vbf=0), recipients abf random each, vbf random for first n-1, final via asset_final_vbf
    std::vector<unsigned char> ZERO32(32, 0);
    std::vector<std::vector<unsigned char>> abfs_rec(n);
    std::vector<std::vector<unsigned char>> vbfs_rec(n);
    for (size_t i = 0; i < n; i++) abfs_rec[i] = rand_bytes(32);
    for (size_t i = 0; i + 1 < n; i++) vbfs_rec[i] = rand_bytes(32);

    // Build arrays for asset_final_vbf
    std::vector<uint64_t> values_all = values_in;
    values_all.push_back(feeSats);
    values_all.insert(values_all.end(), output_values.begin(), output_values.end());

    std::vector<unsigned char> abfs_all = abfs_in;
    abfs_all.insert(abfs_all.end(), ZERO32.begin(), ZERO32.end()); // fee abf
    for (size_t i = 0; i < n; i++) abfs_all.insert(abfs_all.end(), abfs_rec[i].begin(), abfs_rec[i].end());

    std::vector<unsigned char> vbfs_known = vbfs_in;
    vbfs_known.insert(vbfs_known.end(), ZERO32.begin(), ZERO32.end()); // fee vbf
    for (size_t i = 0; i + 1 < n; i++) vbfs_known.insert(vbfs_known.end(), vbfs_rec[i].begin(), vbfs_rec[i].end());

    vbfs_rec[n - 1].resize(32);
    check_ret("wally_asset_final_vbf",
              wally_asset_final_vbf(values_all.data(), values_all.size(),
                                    num_inputs,
                                    abfs_all.data(), abfs_all.size(),
                                    vbfs_known.data(), vbfs_known.size(),
                                    vbfs_rec[n - 1].data(), vbfs_rec[n - 1].size()));

    // Create tx
    struct wally_tx* tx = nullptr;
    const size_t num_outputs = 1 + n;
    check_ret("wally_tx_init_alloc", wally_tx_init_alloc(2, 0, num_inputs, num_outputs, &tx));

    // Fee output (explicit). Note: pass nullptr for empty fields.
    check_ret("wally_tx_add_elements_raw_output(fee)",
              wally_tx_add_elements_raw_output(tx,
                                               nullptr, 0,
                                               fee_asset.data(), fee_asset.size(),
                                               fee_value.data(), fee_value.size(),
                                               nullptr, 0,
                                               nullptr, 0,
                                               nullptr, 0,
                                               0));

    // Recipient outputs (blinded)
    for (size_t i = 0; i < n; i++) {
        const uint64_t value = output_values[i];
        const auto& abf = abfs_rec[i];
        const auto& vbf = vbfs_rec[i];
        const auto& blinding_pubkey = dests[i].blinding_pubkey;
        const auto& script_pubkey = dests[i].script_pubkey;

        std::vector<unsigned char> generator(ASSET_GENERATOR_LEN);
        check_ret("wally_asset_generator_from_bytes(out)",
                  wally_asset_generator_from_bytes(output_asset_id, 32,
                                                   abf.data(), abf.size(),
                                                   generator.data(), generator.size()));

        std::vector<unsigned char> value_commitment(ASSET_GENERATOR_LEN);
        check_ret("wally_asset_value_commitment(out)",
                  wally_asset_value_commitment(value,
                                               vbf.data(), vbf.size(),
                                               generator.data(), generator.size(),
                                               value_commitment.data(), value_commitment.size()));

        auto eph_priv = rand_ec_private_key();
        std::vector<unsigned char> eph_pub(EC_PUBLIC_KEY_LEN);
        check_ret("wally_ec_public_key_from_private_key",
                  wally_ec_public_key_from_private_key(eph_priv.data(), eph_priv.size(), eph_pub.data(), eph_pub.size()));

        // Rangeproof and surjectionproof
        size_t rangeproof_len = 0;
        std::vector<unsigned char> rangeproof(ASSET_RANGEPROOF_MAX_LEN);
        check_ret("wally_asset_rangeproof",
                  wally_asset_rangeproof(value,
                                         blinding_pubkey.data(), blinding_pubkey.size(),
                                         eph_priv.data(), eph_priv.size(),
                                         output_asset_id, 32,
                                         abf.data(), abf.size(),
                                         vbf.data(), vbf.size(),
                                         value_commitment.data(), value_commitment.size(),
                                         script_pubkey.data(), script_pubkey.size(),
                                         generator.data(), generator.size(),
                                         1,
                                         0,
                52,
                                         rangeproof.data(), rangeproof.size(),
                                         &rangeproof_len));
        rangeproof.resize(rangeproof_len);

        size_t surj_len = ASSET_SURJECTIONPROOF_MAX_LEN;
        std::vector<unsigned char> surj(surj_len);
        check_ret("wally_asset_surjectionproof",
                  wally_asset_surjectionproof(output_asset_id, 32,
                                              abf.data(), abf.size(),
                                              generator.data(), generator.size(),
                                              rand_bytes(32).data(), 32,
                                              asset_ids_in.data(), asset_ids_in.size(),
                                              abfs_in.data(), abfs_in.size(),
                                              asset_generators_in.data(), asset_generators_in.size(),
                                              surj.data(), surj.size(),
                                              &surj_len));
        surj.resize(surj_len);

        check_ret("wally_tx_add_elements_raw_output(recipient)",
                  wally_tx_add_elements_raw_output(tx,
                                                   script_pubkey.data(), script_pubkey.size(),
                                                   generator.data(), generator.size(),
                                                   value_commitment.data(), value_commitment.size(),
                                                   eph_pub.data(), eph_pub.size(),
                                                   surj.data(), surj.size(),
                                                   rangeproof.data(), rangeproof.size(),
                                                   0));
    }

    // Add inputs
    for (size_t vin = 0; vin < num_inputs; vin++) {
        const auto& prevTxid = input_prev_txid_for_vin[vin];
        check_ret("wally_tx_add_elements_raw_input",
                  wally_tx_add_elements_raw_input(tx,
                                                  prevTxid.data(), prevTxid.size(),
                                                  vouts_in[vin],
                                                  0xffffffff,
                                                  nullptr, 0,
                                                  nullptr,
                                                  nullptr, 0,
                                                  nullptr, 0,
                                                  nullptr, 0,
                                                  nullptr, 0,
                                                  nullptr, 0,
                                                  nullptr, 0,
                                                  nullptr,
                                                  0));
    }

    // Sign all inputs as P2WPKH
    std::vector<unsigned char> pubkeyhash(HASH160_LEN);
    check_ret("wally_hash160", wally_hash160(signingPubKey.data(), signingPubKey.size(), pubkeyhash.data(), pubkeyhash.size()));

    std::vector<unsigned char> script_code(128);
    size_t script_code_len = 0;
    check_ret("wally_scriptpubkey_p2pkh_from_bytes",
              wally_scriptpubkey_p2pkh_from_bytes(pubkeyhash.data(), pubkeyhash.size(),
                                                  0,
                                                  script_code.data(), script_code.size(),
                                                  &script_code_len));
    script_code.resize(script_code_len);

    for (size_t vin = 0; vin < num_inputs; vin++) {
        const auto& utxo_script = script_pubkeys_in[vin];
        if (utxo_script.size() < 2 + HASH160_LEN) throw std::runtime_error("unexpected utxo script length");
        if (std::memcmp(utxo_script.data() + 2, pubkeyhash.data(), HASH160_LEN) != 0) {
            throw std::runtime_error("Signing key mismatch for vin=" + std::to_string(vin));
        }

        std::vector<unsigned char> sighash(SHA256_LEN);
        const auto& prevout_value = value_commitments_in[vin]; // 33 bytes
        check_ret("wally_tx_get_elements_signature_hash",
                  wally_tx_get_elements_signature_hash(tx,
                                                       vin,
                                                       script_code.data(), script_code.size(),
                                                       prevout_value.data(), prevout_value.size(),
                                                       WALLY_SIGHASH_ALL,
                                                       WALLY_TX_FLAG_USE_WITNESS,
                                                       sighash.data(), sighash.size()));

        std::vector<unsigned char> sig64(EC_SIGNATURE_LEN);
        check_ret("wally_ec_sig_from_bytes",
                  wally_ec_sig_from_bytes(signingPrivKey.data(), signingPrivKey.size(),
                                          sighash.data(), sighash.size(),
                                          EC_FLAG_ECDSA,
                                          sig64.data(), sig64.size()));

        check_ret("wally_ec_sig_verify",
                  wally_ec_sig_verify(signingPubKey.data(), signingPubKey.size(),
                                      sighash.data(), sighash.size(),
                                      EC_FLAG_ECDSA,
                                      sig64.data(), sig64.size()));

        size_t sig_der_len = 0;
        std::vector<unsigned char> sig_der(EC_SIGNATURE_DER_MAX_LEN);
        check_ret("wally_ec_sig_to_der",
                  wally_ec_sig_to_der(sig64.data(), sig64.size(), sig_der.data(), sig_der.size(), &sig_der_len));
        sig_der.resize(sig_der_len);
        sig_der.push_back(static_cast<unsigned char>(WALLY_SIGHASH_ALL));

        struct wally_tx_witness_stack* wit = nullptr;
        check_ret("wally_tx_witness_stack_init_alloc", wally_tx_witness_stack_init_alloc(2, &wit));
        check_ret("wally_tx_witness_stack_add(sig)", wally_tx_witness_stack_add(wit, sig_der.data(), sig_der.size()));
        check_ret("wally_tx_witness_stack_add(pub)", wally_tx_witness_stack_add(wit, signingPubKey.data(), signingPubKey.size()));
        check_ret("wally_tx_set_input_witness", wally_tx_set_input_witness(tx, vin, wit));
        wally_tx_witness_stack_free(wit);
    }

    // Serialize
    char* txhex = nullptr;
    check_ret("wally_tx_to_hex",
              wally_tx_to_hex(tx, WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS, &txhex));
    std::string txHexOut(txhex);
    wally_free_string(txhex);

    std::vector<unsigned char> txid_internal(32);
    check_ret("wally_tx_get_txid(out)", wally_tx_get_txid(tx, txid_internal.data(), txid_internal.size()));
    std::reverse(txid_internal.begin(), txid_internal.end());
    std::string txid = hex_from_bytes(txid_internal.data(), txid_internal.size());

    wally_tx_free(tx);
    for (auto& u : utxos) if (u.tx) wally_tx_free(u.tx);

    return {txHexOut, txid};
}

} // namespace

int main() {
    wally::init(0);
    try {
        uint32_t version = 0;
        wally_get_build_version(&version);
        std::cout << "Wally version: " << version << std::endl;

        // Deterministic seed (test mnemonic)
        std::vector<unsigned char> seed(BIP39_SEED_LEN_512);
        check_ret("bip39_mnemonic_to_seed512",
                  bip39_mnemonic_to_seed512("test test test test test test test test test test test test", "",
                                            seed.data(), seed.size()));

        struct ext_key* master = nullptr;
        check_ret("bip32_key_from_seed_alloc",
                  bip32_key_from_seed_alloc(seed.data(), seed.size(), BIP32_VER_TEST_PRIVATE, 0, &master));

        struct ext_key* derived = nullptr;
        check_ret("bip32_key_from_parent_alloc",
                  bip32_key_from_parent_alloc(master, 8, BIP32_FLAG_KEY_PRIVATE, &derived));

        char* address = nullptr;
        check_ret("wally_bip32_key_to_addr_segwit",
                  wally_bip32_key_to_addr_segwit(derived, "tex", 0, &address));
        std::cout << "Address: " << address << std::endl;

        // script_pubkey for our segwit address
        std::vector<unsigned char> script_pubkey(128);
        size_t spk_len = 0;
        check_ret("wally_addr_segwit_to_bytes",
                  wally_addr_segwit_to_bytes(address, "tex", 0, script_pubkey.data(), script_pubkey.size(), &spk_len));
        script_pubkey.resize(spk_len);

        // Blinding keys
        std::vector<unsigned char> master_blinding_key(HMAC_SHA512_LEN);
        check_ret("wally_asset_blinding_key_from_seed",
                  wally_asset_blinding_key_from_seed(seed.data(), seed.size(), master_blinding_key.data(), master_blinding_key.size()));
        std::vector<unsigned char> private_blinding_key(EC_PRIVATE_KEY_LEN);
        check_ret("wally_asset_blinding_key_to_ec_private_key",
                  wally_asset_blinding_key_to_ec_private_key(master_blinding_key.data(), master_blinding_key.size(),
                                                            script_pubkey.data(), script_pubkey.size(),
                                                            private_blinding_key.data(), private_blinding_key.size()));

        std::vector<unsigned char> public_blinding_key(EC_PUBLIC_KEY_LEN);
        check_ret("wally_ec_public_key_from_private_key",
                  wally_ec_public_key_from_private_key(private_blinding_key.data(), private_blinding_key.size(),
                                                       public_blinding_key.data(), public_blinding_key.size()));

        char* conf_address = nullptr;
        check_ret("wally_confidential_addr_from_addr_segwit",
                  wally_confidential_addr_from_addr_segwit(address, "tex", "tlq",
                                                          public_blinding_key.data(), public_blinding_key.size(),
                                                          &conf_address));
        std::cout << "Confidential Address: " << conf_address << std::endl;

        // Load prev tx hexes (test scenario: tx3/tx4 spend asset, tx5 provides LBTC fee)
        const std::string prevTx3 = read_first_existing({"../testjs/tx3.txt", "testjs/tx3.txt", "tx3.txt", "../examples/testjs/tx3.txt"});
        const std::string prevTx4 = read_first_existing({"../testjs/tx4.txt", "testjs/tx4.txt", "tx4.txt", "../examples/testjs/tx4.txt"});
        const std::string prevTx5 = read_first_existing({"../testjs/tx5.txt", "testjs/tx5.txt", "tx5.txt", "../examples/testjs/tx5.txt"});

        // Print input txids for convenience
        auto print_txid = [](const std::string& hex, const std::string& label) {
            struct wally_tx* t = nullptr;
            check_ret("wally_tx_from_hex(prev)", wally_tx_from_hex(hex.c_str(), WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS, &t));
            std::vector<unsigned char> id(32);
            check_ret("wally_tx_get_txid(prev)", wally_tx_get_txid(t, id.data(), id.size()));
            std::reverse(id.begin(), id.end());
            std::cout << label << ": " << hex_from_bytes(id.data(), id.size()) << std::endl;
            wally_tx_free(t);
        };
        print_txid(prevTx3, "TXI3");
        print_txid(prevTx4, "TXI4");
        print_txid(prevTx5, "TXI5");

        // Destinations
        const std::string destination_conf_addr1 = "tlq1qqd9wdznzt8rr0jsclqlvu20ersxza4v6l446yrpgx5zzz8jq84qlpcrzctqe26j5v3m9s0d0jr0aalmt35lhxj409vtydgd3t";
        const std::string destination_conf_addr2 = "tlq1qq2k4x6xr9nqsv0y5n6sc7k3qr8gpel8kt676qnxx8na2kkfmsrc3ayatr5eptrrtqgj47rve6cvhheac9u5fu5f7we47qwjcs";
        const std::string destination_conf_addr3 = "tlq1qqd9wdznzt8rr0jsclqlvu20ersxza4v6l446yrpgx5zzz8jq84qlpcrzctqe26j5v3m9s0d0jr0aalmt35lhxj409vtydgd3t";

        const std::vector<std::string> dests = {destination_conf_addr1, destination_conf_addr2};

        // Signing keypair
        std::vector<unsigned char> signingPrivKey(EC_PRIVATE_KEY_LEN);
        // `ext_key::priv_key` is 33 bytes with prefix 0; EC privkey is the last 32 bytes.
        std::memcpy(signingPrivKey.data(), derived->priv_key + 1, EC_PRIVATE_KEY_LEN);
        std::vector<unsigned char> signingPubKey(EC_PUBLIC_KEY_LEN);
        check_ret("wally_ec_public_key_from_private_key(signing)",
                  wally_ec_public_key_from_private_key(signingPrivKey.data(), signingPrivKey.size(),
                                                       signingPubKey.data(), signingPubKey.size()));

        // Derive assetIdToSend from tx3, and feeAssetId from tx5
        UtxoSet u3 = getConfidentialUtxosFromTx(prevTx3, script_pubkey, private_blinding_key);
        if (u3.asset_ids_in.size() < 32) throw std::runtime_error("tx3 has no matching asset outputs");
        std::vector<unsigned char> assetIdToSend(u3.asset_ids_in.begin(), u3.asset_ids_in.begin() + 32);
        if (u3.tx) wally_tx_free(u3.tx);

        UtxoSet u5 = getConfidentialUtxosFromTx(prevTx5, script_pubkey, private_blinding_key);
        if (u5.asset_ids_in.size() < 32) throw std::runtime_error("tx5 has no matching fee asset outputs");
        std::vector<unsigned char> feeAssetId(u5.asset_ids_in.begin(), u5.asset_ids_in.begin() + 32);
        if (u5.tx) wally_tx_free(u5.tx);

        const uint64_t feeSats = 1000;

        const auto res = sendAssetToConfidentialAddresses({prevTx3, prevTx4, prevTx5},
                                                            script_pubkey,
                                                            private_blinding_key,
                                                            dests,
                                                            destination_conf_addr3, // fee change destination
                                                            feeSats,
                                                            assetIdToSend,
                                                            feeAssetId,
                                                            "tex",
                                                            "tlq",
                                                            signingPrivKey,
                                                            signingPubKey);

        // Write sendtx.hex
        std::ofstream out("sendtx.hex", std::ios::binary);
        out << res.txHex;
        out.close();

        std::cout << "Raw send tx hex written to sendtx.hex" << std::endl;
        std::cout << "Raw send tx hex length: " << res.txHex.size()
                  << " prefix: " << res.txHex.substr(0, 16)
                  << " suffix: " << res.txHex.substr(res.txHex.size() - 16) << std::endl;
        std::cout << "Send TXID: " << res.txid << std::endl;

        wally_free_string(conf_address);
        wally_free_string(address);
        bip32_key_free(master);
        bip32_key_free(derived);
    } catch (const std::exception& e) {
        std::cerr << "Fatal: " << e.what() << std::endl;
        wally::cleanup(0);
        return 1;
    }

    wally::cleanup(0);
    return 0;
}