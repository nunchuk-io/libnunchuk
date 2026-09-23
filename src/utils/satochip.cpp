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

#include <common/signmessage.h>
#include <key_io.h>
#include <psbt.h>
#include <hash.h>
#include <musig.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <random.h>
#include <script/interpreter.h>
#include <support/allocators/secure.h>
#include <support/cleanse.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <numeric>
#include <set>
#include <stdexcept>
#include "base58.h"
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_musig.h"
#include "span.h"
#include "txutils.hpp"
#include "util/bip32.h"
#include "util/strencodings.h"
#include "utils/satochip.hpp"

extern "C" {
#include <bip39.h>
#include <pbkdf2.h>
}

namespace nunchuk {
static const unsigned char MAINNET_PREFIX[4] = {0x04, 0x88, 0xB2, 0x1E};
static const unsigned char TESTNET_PREFIX[4] = {0x04, 0x35, 0x87, 0xCF};

void SatochipImportSeedFromMnemonic(
    const CardBip32ImportSeedFn &cardBip32ImportSeedFn,
    const std::string &mnemonic, const std::string &passphrase) {
  if (!cardBip32ImportSeedFn) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "[Satochip] missing seed import callback.");
  }
  if (mnemonic.find('\0') != std::string::npos ||
      !Utils::CheckMnemonic(mnemonic)) {
    throw NunchukException(
        NunchukException::INVALID_PARAMETER,
        "Invalid seed phrase. Check the words and their order.");
  }
  constexpr size_t max_length = std::numeric_limits<int>::max();
  if (mnemonic.size() > max_length || passphrase.size() > max_length - 8) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Seed phrase or passphrase is too long.");
  }

  // Use Trezor's BIP39 primitive without mnemonic_to_seed's shared context or
  // 256-byte passphrase limit.
  std::vector<unsigned char, secure_allocator<unsigned char>> salt{
      'm', 'n', 'e', 'm', 'o', 'n', 'i', 'c'};
  salt.insert(salt.end(), passphrase.begin(), passphrase.end());
  std::vector<unsigned char> seed(64);
  try {
    PBKDF2_HMAC_SHA512_CTX context{};
    pbkdf2_hmac_sha512_Init(
        &context, reinterpret_cast<const uint8_t *>(mnemonic.data()),
        static_cast<int>(mnemonic.size()), salt.data(),
        static_cast<int>(salt.size()), 1);
    pbkdf2_hmac_sha512_Update(&context, BIP39_PBKDF2_ROUNDS);
    pbkdf2_hmac_sha512_Final(&context, seed.data());
    cardBip32ImportSeedFn(seed);
  } catch (...) {
    memory_cleanse(seed.data(), seed.size());
    throw;
  }
  memory_cleanse(seed.data(), seed.size());
}

static std::pair<CScript, SigVersion> get_ecdsa_scriptcode(
    const CTxOut &utxo, const PSBTInput &in) {
  const CScript &script = utxo.scriptPubKey.IsPayToScriptHash()
                              ? in.redeem_script
                              : utxo.scriptPubKey;
  if (script.IsPayToWitnessScriptHash()) {
    return {in.witness_script, SigVersion::WITNESS_V0};
  }
  int version{};
  std::vector<unsigned char> program;
  if (script.IsWitnessProgram(version, program) && version == 0 &&
      program.size() == 20) {
    return {CScript() << OP_DUP << OP_HASH160 << program << OP_EQUALVERIFY
                      << OP_CHECKSIG,
            SigVersion::WITNESS_V0};
  }
  return {script, SigVersion::BASE};
}

static bool script_has_key(const CScript &script,
                           std::span<const unsigned char> pubkey) {
  const auto key_hash = Hash160(pubkey);
  auto it = script.begin();
  opcodetype opcode;
  std::vector<unsigned char> data;
  while (script.GetOp(it, opcode, data)) {
    if (std::equal(data.begin(), data.end(), pubkey.begin(), pubkey.end()) ||
        std::equal(data.begin(), data.end(), key_hash.begin(),
                   key_hash.end())) {
      return true;
    }
  }
  return false;
}

static uint256 satochip_nonce_id(const CPubKey &script_pubkey,
                                 const CPubKey &pubkey, const uint256 &hash,
                                 const std::vector<unsigned char> &pubnonce) {
  auto hasher = TaggedHash("Satochip/MuSig2/nonce");
  hasher << MuSig2SessionID(script_pubkey, pubkey, hash) << pubnonce;
  return hasher.GetSHA256();
}

static secp256k1_context *secp_ctx =
    secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

static std::vector<unsigned char> normalize_ecdsa_signature(
    const std::vector<unsigned char> &der, int sighash_type = 0x01) {
  secp256k1_ecdsa_signature sig;
  if (der.empty() || !secp256k1_ecdsa_signature_parse_der(
                         secp_ctx, &sig, der.data(), der.size())) {
    throw std::runtime_error(
        "Satochip returned an invalid transaction signature.");
  }

  secp256k1_ecdsa_signature_normalize(secp_ctx, &sig, &sig);

  std::vector<unsigned char> out(75);
  size_t out_size(out.size());
  if (!secp256k1_ecdsa_signature_serialize_der(secp_ctx, out.data(), &out_size,
                                               &sig)) {
    throw std::runtime_error(
        "[Satochip] secp256k1_ecdsa_signature_serialize_der error.");
  }
  out.resize(out_size);
  out.push_back(sighash_type);
  return out;
}

static void check_schnorr_signature(const XOnlyPubKey &pubkey,
                                    const uint256 &hash,
                                    const std::vector<unsigned char> &sig) {
  if (sig.size() != 64) {
    throw NunchukException(NunchukException::INVALID_SIGNATURE,
                           "Invalid Taproot signature.");
  }
  if (!pubkey.VerifySchnorr(hash, sig)) {
    throw NunchukException(NunchukException::INVALID_SIGNATURE,
                           "Could not verify the Taproot signature.");
  }
}

static void append_taproot_sighash(std::vector<unsigned char> &sig,
                                   int sighash_type) {
  if (sighash_type != SIGHASH_DEFAULT) {
    sig.push_back(static_cast<unsigned char>(sighash_type));
  }
}

static std::vector<unsigned char> sign_satochip_schnorr_hash(
    const SatochipSignPsbtParams &params, const XOnlyPubKey &verify_key,
    const uint256 &hash, int sighash_type, bool tweak_key) {
  // Zero selects the no-tree tweak; bypass preserves the BIP32 key.
  // Reprepare each time: signing overwrites the applet's key slot.
  params.cardTaprootTweakPrivateKeyFn(0xff, std::vector<unsigned char>(32, 0),
                                      !tweak_key);
  auto signature = params.cardSignSchnorrHashFn({hash.begin(), hash.end()});
  check_schnorr_signature(verify_key, hash, signature);
  append_taproot_sighash(signature, sighash_type);
  return signature;
}

static uint256 get_taproot_sighash(const PartiallySignedTransaction &psbt,
                                   const PrecomputedTransactionData &txdata,
                                   int index, int sighash_type,
                                   const uint256 *leaf_hash = nullptr) {
  ScriptExecutionData execdata;
  execdata.m_annex_init = true;
  execdata.m_annex_present = false;
  if (leaf_hash) {
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFF;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_tapleaf_hash = *leaf_hash;
  }
  const auto sigversion =
      leaf_hash ? SigVersion::TAPSCRIPT : SigVersion::TAPROOT;
  uint256 hash;
  if (!SignatureHashSchnorr(hash, execdata, *psbt.tx, index, sighash_type,
                            sigversion, txdata, MissingDataBehavior::FAIL)) {
    throw std::runtime_error(
        "Invalid or incomplete transaction data for Taproot signing.");
  }
  return hash;
}

static CPubKey serialize_secp_pubkey(const secp256k1_pubkey &pubkey) {
  std::vector<unsigned char> out(CPubKey::COMPRESSED_SIZE);
  size_t out_len = out.size();
  if (!secp256k1_ec_pubkey_serialize(secp_ctx, out.data(), &out_len, &pubkey,
                                     SECP256K1_EC_COMPRESSED)) {
    throw std::runtime_error("[Satochip] failed to serialize public key.");
  }
  out.resize(out_len);
  return CPubKey(out.begin(), out.end());
}

static CPubKey compress_card_pubkey(const std::vector<unsigned char> &pubkey) {
  CPubKey cpubkey(pubkey.begin(), pubkey.end());
  if (!cpubkey.IsFullyValid()) {
    throw std::runtime_error(
        "Invalid Satochip public key. Read the card again.");
  }
  if (pubkey.size() == CPubKey::COMPRESSED_SIZE) {
    return cpubkey;
  }

  secp256k1_pubkey parsed_pubkey;
  if (!secp256k1_ec_pubkey_parse(secp_ctx, &parsed_pubkey, pubkey.data(),
                                 pubkey.size())) {
    throw std::runtime_error("[Satochip] failed to parse public key.");
  }
  return serialize_secp_pubkey(parsed_pubkey);
}

struct MuSig2Setup {
  CPubKey script_pubkey;
  std::vector<std::pair<uint256, bool>> tweaks;
};

static std::optional<MuSig2Setup> get_musig2_setup(
    const PSBTInput &input, const CPubKey &aggregate_pubkey,
    const XOnlyPubKey &script_xonly, const uint256 *merkle_root) {
  MuSig2Setup setup{.script_pubkey = aggregate_pubkey};

  if (XOnlyPubKey(aggregate_pubkey) != script_xonly) {
    auto origin_it = input.m_tap_bip32_paths.find(script_xonly);
    if (origin_it == input.m_tap_bip32_paths.end()) {
      return std::nullopt;
    }

    const KeyOriginInfo &origin = origin_it->second.second;
    CKeyID keyid = aggregate_pubkey.GetID();
    if (!std::equal(std::begin(origin.fingerprint),
                    std::end(origin.fingerprint), keyid.begin())) {
      return std::nullopt;
    }

    CExtPubKey extpub = CreateMuSig2SyntheticXpub(aggregate_pubkey);
    for (uint32_t child : origin.path) {
      uint256 tweak;
      if ((child & 0x80000000) || !extpub.Derive(extpub, child, &tweak)) {
        return std::nullopt;
      }
      setup.tweaks.emplace_back(tweak, false);
    }

    if (XOnlyPubKey(extpub.pubkey) != script_xonly) {
      return std::nullopt;
    }
    setup.script_pubkey = extpub.pubkey;
  }

  if (merkle_root != nullptr) {
    const uint256 *tap_merkle_root =
        merkle_root->IsNull() ? nullptr : merkle_root;
    setup.tweaks.emplace_back(script_xonly.ComputeTapTweakHash(tap_merkle_root),
                              true);
    auto tweaked = script_xonly.CreateTapTweak(tap_merkle_root);
    if (!tweaked) {
      return std::nullopt;
    }
    setup.script_pubkey =
        tweaked->first.GetCPubKeys().at(tweaked->second ? 1 : 0);
  }

  return setup;
}

static std::vector<unsigned char> get_musig2_keyagg_coefficient(
    const CPubKey &pubkey, const std::vector<CPubKey> &participants) {
  auto list_hasher = TaggedHash("KeyAgg list");
  for (const CPubKey &participant : participants) {
    list_hasher.write(MakeByteSpan(participant));
  }
  const auto pks_hash = list_hasher.GetSHA256();

  auto second_distinct =
      std::find_if(std::next(participants.begin()), participants.end(),
                   [&](const CPubKey &participant) {
                     return participant != participants[0];
                   });
  if (second_distinct != participants.end() && *second_distinct == pubkey) {
    std::vector<unsigned char> one(32);
    one.back() = 1;
    return one;
  }

  auto coefficient_hasher = TaggedHash("KeyAgg coefficient");
  coefficient_hasher.write(MakeByteSpan(pks_hash));
  coefficient_hasher.write(MakeByteSpan(pubkey));
  const auto coefficient = coefficient_hasher.GetSHA256();
  return {coefficient.begin(), coefficient.end()};
}

struct SatochipMuSig2SignData {
  std::vector<unsigned char> b;
  std::vector<unsigned char> ea;
  bool r_has_even_y = true;
  bool ggacc_is_1 = true;
  secp256k1_musig_keyagg_cache keyagg_cache{};
  secp256k1_musig_session session{};
};

static void set_musig2_card_parameters(
    SatochipMuSig2SignData &data, bool final_pubkey_odd,
    const CPubKey &my_pubkey, const std::vector<CPubKey> &participants) {
  // Layouts of the bundled secp256k1-zkp keyagg cache and session.
  static_assert(sizeof(data.keyagg_cache.data) == 197);
  static_assert(sizeof(data.session.data) == 133);
  constexpr size_t parity_offset = 164;
  constexpr size_t nonce_parity_offset = 4;
  constexpr size_t noncecoef_offset = 37;
  constexpr size_t challenge_offset = 69;
  data.ggacc_is_1 =
      final_pubkey_odd == ((data.keyagg_cache.data[parity_offset] & 1) != 0);
  const auto *session = data.session.data;
  data.r_has_even_y = session[nonce_parity_offset] == 0;
  data.b.assign(session + noncecoef_offset, session + noncecoef_offset + 32);
  data.ea = get_musig2_keyagg_coefficient(my_pubkey, participants);
  if (!secp256k1_ec_seckey_tweak_mul(secp_ctx, data.ea.data(),
                                     session + challenge_offset)) {
    throw std::runtime_error("Could not prepare the MuSig2 signature.");
  }
}

static SatochipMuSig2SignData get_satochip_musig2_sign_data(
    const CPubKey &my_pubkey, const CPubKey &aggregate_pubkey,
    const std::vector<CPubKey> &participants,
    const std::map<CPubKey, std::vector<uint8_t>> &pubnonces,
    const std::vector<std::pair<uint256, bool>> &tweaks,
    const uint256 &sighash) {
  if (participants.empty()) {
    throw std::runtime_error("Missing MuSig2 signing keys.");
  }

  SatochipMuSig2SignData data;
  if (!MuSig2AggregatePubkeys(participants, data.keyagg_cache,
                              std::optional<CPubKey>{aggregate_pubkey})) {
    throw std::runtime_error(
        "Combined MuSig2 key does not match the signing keys.");
  }

  for (const auto &[tweak, xonly] : tweaks) {
    int ok = xonly ? secp256k1_musig_pubkey_xonly_tweak_add(
                         secp_ctx, nullptr, &data.keyagg_cache, tweak.data())
                   : secp256k1_musig_pubkey_ec_tweak_add(
                         secp_ctx, nullptr, &data.keyagg_cache, tweak.data());
    if (!ok) {
      throw std::runtime_error("Invalid MuSig2 key derivation data.");
    }
  }

  secp256k1_pubkey final_pubkey;
  if (!secp256k1_musig_pubkey_get(secp_ctx, &final_pubkey,
                                  &data.keyagg_cache)) {
    throw std::runtime_error("Could not combine the MuSig2 signing keys.");
  }
  CPubKey final_cpubkey = serialize_secp_pubkey(final_pubkey);
  const bool final_pubkey_odd = final_cpubkey[0] == 0x03;

  std::vector<secp256k1_musig_pubnonce> secp_pubnonces;
  std::vector<const secp256k1_musig_pubnonce *> pubnonce_ptrs;
  secp_pubnonces.reserve(participants.size());
  pubnonce_ptrs.reserve(participants.size());
  for (const CPubKey &participant : participants) {
    auto pubnonce_it = pubnonces.find(participant);
    if (pubnonce_it == pubnonces.end() ||
        pubnonce_it->second.size() != MUSIG2_PUBNONCE_SIZE) {
      throw std::runtime_error(
          "Missing or incomplete MuSig2 signing-session data.");
    }
    auto &secp_pubnonce = secp_pubnonces.emplace_back();
    if (!secp256k1_musig_pubnonce_parse(secp_ctx, &secp_pubnonce,
                                        pubnonce_it->second.data())) {
      throw std::runtime_error(
          "Invalid signing-session data from a MuSig2 signer.");
    }
    pubnonce_ptrs.push_back(&secp_pubnonce);
  }

  secp256k1_musig_aggnonce aggnonce;
  if (!secp256k1_musig_nonce_agg(secp_ctx, &aggnonce, pubnonce_ptrs.data(),
                                 pubnonce_ptrs.size())) {
    throw std::runtime_error(
        "Could not combine the MuSig2 signing-session data.");
  }

  if (!secp256k1_musig_nonce_process(secp_ctx, &data.session, &aggnonce,
                                     sighash.data(), &data.keyagg_cache,
                                     nullptr)) {
    throw std::runtime_error(
        "Invalid MuSig2 session. Start a new signing session.");
  }

  set_musig2_card_parameters(data, final_pubkey_odd, my_pubkey, participants);
  return data;
}

static bool verify_musig2_partial_sig(
    const CPubKey &pubkey, const std::vector<unsigned char> &partial_sig,
    const std::vector<unsigned char> &pubnonce,
    const secp256k1_musig_keyagg_cache &keyagg_cache,
    const secp256k1_musig_session &session) {
  if (partial_sig.size() != 32 || pubnonce.size() != MUSIG2_PUBNONCE_SIZE) {
    return false;
  }

  secp256k1_pubkey secp_pubkey;
  if (!secp256k1_ec_pubkey_parse(secp_ctx, &secp_pubkey, pubkey.data(),
                                 pubkey.size())) {
    return false;
  }

  secp256k1_musig_pubnonce secp_pubnonce;
  if (!secp256k1_musig_pubnonce_parse(secp_ctx, &secp_pubnonce,
                                      pubnonce.data())) {
    return false;
  }

  secp256k1_musig_partial_sig secp_partial_sig;
  if (!secp256k1_musig_partial_sig_parse(secp_ctx, &secp_partial_sig,
                                         partial_sig.data())) {
    return false;
  }

  return secp256k1_musig_partial_sig_verify(secp_ctx, &secp_partial_sig,
                                            &secp_pubnonce, &secp_pubkey,
                                            &keyagg_cache, &session) != 0;
}

static CExtPubKey SatochipGetExtPubKey(
    const CardBip32GetExtendedKeyFn &cardBip32GetExtendedKeyFn,
    std::string path, bool is_testnet = false) {
  if (!cardBip32GetExtendedKeyFn) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Missing Satochip key callback.");
  }
  std::vector<uint32_t> parsed_path;
  std::replace(path.begin(), path.end(), 'h', '\'');
  if (!ParseHDKeypath(path, parsed_path)) {
    throw std::runtime_error("Invalid key derivation path.");
  }
  if (parsed_path.size() > 255) {
    throw std::runtime_error(
        "Key derivation path exceeds the maximum depth of 255.");
  }
  auto card_bip32 = cardBip32GetExtendedKeyFn(path);
  if (card_bip32.size() < 2 || card_bip32[1].size() != 32) {
    throw std::runtime_error(
        "Could not read the Satochip public key. Try again.");
  }
  CExtPubKey extkey{};
  memcpy(extkey.version, !is_testnet ? MAINNET_PREFIX : TESTNET_PREFIX, 4);
  extkey.nDepth = static_cast<unsigned char>(parsed_path.size());
  if (!parsed_path.empty()) {
    auto parent_path = parsed_path;
    parent_path.pop_back();
    auto parent = cardBip32GetExtendedKeyFn(WriteHDKeypath(parent_path, true));
    if (parent.empty()) {
      throw std::runtime_error(
          "Could not read the Satochip public key. Try again.");
    }
    auto parent_xpub_id = compress_card_pubkey(parent[0]).GetID();
    memcpy(extkey.vchFingerprint, parent_xpub_id.begin(), 4);
  }
  extkey.nChild = parsed_path.empty() ? 0 : parsed_path.back();
  extkey.chaincode = ChainCode(card_bip32[1]);
  extkey.pubkey = compress_card_pubkey(card_bip32[0]);
  return extkey;
}

std::string SatochipGetXpub(
    const CardBip32GetExtendedKeyFn &cardBip32GetExtendedKeyFn,
    const std::string &path, bool is_testnet) {
  auto extkey =
      SatochipGetExtPubKey(cardBip32GetExtendedKeyFn, path, is_testnet);
  std::vector<unsigned char> encoded(BIP32_EXTKEY_WITH_VERSION_SIZE);
  extkey.EncodeWithVersion(encoded.data());
  return EncodeBase58Check(encoded);
}

std::string SatochipGetMasterFingerprint(
    const CardBip32GetExtendedKeyFn &cardBip32GetExtendedKeyFn) {
  if (!cardBip32GetExtendedKeyFn) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Missing Satochip key callback.");
  }
  auto master = cardBip32GetExtendedKeyFn("m");

  if (master.empty()) {
    throw std::runtime_error(
        "Could not read the Satochip public key. Try again.");
  }

  auto master_xpub_id = compress_card_pubkey(master[0]).GetID();
  auto master_fingerprint = MakeUCharSpan(master_xpub_id).first(4);
  return HexStr(master_fingerprint);
}

std::string SatochipSignMessage(
    const CardBip32GetExtendedKeyFn &cardBip32GetExtendedKeyFn,
    const CardSignTransactionHashFn &cardSignTransactionHashFn,
    const SingleSigner &signer, const std::string &message) {
  if (!cardBip32GetExtendedKeyFn || !cardSignTransactionHashFn) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "[Satochip] missing message signing callback.");
  }
  auto path = signer.get_derivation_path();
  std::replace(path.begin(), path.end(), 'h', '\'');
  auto pubkey = signer.get_xpub().empty()
                    ? CPubKey(ParseHex(signer.get_public_key()))
                    : DecodeExtPubKey(signer.get_xpub()).pubkey;
  pubkey = compress_card_pubkey({pubkey.begin(), pubkey.end()});
  cardBip32GetExtendedKeyFn(path);
  const auto hash = MessageHash(message);
  const auto der = cardSignTransactionHashFn(0xff, {hash.begin(), hash.end()});
  secp256k1_ecdsa_signature signature;
  if (der.empty() || !secp256k1_ecdsa_signature_parse_der(
                         secp_ctx, &signature, der.data(), der.size())) {
    throw NunchukException(NunchukException::INVALID_SIGNATURE,
                           "Satochip returned an invalid message signature.");
  }
  secp256k1_ecdsa_signature_normalize(secp_ctx, &signature, &signature);
  std::vector<unsigned char> compact(CPubKey::COMPACT_SIGNATURE_SIZE);
  secp256k1_ecdsa_signature_serialize_compact(secp_ctx, compact.data() + 1,
                                              &signature);
  for (unsigned char recovery_id = 0; recovery_id < 4; ++recovery_id) {
    compact[0] = 31 + recovery_id;
    CPubKey recovered;
    if (recovered.RecoverCompact(hash, compact) && recovered == pubkey) {
      return EncodeBase64(compact);
    }
  }
  throw NunchukException(
      NunchukException::INVALID_SIGNATURE,
      "Could not verify the message signature. Check the selected card.");
}

static std::map<std::vector<uint32_t>, CExtPubKey> get_signer_xpubs(
    const std::vector<SingleSigner> &signers, const std::string &xfp) {
  std::map<std::vector<uint32_t>, CExtPubKey> xpubs;
  for (const auto &signer : signers) {
    if (signer.get_master_fingerprint() != xfp || signer.get_xpub().empty()) {
      continue;
    }
    auto path = signer.get_derivation_path();
    std::replace(path.begin(), path.end(), 'h', '\'');
    std::vector<uint32_t> keypath;
    auto xpub = DecodeExtPubKey(signer.get_xpub());
    if (!ParseHDKeypath(path, keypath) || !xpub.pubkey.IsFullyValid()) {
      throw std::runtime_error("Invalid saved signer key.");
    }
    xpubs.emplace(std::move(keypath), xpub);
  }
  return xpubs;
}

static CPubKey get_satochip_pubkey(
    const KeyOriginInfo &key_origin,
    const std::map<std::vector<uint32_t>, CExtPubKey> &xpubs,
    const CardBip32GetExtendedKeyFn &cardBip32GetExtendedKeyFn) {
  const auto &path = key_origin.path;
  for (auto it = xpubs.rbegin(); it != xpubs.rend(); ++it) {
    const auto &[parent, xpub] = *it;
    if (parent.size() > path.size() ||
        !std::equal(parent.begin(), parent.end(), path.begin()) ||
        std::any_of(path.begin() + parent.size(), path.end(),
                    [](uint32_t child) { return child & 0x80000000; })) {
      continue;
    }
    auto derived = xpub;
    for (size_t i = parent.size(); i < path.size(); ++i) {
      if (!derived.Derive(derived, path[i])) {
        throw std::runtime_error("Could not derive the Satochip signing key.");
      }
    }
    return derived.pubkey;
  }
  auto bip32 = cardBip32GetExtendedKeyFn(WriteHDKeypath(key_origin.path, true));
  if (bip32.empty()) {
    throw std::runtime_error(
        "Could not read the Satochip public key. Try again.");
  }
  return compress_card_pubkey(bip32[0]);
}

static std::map<XOnlyPubKey, std::set<uint256>> get_taproot_script_keys(
    const PSBTInput &input) {
  std::map<uint256, CScript> leaf_scripts;
  for (const auto &[leaf, controls] : input.m_tap_scripts) {
    const auto &[script, version] = leaf;
    if (version != TAPROOT_LEAF_TAPSCRIPT) continue;
    leaf_scripts.emplace(ComputeTapleafHash(version, script),
                         CScript(script.begin(), script.end()));
  }
  std::map<XOnlyPubKey, std::set<uint256>> script_keys;
  for (const auto &[key, leaf_origin] : input.m_tap_bip32_paths) {
    for (const auto &leaf_hash : leaf_origin.first) {
      auto script = leaf_scripts.find(leaf_hash);
      if (script != leaf_scripts.end() &&
          script_has_key(script->second, {key.begin(), key.size()})) {
        script_keys[key].insert(leaf_hash);
      }
    }
  }
  return script_keys;
}

static bool is_musig2_spending_key(
    const PSBTInput &input, const XOnlyPubKey &output_key,
    const std::map<XOnlyPubKey, std::set<uint256>> &script_keys,
    const XOnlyPubKey &key) {
  for (const auto &[aggregate, participants] : input.m_musig2_participants) {
    if (std::none_of(
            participants.begin(), participants.end(),
            [&](const CPubKey &part) { return XOnlyPubKey(part) == key; }))
      continue;
    auto setup = get_musig2_setup(input, aggregate, input.m_tap_internal_key,
                                  &input.m_tap_merkle_root);
    if (setup && XOnlyPubKey(setup->script_pubkey) == output_key) return true;
    if (get_musig2_setup(input, aggregate, output_key, nullptr)) return true;
    for (const auto &[candidate, leaves] : script_keys) {
      if (get_musig2_setup(input, aggregate, candidate, nullptr)) return true;
    }
  }
  return false;
}

template <typename Values>
static bool all_participants_present(const Values &values,
                                     const std::vector<CPubKey> &participants) {
  return values.size() == participants.size() &&
         std::all_of(participants.begin(), participants.end(),
                     [&](const CPubKey &key) { return values.count(key); });
}

static std::vector<std::vector<unsigned char>> generate_satochip_musig2_nonce(
    const CardMusig2GenerateNonceFn &cardMusig2GenerateNonceFn,
    const CPubKey &aggregate_pubkey, const uint256 &hash) {
  XOnlyPubKey aggregate_xonly(aggregate_pubkey);
  std::vector<unsigned char> aggregate_xonly_bytes(aggregate_xonly.begin(),
                                                   aggregate_xonly.end());
  std::vector<unsigned char> extra(32);
  GetStrongRandBytes(std::span<unsigned char>(extra.data(), extra.size()));
  auto nonce_resp = cardMusig2GenerateNonceFn(
      0xff, aggregate_xonly_bytes, {hash.begin(), hash.end()}, extra);
  if (nonce_resp.size() < 2 || nonce_resp[0].size() < MUSIG2_PUBNONCE_SIZE ||
      nonce_resp[1].size() != 144) {
    throw std::runtime_error(
        "Satochip returned invalid MuSig2 signing-session data.");
  }
  // Firmware may append a two-byte nonce ID.
  nonce_resp[0].resize(MUSIG2_PUBNONCE_SIZE);
  return nonce_resp;
}

static bool aggregate_musig2_signature(
    PSBTInput &input, const CPubKey &aggregate_pubkey,
    const std::vector<CPubKey> &participants, const MuSig2Setup &setup,
    const uint256 &hash, const uint256 *leaf_hash, int sighash_type) {
  const bool key_path = leaf_hash == nullptr;
  const uint256 lookup_leaf_hash = leaf_hash ? *leaf_hash : uint256();
  const auto agg_lh = std::make_pair(setup.script_pubkey, lookup_leaf_hash);
  auto pubnonce_it = input.m_musig2_pubnonces.find(agg_lh);
  auto partial_sig_it = input.m_musig2_partial_sigs.find(agg_lh);
  if (pubnonce_it == input.m_musig2_pubnonces.end() ||
      partial_sig_it == input.m_musig2_partial_sigs.end()) {
    return false;
  }
  if (!all_participants_present(pubnonce_it->second, participants) ||
      !all_participants_present(partial_sig_it->second, participants)) {
    return false;
  }

  auto signature = CreateMuSig2AggregateSig(
      participants, aggregate_pubkey, setup.tweaks, hash, pubnonce_it->second,
      partial_sig_it->second);
  if (!signature) {
    throw NunchukException(NunchukException::INVALID_SIGNATURE,
                           "Could not verify the combined MuSig2 signature.");
  }
  check_schnorr_signature(XOnlyPubKey(setup.script_pubkey), hash, *signature);
  append_taproot_sighash(*signature, sighash_type);
  if (key_path) {
    input.m_tap_key_sig = std::move(*signature);
  } else {
    input.m_tap_script_sigs[std::make_pair(XOnlyPubKey(setup.script_pubkey),
                                           lookup_leaf_hash)] =
        std::move(*signature);
  }
  return true;
}

static bool origin_matches_fingerprint(const KeyOriginInfo &origin,
                                       std::span<const unsigned char> my_xfp) {
  return std::equal(std::begin(origin.fingerprint),
                    std::end(origin.fingerprint), my_xfp.begin(), my_xfp.end());
}

static bool process_satochip_musig2_session(
    const SatochipSignPsbtParams &params, PartiallySignedTransaction &psbt,
    const PrecomputedTransactionData &txdata, int index,
    const XOnlyPubKey &output_key, const CPubKey &my_pubkey,
    const CPubKey &aggregate_pubkey, const XOnlyPubKey &script_xonly,
    const uint256 *merkle_root, const uint256 *leaf_hash,
    const CardMusig2SaveSecNonceFn &saveSecNonceFn,
    const CardMusig2ConsumeSecNonceFn &consumeSecNonceFn) {
  auto &input = psbt.inputs[index];
  const auto &participants = input.m_musig2_participants.at(aggregate_pubkey);
  const int sighash_type = input.sighash_type.value_or(SIGHASH_DEFAULT);
  const auto signing_path = WriteHDKeypath(
      input.m_tap_bip32_paths.at(XOnlyPubKey(my_pubkey)).second.path, true);
  const bool key_path = leaf_hash == nullptr;
  auto setup =
      get_musig2_setup(input, aggregate_pubkey, script_xonly, merkle_root);
  if (!setup) {
    return false;
  }
  if (key_path && XOnlyPubKey(setup->script_pubkey) != output_key) {
    return false;
  }

  const uint256 lookup_leaf_hash =
      leaf_hash == nullptr ? uint256() : *leaf_hash;
  const auto agg_lh = std::make_pair(setup->script_pubkey, lookup_leaf_hash);
  if (!key_path && input.m_tap_script_sigs.count(std::make_pair(
                       XOnlyPubKey(setup->script_pubkey), lookup_leaf_hash))) {
    return true;
  }
  if (key_path && !input.m_tap_key_sig.empty()) {
    return true;
  }

  const auto hash =
      get_taproot_sighash(psbt, txdata, index, sighash_type, leaf_hash);

  if (aggregate_musig2_signature(input, aggregate_pubkey, participants, *setup,
                                 hash, leaf_hash, sighash_type)) {
    return true;
  }

  auto &pubnonces = input.m_musig2_pubnonces[agg_lh];
  auto partial_sig_it = input.m_musig2_partial_sigs.find(agg_lh);
  if (partial_sig_it != input.m_musig2_partial_sigs.end() &&
      partial_sig_it->second.count(my_pubkey)) {
    return true;
  }

  if (all_participants_present(pubnonces, participants)) {
    auto sign_data =
        get_satochip_musig2_sign_data(my_pubkey, aggregate_pubkey, participants,
                                      pubnonces, setup->tweaks, hash);
    params.cardBip32GetExtendedKeyFn(signing_path);
    const auto session_id = satochip_nonce_id(setup->script_pubkey, my_pubkey,
                                              hash, pubnonces.at(my_pubkey));
    auto secnonce = consumeSecNonceFn(session_id.GetHex());
    if (!secnonce || secnonce->empty()) {
      throw std::runtime_error(
          "Signing session unavailable. Delete this transaction and create a "
          "new one.");
    }

    auto partial_sig =
        params.cardMusig2SignFn(0xff, *secnonce, sign_data.b, sign_data.ea,
                                sign_data.r_has_even_y, sign_data.ggacc_is_1);
    if (!verify_musig2_partial_sig(my_pubkey, partial_sig,
                                   pubnonces.at(my_pubkey),
                                   sign_data.keyagg_cache, sign_data.session)) {
      throw NunchukException(NunchukException::INVALID_SIGNATURE,
                             "Could not verify the Satochip MuSig2 signature.");
    }
    input.m_musig2_partial_sigs[agg_lh][my_pubkey] = uint256{
        std::span<const unsigned char>(partial_sig.data(), partial_sig.size())};
    aggregate_musig2_signature(input, aggregate_pubkey, participants, *setup,
                               hash, leaf_hash, sighash_type);
    return true;
  }

  if (!pubnonces.count(my_pubkey)) {
    params.cardBip32GetExtendedKeyFn(signing_path);
    auto nonce_resp = generate_satochip_musig2_nonce(
        params.cardMusig2GenerateNonceFn, aggregate_pubkey, hash);
    const auto session_id =
        satochip_nonce_id(setup->script_pubkey, my_pubkey, hash, nonce_resp[0]);
    saveSecNonceFn(session_id.GetHex(), nonce_resp[1]);
    pubnonces[my_pubkey] = std::move(nonce_resp[0]);
  }

  return true;
}

static void sign_satochip_musig2_participant(
    const SatochipSignPsbtParams &params, PartiallySignedTransaction &psbt,
    const PrecomputedTransactionData &txdata, int index,
    const XOnlyPubKey &output_key, const CPubKey &my_pubkey,
    const std::map<XOnlyPubKey, std::set<uint256>> &script_keys,
    const CardMusig2SaveSecNonceFn &saveSecNonceFn,
    const CardMusig2ConsumeSecNonceFn &consumeSecNonceFn) {
  auto &input = psbt.inputs[index];
  const auto &leaf_hashes =
      input.m_tap_bip32_paths.at(XOnlyPubKey(my_pubkey)).first;
  for (const auto &[aggregate_pubkey, participants] :
       input.m_musig2_participants) {
    if (std::find(participants.begin(), participants.end(), my_pubkey) ==
        participants.end()) {
      continue;
    }

    bool key_path_processed = false;
    if (!input.m_tap_internal_key.IsNull()) {
      key_path_processed = process_satochip_musig2_session(
          params, psbt, txdata, index, output_key, my_pubkey, aggregate_pubkey,
          input.m_tap_internal_key, &input.m_tap_merkle_root, nullptr,
          saveSecNonceFn, consumeSecNonceFn);
    }
    if (!key_path_processed) {
      process_satochip_musig2_session(
          params, psbt, txdata, index, output_key, my_pubkey, aggregate_pubkey,
          output_key, nullptr, nullptr, saveSecNonceFn, consumeSecNonceFn);
    }

    for (const auto &[candidate_xonly, candidate_leaf_hashes] : script_keys) {
      for (const auto &leaf_hash : candidate_leaf_hashes) {
        if (!leaf_hashes.contains(leaf_hash)) continue;
        process_satochip_musig2_session(params, psbt, txdata, index, output_key,
                                        my_pubkey, aggregate_pubkey,
                                        candidate_xonly, nullptr, &leaf_hash,
                                        saveSecNonceFn, consumeSecNonceFn);
      }
    }
  }
}

static void sign_satochip_taproot_input(
    const SatochipSignPsbtParams &params, PartiallySignedTransaction &psbt,
    const PrecomputedTransactionData &txdata, int index, const CTxOut &utxo,
    std::span<const unsigned char> my_xfp,
    const std::map<std::vector<uint32_t>, CExtPubKey> &xpubs,
    const CardMusig2SaveSecNonceFn &saveSecNonceFn,
    const CardMusig2ConsumeSecNonceFn &consumeSecNonceFn) {
  auto &input = psbt.inputs[index];
  if (!input.m_tap_key_sig.empty()) return;
  const XOnlyPubKey output_key{MakeUCharSpan(utxo.scriptPubKey).subspan(2)};

  const int sighash_type = input.sighash_type.value_or(SIGHASH_DEFAULT);

  const auto script_keys = get_taproot_script_keys(input);

  for (const auto &[xonly_pub, leaf_pair] : input.m_tap_bip32_paths) {
    const auto &[leaf_hashes, key_origin] = leaf_pair;
    if (!origin_matches_fingerprint(key_origin, my_xfp)) continue;
    const bool musig2 =
        is_musig2_spending_key(input, output_key, script_keys, xonly_pub);
    if (!musig2 && xonly_pub != input.m_tap_internal_key &&
        xonly_pub != output_key && !script_keys.count(xonly_pub))
      continue;

    const auto signing_path = WriteHDKeypath(key_origin.path, true);
    const CPubKey my_pubkey = get_satochip_pubkey(
        key_origin, xpubs, params.cardBip32GetExtendedKeyFn);
    if (XOnlyPubKey(my_pubkey) != xonly_pub) {
      throw std::runtime_error(
          "Transaction signing key does not match the Satochip key.");
    }

    if (musig2) {
      sign_satochip_musig2_participant(params, psbt, txdata, index, output_key,
                                       my_pubkey, script_keys, saveSecNonceFn,
                                       consumeSecNonceFn);
    }

    const bool key_path_candidate = leaf_hashes.empty();
    const bool signs_internal_key = key_path_candidate &&
                                    !input.m_tap_internal_key.IsNull() &&
                                    input.m_tap_internal_key == xonly_pub;
    const bool signs_output_key = key_path_candidate && output_key == xonly_pub;

    if (signs_internal_key || signs_output_key) {
      const auto hash = get_taproot_sighash(psbt, txdata, index, sighash_type);
      if (signs_internal_key) {
        if (!input.m_tap_merkle_root.IsNull()) {
          throw NunchukException(NunchukException::INVALID_PARAMETER,
                                 "Satochip does not support Taproot key-path "
                                 "signing with a script tree.");
        }
        auto tweaked = xonly_pub.CreateTapTweak(nullptr);
        if (!tweaked || tweaked->first != output_key) {
          throw NunchukException(
              NunchukException::INVALID_PARAMETER,
              "Taproot output does not match the selected Satochip key.");
        }
      }
      params.cardBip32GetExtendedKeyFn(signing_path);
      input.m_tap_key_sig = sign_satochip_schnorr_hash(
          params, output_key, hash, sighash_type, signs_internal_key);
      return;
    }

    auto script_key = script_keys.find(xonly_pub);
    if (script_key == script_keys.end()) continue;
    for (const auto &leaf_hash : script_key->second) {
      auto script_sig_key = std::make_pair(xonly_pub, leaf_hash);
      if (input.m_tap_script_sigs.count(script_sig_key)) continue;

      const auto hash =
          get_taproot_sighash(psbt, txdata, index, sighash_type, &leaf_hash);
      params.cardBip32GetExtendedKeyFn(signing_path);
      input.m_tap_script_sigs[script_sig_key] = sign_satochip_schnorr_hash(
          params, xonly_pub, hash, sighash_type, false);
    }
  }
}

static void sign_satochip_ecdsa_input(const SatochipSignPsbtParams &params,
                                      PartiallySignedTransaction &psbt,
                                      const PrecomputedTransactionData &txdata,
                                      int index, const CTxOut &utxo,
                                      std::span<const unsigned char> my_xfp) {
  auto &input = psbt.inputs[index];
  int sighashType = input.sighash_type.value_or(SIGHASH_ALL);
  if (sighashType == SIGHASH_DEFAULT) sighashType = SIGHASH_ALL;
  const auto [scriptCode, sigversion] = get_ecdsa_scriptcode(utxo, input);
  for (auto &&[pubkey, key_origin] : input.hd_keypaths) {
    if (input.partial_sigs.count(pubkey.GetID())) continue;
    if (!origin_matches_fingerprint(key_origin, my_xfp)) continue;

    if (!script_has_key(scriptCode, {pubkey.begin(), pubkey.size()})) continue;
    auto hash = SignatureHash(scriptCode, *psbt.tx, index, sighashType,
                              utxo.nValue, sigversion, &txdata);
    params.cardBip32GetExtendedKeyFn(WriteHDKeypath(key_origin.path, true));
    auto signature =
        params.cardSignTransactionHashFn(0xff, {hash.begin(), hash.end()});
    auto norm_signature = normalize_ecdsa_signature(signature, sighashType);
    if (!pubkey.Verify(hash, signature)) {
      throw NunchukException(
          NunchukException::INVALID_SIGNATURE,
          "Could not verify the Satochip transaction signature.");
    }
    input.partial_sigs[pubkey.GetID()] =
        SigPair{pubkey, std::move(norm_signature)};
  }
}

template <typename Callback, typename Progress>
static auto track_card_operation(const Callback &callback, Progress &progress) {
  return [&callback, &progress](const auto &...args) {
    auto result = callback(args...);
    progress();
    return result;
  };
}

std::string SatochipSignPsbt(
    const SatochipSignPsbtParams &params, const std::string &xfp,
    const std::string &base64_psbt,
    const CardMusig2SaveSecNonceFn &saveSecNonceFn,
    const CardMusig2ConsumeSecNonceFn &consumeSecNonceFn,
    const Wallet &wallet) {
  if (!params.cardBip32GetExtendedKeyFn || !params.cardSignTransactionHashFn ||
      !params.cardTaprootTweakPrivateKeyFn || !params.cardSignSchnorrHashFn ||
      !params.cardMusig2GenerateNonceFn || !params.cardMusig2SignFn ||
      !saveSecNonceFn || !consumeSecNonceFn) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "[Satochip] missing transaction signing callback.");
  }
  std::vector<unsigned char> my_xfp = ParseHex(xfp);
  if (my_xfp.size() != 4) {
    throw std::runtime_error("[Satochip] invalid master fingerprint.");
  }
  if (params.progress) params.progress(0);
  auto psbt = DecodePsbt(base64_psbt);
  const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);

  const size_t estimated_operations = std::accumulate(
      psbt.inputs.begin(), psbt.inputs.end(), size_t{0},
      [](size_t total, const PSBTInput &input) {
        if (!input.final_script_sig.empty() ||
            !input.final_script_witness.IsNull() ||
            !input.m_tap_key_sig.empty())
          return total;
        if (input.m_tap_bip32_paths.empty()) return total + 2;
        const size_t spending_paths = 1 + input.m_tap_scripts.size();
        const size_t operations_per_path =
            input.m_musig2_participants.empty() ? 2 : 1;
        return total + 1 + spending_paths * operations_per_path;
      });
  auto report_progress = [&, completed = size_t{0},
                          last_percent = 0]() mutable {
    if (!params.progress || estimated_operations == 0) return;
    int percent =
        std::min<size_t>(99, ++completed * 100 / estimated_operations);
    if (percent > last_percent) {
      last_percent = percent;
      params.progress(percent);
    }
  };

  SatochipSignPsbtParams signing_params{
      .cardBip32GetExtendedKeyFn =
          [&, cur_path = std::string(),
           ret = std::vector<std::vector<unsigned char>>()](
              const std::string &path) mutable {
            if (cur_path == path) return ret;
            cur_path = path;
            ret = params.cardBip32GetExtendedKeyFn(path);
            report_progress();
            return ret;
          },
      .cardSignTransactionHashFn = track_card_operation(
          params.cardSignTransactionHashFn, report_progress),
      .cardTaprootTweakPrivateKeyFn = track_card_operation(
          params.cardTaprootTweakPrivateKeyFn, report_progress),
      .cardSignSchnorrHashFn =
          track_card_operation(params.cardSignSchnorrHashFn, report_progress),
      .cardMusig2GenerateNonceFn = track_card_operation(
          params.cardMusig2GenerateNonceFn, report_progress),
      .cardMusig2SignFn =
          track_card_operation(params.cardMusig2SignFn, report_progress),
      .progress = {}};

  auto xpubs = get_signer_xpubs(wallet.get_signers(), xfp);

  for (size_t i = 0; i < psbt.tx->vin.size(); ++i) {
    PSBTInput &input = psbt.inputs[i];
    if (!input.final_script_sig.empty() ||
        !input.final_script_witness.IsNull()) {
      continue;
    }

    if (CTxOut utxo; psbt.GetInputUTXO(utxo, i) && !utxo.IsNull()) {
      if (utxo.scriptPubKey.IsPayToTaproot()) {
        sign_satochip_taproot_input(signing_params, psbt, txdata, i, utxo,
                                    my_xfp, xpubs, saveSecNonceFn,
                                    consumeSecNonceFn);
      } else {
        sign_satochip_ecdsa_input(signing_params, psbt, txdata, i, utxo,
                                  my_xfp);
      }
    }
  }

  auto result = EncodePsbt(psbt);
  if (params.progress) params.progress(100);
  return result;
}

}  // namespace nunchuk
