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

#ifndef NUNCHUK_SATOCHIP_H
#define NUNCHUK_SATOCHIP_H

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace nunchuk {

class SingleSigner;
class Wallet;

// Consume synchronously, clear copies, and throw on card errors.
using CardBip32ImportSeedFn =
    std::function<void(const std::vector<unsigned char> &seed)>;

// Requires card setup, PIN verification, and UTF-8 NFKD-normalized inputs.
void SatochipImportSeedFromMnemonic(
    const CardBip32ImportSeedFn &cardBip32ImportSeedFn,
    const std::string &mnemonic, const std::string &passphrase = "");

// Returns {pubkey (33/65 bytes), chain code (32 bytes)} and selects the card
// key. Must derive on-card even if the public key is cached.
using CardBip32GetExtendedKeyFn =
    std::function<std::vector<std::vector<unsigned char>>(
        const std::string &path)>;

// Signing does not support 2FA; callers must reject 2FA-enabled cards.
// Returns DER or throws; pass no 2FA response to the card library.
using CardSignTransactionHashFn = std::function<std::vector<unsigned char>(
    unsigned char keynbr, const std::vector<unsigned char> &txhash)>;

// `tweak` is the raw 32-byte APDU parameter, not a TapTweak scalar or Merkle
// root. Returns a 33/65-byte pubkey. Bypass requires the applet's Nostr
// feature.
using CardTaprootTweakPrivateKeyFn = std::function<std::vector<unsigned char>(
    int keynbr, const std::vector<unsigned char> &tweak, bool bypass_flag)>;

// Returns 64 bytes or throws; pass no 2FA response to the card library.
using CardSignSchnorrHashFn = std::function<std::vector<unsigned char>(
    const std::vector<unsigned char> &txhash)>;

using CardMusig2GenerateNonceFn =
    std::function<std::vector<std::vector<unsigned char>>(
        int keynbr, const std::vector<unsigned char> &aggpk,
        const std::vector<unsigned char> &msg,
        const std::vector<unsigned char> &extra)>;

using CardMusig2SignFn = std::function<std::vector<unsigned char>(
    int keynbr, const std::vector<unsigned char> &secnonce,
    const std::vector<unsigned char> &b, const std::vector<unsigned char> &ea,
    bool r_has_even_y, bool ggacc_is_1)>;

// Save card-encrypted nonces; consume atomically returns and deletes them.
// Never restore a consumed nonce, even after a signing error.
using CardMusig2SaveSecNonceFn = std::function<void(
    const std::string &session_id, const std::vector<unsigned char> &secnonce)>;

using CardMusig2ConsumeSecNonceFn =
    std::function<std::optional<std::vector<unsigned char>>(
        const std::string &session_id)>;

std::string SatochipGetXpub(
    const CardBip32GetExtendedKeyFn &cardBip32GetExtendedKeyFn,
    const std::string &path, bool is_testnet = false);

// Serialize the entire operation on one authenticated card session.
struct SatochipSignPsbtParams {
  CardBip32GetExtendedKeyFn cardBip32GetExtendedKeyFn;
  CardSignTransactionHashFn cardSignTransactionHashFn;
  CardTaprootTweakPrivateKeyFn cardTaprootTweakPrivateKeyFn;
  CardSignSchnorrHashFn cardSignSchnorrHashFn;
  CardMusig2GenerateNonceFn cardMusig2GenerateNonceFn;
  CardMusig2SignFn cardMusig2SignFn;
  // Optional notification: estimated progress (0-100) for this signing pass.
  std::function<void(int)> progress;
};

std::string SatochipGetMasterFingerprint(
    const CardBip32GetExtendedKeyFn &cardBip32GetExtendedKeyFn);

// Returns a Base64 compact signature; keep both callbacks on one card session.
std::string SatochipSignMessage(
    const CardBip32GetExtendedKeyFn &cardBip32GetExtendedKeyFn,
    const CardSignTransactionHashFn &cardSignTransactionHashFn,
    const SingleSigner &signer, const std::string &message);

std::string SatochipSignPsbt(
    const SatochipSignPsbtParams &params, const std::string &xfp,
    const std::string &psbt, const CardMusig2SaveSecNonceFn &saveSecNonceFn,
    const CardMusig2ConsumeSecNonceFn &consumeSecNonceFn, const Wallet &wallet);

}  // namespace nunchuk

#endif
