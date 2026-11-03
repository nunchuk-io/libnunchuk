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

#include <coreutils.h>
#include <key_io.h>
#include <softwaresigner.h>
#include <utils/bip85.h>

#include <doctest.h>

// BIP39 vector: entropy 0000...00. Root keys are BIP32 HMAC-SHA512("Bitcoin seed").
// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
static const char* kMnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about";

static const char* kRootXprvEmpty =
    "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2"
    "Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";
static const char* kRootXpubEmpty =
    "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3"
    "uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8";
static const char* kAccountXpub84 =
    "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPs"
    "hWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";

// Passphrase "TREZOR" from the same BIP39 vector.
static const char* kRootXprvTrezor =
    "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs"
    "1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF";

// BIP85 m/83696968'/39'/0'/12'/0': HMAC-SHA512("bip-entropy-from-k", child key).
static const char* kBip85Mnemonic12 =
    "prosper short ramp prepare exchange stove life snack client enough "
    "purpose fold";

TEST_CASE("software signer BIP39 derivation survives seed cleanse") {
  using namespace nunchuk;
  CoreUtils::getInstance().SetChain(Chain::MAIN);

  CHECK(SoftwareSigner::CheckMnemonic(kMnemonic));

  SoftwareSigner signer{kMnemonic, ""};
  CHECK(signer.GetMasterFingerprint() == "73c5da0a");
  CHECK(EncodeExtKey(signer.GetExtKeyAtPath("m")) == kRootXprvEmpty);
  // Second read uses the stored CExtKey, after the seed buffers were wiped.
  CHECK(EncodeExtKey(signer.GetExtKeyAtPath("m")) == kRootXprvEmpty);
  CHECK(signer.GetXpubAtPath("m") == kRootXpubEmpty);
  CHECK(signer.GetXpubAtPath("m/84h/0h/0h") == kAccountXpub84);
  CHECK(signer.GetAddressAtPath("m/44h/0h/0h/0/0") ==
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");

  // Deriving again must match. The BIP39 seed is not kept in a static cache.
  SoftwareSigner again{kMnemonic, ""};
  CHECK(again.GetMasterFingerprint() == "73c5da0a");
  CHECK(EncodeExtKey(again.GetExtKeyAtPath("m")) == kRootXprvEmpty);

  SoftwareSigner with_passphrase{kMnemonic, "TREZOR"};
  CHECK(with_passphrase.GetMasterFingerprint() == "b4e3f5ed");
  CHECK(EncodeExtKey(with_passphrase.GetExtKeyAtPath("m")) == kRootXprvTrezor);
  CHECK(EncodeExtKey(with_passphrase.GetExtKeyAtPath("m")) != kRootXprvEmpty);
}

TEST_CASE("bip85 derivation survives seed cleanse") {
  using namespace nunchuk;
  CoreUtils::getInstance().SetChain(Chain::MAIN);

  Bip85 bip85{kMnemonic, ""};
  CHECK(bip85.GetMnemonic(0, 12) == kBip85Mnemonic12);
  CHECK(SoftwareSigner::CheckMnemonic(bip85.GetMnemonic(0, 12)));

  Bip85 again{kMnemonic, ""};
  CHECK(again.GetMnemonic(0, 12) == kBip85Mnemonic12);
}
