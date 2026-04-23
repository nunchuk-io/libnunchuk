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

#include <nunchuk.h>
#include <descriptor.h>
#include <coreutils.h>

#include <doctest.h>

TEST_CASE("testing ParseDescriptors") {
  using namespace nunchuk;
  CoreUtils::getInstance().SetChain(Chain::REGTEST);
  std::string error;

  std::string legacySingle =
      "pkh([423faab6/44'/1'/0']"
      "tpubDC74mC2mXearamPqwV1T8PkhKLBZEEve9t9DTXT674v3pVQrLxxY5ksfvcK2FT2PCa91"
      "TagW9Q6kMy2xbmKsV9nqCsbD2jjLWDqXyibc5q2/0/*)#7s4gy4cx\n"
      "pkh([423faab6/44'/1'/0']"
      "tpubDC74mC2mXearamPqwV1T8PkhKLBZEEve9t9DTXT674v3pVQrLxxY5ksfvcK2FT2PCa91"
      "TagW9Q6kMy2xbmKsV9nqCsbD2jjLWDqXyibc5q2/1/*)#0ysfeqg7";

  auto w1 = ParseDescriptors(legacySingle, error);
  CHECK(w1.has_value());
  CHECK(error.empty());
  CHECK(w1->get_m() == 1);
  CHECK(w1->get_n() == 1);
  CHECK(w1->get_address_type() == AddressType::LEGACY);
  CHECK(w1->get_wallet_type() == WalletType::SINGLE_SIG);
  CHECK(w1->get_signers().size() == 1);
  CHECK(w1->get_signers()[0].get_xpub() ==
        "tpubDC74mC2mXearamPqwV1T8PkhKLBZEEve9t9DTXT674v3pVQrLxxY5ksfvcK2FT2PCa"
        "91TagW9Q6kMy2xbmKsV9nqCsbD2jjLWDqXyibc5q2");
  CHECK(w1->get_signers()[0].get_public_key() == "");
  CHECK(w1->get_signers()[0].get_master_fingerprint() == "423faab6");
  CHECK(w1->get_signers()[0].get_derivation_path() == "m/44h/1h/0h");

  std::string nested1of3 =
      "sh(wsh(sortedmulti(1,[423faab6/48'/1'/6']"
      "tpubDD4VXPr1QFidEe6xJSjz1xw7V4GtKmWKzNaGLp5Ko4Aqf18FA7XkDMqmsHA6kefMFHTg"
      "F2jEH4b2oyTUmw116wjZmPNWo8E725ZqdPgK58G/0/*,[0b93c52e/48'/1'/1']"
      "tpubDDHA32QuyKQXdUJQcrhVjD4DwHrTCLCFKkAGf3q4vEPPZKLU2XjnuuF4XwCxxBJMqnP7"
      "484SyhEtnCyK4WcMei8MRvewrY7GtbgkjXG9R16/0/*,[a43bb737/48'/1'/6']"
      "tpubDDcE2gjg1bWMzPiLtMgGp4iBV4ZTeCnQxWj2qsbz7cJW4mqVFBMpZpsmidLwV1T7MCWR"
      "aBwhNFHuv6iJNFRcCKD2aLG4pkrVNzY3TDyW75j/0/*)))#l29exxxm\n"
      "sh(wsh(sortedmulti(1,[423faab6/48'/1'/6']"
      "tpubDD4VXPr1QFidEe6xJSjz1xw7V4GtKmWKzNaGLp5Ko4Aqf18FA7XkDMqmsHA6kefMFHTg"
      "F2jEH4b2oyTUmw116wjZmPNWo8E725ZqdPgK58G/1/*,[0b93c52e/48'/1'/1']"
      "tpubDDHA32QuyKQXdUJQcrhVjD4DwHrTCLCFKkAGf3q4vEPPZKLU2XjnuuF4XwCxxBJMqnP7"
      "484SyhEtnCyK4WcMei8MRvewrY7GtbgkjXG9R16/1/*,[a43bb737/48'/1'/6']"
      "tpubDDcE2gjg1bWMzPiLtMgGp4iBV4ZTeCnQxWj2qsbz7cJW4mqVFBMpZpsmidLwV1T7MCWR"
      "aBwhNFHuv6iJNFRcCKD2aLG4pkrVNzY3TDyW75j/1/*)))#nqfsesz5";

  error.clear();
  auto w2 = ParseDescriptors(nested1of3, error);
  CHECK(w2.has_value());
  CHECK(error.empty());
  CHECK(w2->get_m() == 1);
  CHECK(w2->get_n() == 3);
  CHECK(w2->get_address_type() == AddressType::NESTED_SEGWIT);
  CHECK(w2->get_wallet_type() == WalletType::MULTI_SIG);
  CHECK(w2->get_signers().size() == 3);
  CHECK(w2->get_signers()[0].get_xpub() ==
        "tpubDD4VXPr1QFidEe6xJSjz1xw7V4GtKmWKzNaGLp5Ko4Aqf18FA7XkDMqmsHA6kefMFH"
        "TgF2jEH4b2oyTUmw116wjZmPNWo8E725ZqdPgK58G");
  CHECK(w2->get_signers()[0].get_public_key() == "");
  CHECK(w2->get_signers()[0].get_master_fingerprint() == "423faab6");
  CHECK(w2->get_signers()[0].get_derivation_path() == "m/48h/1h/6h");
  CHECK(w2->get_signers()[1].get_xpub() ==
        "tpubDDHA32QuyKQXdUJQcrhVjD4DwHrTCLCFKkAGf3q4vEPPZKLU2XjnuuF4XwCxxBJMqn"
        "P7484SyhEtnCyK4WcMei8MRvewrY7GtbgkjXG9R16");
  CHECK(w2->get_signers()[1].get_public_key() == "");

  CHECK(w2->get_signers()[1].get_master_fingerprint() == "0b93c52e");
  CHECK(w2->get_signers()[1].get_derivation_path() == "m/48h/1h/1h");
  CHECK(w2->get_signers()[2].get_xpub() ==
        "tpubDDcE2gjg1bWMzPiLtMgGp4iBV4ZTeCnQxWj2qsbz7cJW4mqVFBMpZpsmidLwV1T7MC"
        "WRaBwhNFHuv6iJNFRcCKD2aLG4pkrVNzY3TDyW75j");
  CHECK(w2->get_signers()[2].get_public_key() == "");
  CHECK(w2->get_signers()[2].get_master_fingerprint() == "a43bb737");
  CHECK(w2->get_signers()[2].get_derivation_path() == "m/48h/1h/6h");

  std::string nativeEscrow2of2 =
      "wsh(sortedmulti(2,[423faab6/48'/1'/6']"
      "02841c0aafa8728be24a2649a9d84912f1cef794c85434dbcc5c689e2eb9cbd5f1,"
      "[a43bb737/48'/1'/6']"
      "03cd1289fa27f2d5a9dd4af68782bb703280ca86e4f6b91f8eb7a067c86875eb28))#"
      "k57nsxg2";

  error.clear();
  auto w3 = ParseDescriptors(nativeEscrow2of2, error);
  CHECK(w3.has_value());
  CHECK(error.empty());
  CHECK(w3->get_m() == 2);
  CHECK(w3->get_n() == 2);
  CHECK(w3->get_address_type() == AddressType::NATIVE_SEGWIT);
  CHECK(w3->get_wallet_type() == WalletType::ESCROW);
  CHECK(w3->get_signers().size() == 2);
  CHECK(w3->get_signers()[0].get_xpub() == "");
  CHECK(w3->get_signers()[0].get_public_key() ==
        "02841c0aafa8728be24a2649a9d84912f1cef794c85434dbcc5c689e2eb9cbd5f1");
  CHECK(w3->get_signers()[0].get_master_fingerprint() == "423faab6");
  CHECK(w3->get_signers()[0].get_derivation_path() == "m/48h/1h/6h");
  CHECK(w3->get_signers()[1].get_xpub() == "");
  CHECK(w3->get_signers()[1].get_public_key() ==
        "03cd1289fa27f2d5a9dd4af68782bb703280ca86e4f6b91f8eb7a067c86875eb28");
  CHECK(w3->get_signers()[1].get_master_fingerprint() == "a43bb737");
  CHECK(w3->get_signers()[1].get_derivation_path() == "m/48h/1h/6h");
}
