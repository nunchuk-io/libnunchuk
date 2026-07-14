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
#include <liquid/wallyutils.hpp>
#include <utils/addressutils.hpp>

#include <doctest.h>

TEST_CASE("testing addressutils") {
  nunchuk::Utils::SetChain(nunchuk::Chain::MAIN);

  CHECK(AddressToScriptPubKey("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") ==
        "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac");
  CHECK(AddressToScriptHash("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") ==
        "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161");

  // Invalid address (testnet address)
  CHECK_THROWS(AddressToScriptPubKey("2NA1yEBoC92mDxR57gUGmxFC6dtk9qPLFmr"));
  CHECK_THROWS(AddressToScriptHash("2NA1yEBoC92mDxR57gUGmxFC6dtk9qPLFmr"));

  nunchuk::Utils::SetChain(nunchuk::Chain::TESTNET);

  // Testnet addresses are valid now
  CHECK(AddressToScriptPubKey("2NA1yEBoC92mDxR57gUGmxFC6dtk9qPLFmr") ==
        "a914b7f868d832799c75ff39a617c623cee9d2ea42e987");
  CHECK(AddressToScriptHash("2NA1yEBoC92mDxR57gUGmxFC6dtk9qPLFmr") ==
        "3ccd5a9eea69cd2728b0bf1fe1a32955a3c4f5ed663fda597505450f58de2493");
}

TEST_CASE("Liquid confidential and unconfidential share Electrum scripthash") {
  nunchuk::wally::WallyUtils::Init();
  nunchuk::Utils::SetChain(nunchuk::Chain::MAIN);
  // libwally-core test_confidential_addr_segwit.py (Liquid main P2WPKH pair)
  const char* unconf = "ex1qm39086s5kpvjvg23fc4afg8qs0rl4shj76t00e";
  const char* conf =
      "lq1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqphz2704pfvz"
      "eycs4zn3t6jswpq78ltp0yxz3p90nf3npx";
  CHECK(AddressToScriptHash(unconf) == AddressToScriptHash(conf));
  CHECK(nunchuk::Utils::IsLiquidAddress(unconf));
  CHECK(nunchuk::Utils::IsLiquidAddress(conf));
  CHECK_FALSE(nunchuk::Utils::IsLiquidAddress(
      "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
  nunchuk::wally::WallyUtils::Cleanup();
}

TEST_CASE("IsLiquidAddress respects chain") {
  nunchuk::wally::WallyUtils::Init();
  const char* main_unconf = "ex1qm39086s5kpvjvg23fc4afg8qs0rl4shj76t00e";
  const char* main_conf =
      "lq1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqphz2704pfvz"
      "eycs4zn3t6jswpq78ltp0yxz3p90nf3npx";
  const char* test_conf =
      "tlq1qq2k4x6xr9nqsv0y5n6sc7k3qr8gpel8kt676qnxx8na2kkfmsrc3ayatr5eptrrtq"
      "gj47rve6cvhheac9u5fu5f7we47qwjcs";

  nunchuk::Utils::SetChain(nunchuk::Chain::MAIN);
  CHECK(nunchuk::Utils::IsLiquidAddress(main_unconf));
  CHECK(nunchuk::Utils::IsLiquidAddress(main_conf));
  CHECK_FALSE(nunchuk::Utils::IsLiquidAddress(test_conf));

  nunchuk::Utils::SetChain(nunchuk::Chain::TESTNET);
  CHECK(nunchuk::Utils::IsLiquidAddress(test_conf));
  CHECK_FALSE(nunchuk::Utils::IsLiquidAddress(main_unconf));
  CHECK_FALSE(nunchuk::Utils::IsLiquidAddress(main_conf));
  nunchuk::wally::WallyUtils::Cleanup();
}
