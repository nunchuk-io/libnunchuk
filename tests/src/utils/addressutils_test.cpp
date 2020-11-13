// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nunchuk.h>
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
