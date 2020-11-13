// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <utils/bip32.hpp>

#include <doctest.h>

TEST_CASE("testing bip32 utils") {
  using namespace nunchuk;
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::SINGLE_SIG,
                     AddressType::LEGACY, 1) == "m/44h/1h/1h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::SINGLE_SIG,
                     AddressType::NESTED_SEGWIT, 2) == "m/49h/1h/2h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::SINGLE_SIG,
                     AddressType::NATIVE_SEGWIT, 3) == "m/84h/1h/3h");
  CHECK_THROWS(GetBip32Path(Chain::TESTNET, WalletType::SINGLE_SIG,
                            AddressType::ANY, 3));
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::MULTI_SIG, AddressType::LEGACY,
                     4) == "m/48h/1h/4h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::MULTI_SIG,
                     AddressType::NESTED_SEGWIT, 5) == "m/48h/1h/5h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::MULTI_SIG,
                     AddressType::NATIVE_SEGWIT, 6) == "m/48h/1h/6h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::MULTI_SIG, AddressType::ANY,
                     6) == "m/48h/1h/6h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::ESCROW, AddressType::LEGACY,
                     7) == "m/48h/1h/0h/7h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::ESCROW,
                     AddressType::NESTED_SEGWIT, 8) == "m/48h/1h/0h/8h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::ESCROW,
                     AddressType::NATIVE_SEGWIT, 9) == "m/48h/1h/0h/9h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::ESCROW, AddressType::ANY, 9) ==
        "m/48h/1h/0h/9h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::SINGLE_SIG, AddressType::LEGACY,
                     1) == "m/44h/0h/1h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::SINGLE_SIG,
                     AddressType::NESTED_SEGWIT, 2) == "m/49h/0h/2h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::SINGLE_SIG,
                     AddressType::NATIVE_SEGWIT, 3) == "m/84h/0h/3h");
  CHECK_THROWS(
      GetBip32Path(Chain::MAIN, WalletType::SINGLE_SIG, AddressType::ANY, 3));
  CHECK(GetBip32Path(Chain::MAIN, WalletType::MULTI_SIG, AddressType::LEGACY,
                     4) == "m/48h/0h/4h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::MULTI_SIG,
                     AddressType::NESTED_SEGWIT, 5) == "m/48h/0h/5h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::MULTI_SIG,
                     AddressType::NATIVE_SEGWIT, 6) == "m/48h/0h/6h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::MULTI_SIG, AddressType::ANY, 6) ==
        "m/48h/0h/6h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::ESCROW, AddressType::LEGACY, 7) ==
        "m/48h/0h/0h/7h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::ESCROW,
                     AddressType::NESTED_SEGWIT, 8) == "m/48h/0h/0h/8h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::ESCROW,
                     AddressType::NATIVE_SEGWIT, 9) == "m/48h/0h/0h/9h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::ESCROW, AddressType::ANY, 9) ==
        "m/48h/0h/0h/9h");
  CHECK_THROWS(GetBip32Path(Chain::MAIN, WalletType::MULTI_SIG,
                            AddressType::NESTED_SEGWIT, 0));

  CHECK(GetBip32Type(WalletType::SINGLE_SIG, AddressType::LEGACY) == "bip44");
  CHECK(GetBip32Type(WalletType::SINGLE_SIG, AddressType::NESTED_SEGWIT) ==
        "bip49");
  CHECK(GetBip32Type(WalletType::SINGLE_SIG, AddressType::NATIVE_SEGWIT) ==
        "bip84");
  CHECK_THROWS(GetBip32Type(WalletType::SINGLE_SIG, AddressType::ANY));
  CHECK(GetBip32Type(WalletType::MULTI_SIG, AddressType::LEGACY) == "bip48");
  CHECK(GetBip32Type(WalletType::MULTI_SIG, AddressType::NESTED_SEGWIT) ==
        "bip48");
  CHECK(GetBip32Type(WalletType::MULTI_SIG, AddressType::NATIVE_SEGWIT) ==
        "bip48");
  CHECK(GetBip32Type(WalletType::MULTI_SIG, AddressType::ANY) == "bip48");
  CHECK(GetBip32Type(WalletType::ESCROW, AddressType::LEGACY) == "escrow");
  CHECK(GetBip32Type(WalletType::ESCROW, AddressType::NESTED_SEGWIT) ==
        "escrow");
  CHECK(GetBip32Type(WalletType::ESCROW, AddressType::NATIVE_SEGWIT) ==
        "escrow");
  CHECK(GetBip32Type(WalletType::ESCROW, AddressType::ANY) == "escrow");

  CHECK(GetIndexFromPath("m/84h/0h/10h") == 10);
  CHECK(GetIndexFromPath("m/48h/0h/0h/11h") == 11);
}
