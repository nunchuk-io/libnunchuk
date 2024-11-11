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
                     4) == "m/45h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::MULTI_SIG,
                     AddressType::NESTED_SEGWIT, 5) == "m/48h/1h/5h/1h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::MULTI_SIG,
                     AddressType::NATIVE_SEGWIT, 6) == "m/48h/1h/6h/2h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::ESCROW, AddressType::LEGACY,
                     7) == "m/48h/1h/9999h/7h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::ESCROW,
                     AddressType::NESTED_SEGWIT, 8) == "m/48h/1h/9999h/8h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::ESCROW,
                     AddressType::NATIVE_SEGWIT, 9) == "m/48h/1h/9999h/9h");
  CHECK(GetBip32Path(Chain::TESTNET, WalletType::ESCROW, AddressType::ANY, 9) ==
        "m/48h/1h/9999h/9h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::SINGLE_SIG, AddressType::LEGACY,
                     1) == "m/44h/0h/1h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::SINGLE_SIG,
                     AddressType::NESTED_SEGWIT, 2) == "m/49h/0h/2h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::SINGLE_SIG,
                     AddressType::NATIVE_SEGWIT, 3) == "m/84h/0h/3h");
  CHECK_THROWS(
      GetBip32Path(Chain::MAIN, WalletType::SINGLE_SIG, AddressType::ANY, 3));
  CHECK(GetBip32Path(Chain::MAIN, WalletType::MULTI_SIG, AddressType::LEGACY,
                     4) == "m/45h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::MULTI_SIG,
                     AddressType::NESTED_SEGWIT, 5) == "m/48h/0h/5h/1h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::MULTI_SIG,
                     AddressType::NATIVE_SEGWIT, 6) == "m/48h/0h/6h/2h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::ESCROW, AddressType::LEGACY, 7) ==
        "m/48h/0h/9999h/7h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::ESCROW,
                     AddressType::NESTED_SEGWIT, 8) == "m/48h/0h/9999h/8h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::ESCROW,
                     AddressType::NATIVE_SEGWIT, 9) == "m/48h/0h/9999h/9h");
  CHECK(GetBip32Path(Chain::MAIN, WalletType::ESCROW, AddressType::ANY, 9) ==
        "m/48h/0h/9999h/9h");
  CHECK(GetBip32Type(WalletType::SINGLE_SIG, AddressType::LEGACY) == "bip44");
  CHECK(GetBip32Type(WalletType::SINGLE_SIG, AddressType::NESTED_SEGWIT) ==
        "bip49");
  CHECK(GetBip32Type(WalletType::SINGLE_SIG, AddressType::NATIVE_SEGWIT) ==
        "bip84");
  CHECK_THROWS(GetBip32Type(WalletType::SINGLE_SIG, AddressType::ANY));
  CHECK(GetBip32Type(WalletType::MULTI_SIG, AddressType::LEGACY) == "bip45");
  CHECK(GetBip32Type(WalletType::MULTI_SIG, AddressType::NESTED_SEGWIT) ==
        "bip48_1");
  CHECK(GetBip32Type(WalletType::MULTI_SIG, AddressType::NATIVE_SEGWIT) ==
        "bip48_2");
  CHECK(GetBip32Type(WalletType::ESCROW, AddressType::LEGACY) == "escrow");
  CHECK(GetBip32Type(WalletType::ESCROW, AddressType::NESTED_SEGWIT) ==
        "escrow");
  CHECK(GetBip32Type(WalletType::ESCROW, AddressType::NATIVE_SEGWIT) ==
        "escrow");
  CHECK(GetBip32Type(WalletType::ESCROW, AddressType::ANY) == "escrow");

  CHECK(GetIndexFromPath("m/84h/0h/10h") == 10);
  CHECK(GetIndexFromPath("m/48h/0h/11h/1h") == 11);
}
