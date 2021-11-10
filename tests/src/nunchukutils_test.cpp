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
#include <amount.h>

#include <doctest.h>

TEST_CASE("testing SanitizeBIP32Input") {
  using namespace nunchuk;
  std::string xpub =
      "xpub6Gs9Gp1P7ov2Xy6XmVBawLUwRgifGMK93K6bYuMdi9PfmJ6y6e7ffzD"
      "7JKCjWgJn71YGCQMozL1284Ywoaptv8UGRsua635k8yELEKk9nhh";
  std::string ypub =
      "ypub6bhQaUgJGVTWPGHebqyD9RaSbes7CyJdxRcpLJFX69mYpPvCMJHEJ3sFKXAKWaxhWef4"
      "wsxNSzMa1MAWXHEuiN9sJDbzfwuEQhHycrWdgeH";
  std::string Ypub =
      "Ypub6nbVhiQjqT1soqT2YWSByVvFKSuNRKzEGhGVFZX4TvbxSaV77hfWPAjB8E7o52Bbk7j3"
      "pTxVLCk58WnGpWPrrrGY8giQ5MNEJRZrCmSRoL4";
  std::string zpub =
      "zpub6vXft9MDRAzzEZUmSCkqMWfwmd1Z9bJ8sY937h9QUA9RsVjRbxSnv7XPLj7uWVccvHms"
      "hMYvuei7tdn5EyevWbqUAZJRFriigRMd1QQKz7X";
  std::string Zpub =
      "Zpub77Rm1P5ez8ZMf8e9NsDpBb1kVR3pMwyjBoni2xQwqvyqVgJLNMq51EPK9S5P4vqX9kqr"
      "ZwZ3ns6d1oPqYCosf5x912QpfGBia9dVbJBHr4f";
  std::string tpub =
      "tpubDHEmo3q4q5sUomHPDgAg9FpJkopKFjpCawgtuTQn449ZWamgArxkpRswYMHX3BG1tv5A"
      "oysgXRq4pF3ZCSg8oZvZVUesmZjyivpjzGcUHhL";
  std::string upub =
      "upub5JNMMozdfmHaz5XBGQpiK5CRunHKSVLeHyXwCifya8G2bzfHLfcyooEhEhKyWxM1t6Bq"
      "wya8cLwNUCiFeVarXRRTprpJLJdHKo3Q4YUZrZs";
  std::string Upub =
      "Upub5VGSV3j5EiqxQegZD5Hh99YEdaKaer2EcFBc7ywWwu6SEBEC751Ftv6d3QHT5PZv7ZFp"
      "pZaFVZKsbNL1wijofuY8fKvhji6HDXKGeUuAykS";
  std::string vpub =
      "vpub5dCcfUfYpSq4qNiJ6mcLXAHw5kRmP7L9D649z7Zrx8duf6UWbKnYRrtqFuHZWrzwHjJe"
      "hTAh51HvMVKpNBzsKf74hCWivDSmbX73T9rLCgP";
  std::string Vpub =
      "Vpub5p6hniPzPQPSFwsg3S5KMEdjoYU2bU1jXMhpuNqQKuUKHH3RMjApWykm4cF35JDqXCNd"
      "a3AoxDgRUewafR9pU9DjXfd8KcumVFNv353acNH";

  CHECK(Utils::SanitizeBIP32Input(xpub, "xpub") == xpub);
  CHECK(Utils::SanitizeBIP32Input(ypub, "xpub") == xpub);
  CHECK(Utils::SanitizeBIP32Input(Ypub, "xpub") == xpub);
  CHECK(Utils::SanitizeBIP32Input(zpub, "xpub") == xpub);
  CHECK(Utils::SanitizeBIP32Input(Zpub, "xpub") == xpub);
  CHECK(Utils::SanitizeBIP32Input(tpub, "tpub") == tpub);
  CHECK(Utils::SanitizeBIP32Input(upub, "tpub") == tpub);
  CHECK(Utils::SanitizeBIP32Input(Upub, "tpub") == tpub);
  CHECK(Utils::SanitizeBIP32Input(vpub, "tpub") == tpub);
  CHECK(Utils::SanitizeBIP32Input(Vpub, "tpub") == tpub);
  CHECK_THROWS(Utils::SanitizeBIP32Input("invalidxpub", "tpub"));
  CHECK_THROWS(Utils::SanitizeBIP32Input("", "tpub"));
}

TEST_CASE("testing IsValid...") {
  using namespace nunchuk;
  Utils::SetChain(Chain::MAIN);
  CHECK(Utils::IsValidXPub(
      "xpub6Gs9Gp1P7ov2Xy6XmVBawLUwRgifGMK93K6bYuMdi9PfmJ6y6e7ffzD"
      "7JKCjWgJn71YGCQMozL1284Ywoaptv8UGRsua635k8yELEKk9nhh"));
  CHECK(Utils::IsValidPublicKey(
      "0297da76f2b4ae426f41e617b4f13243716d1417d3acc3f8da7a54f301fc951741"));
  CHECK(Utils::IsValidDerivationPath("m/44h/0h/1h"));
  CHECK(Utils::IsValidDerivationPath("m/48'/0'/0'/7'"));
  CHECK(Utils::IsValidFingerPrint("0b93c52e"));

  CHECK_FALSE(Utils::IsValidXPub(
      "tpubDHEmo3q4q5sUomHPDgAg9FpJkopKFjpCawgtuTQn449ZWamgArxkpRs"
      "wYMHX3BG1tv5AoysgXRq4pF3ZCSg8oZvZVUesmZjyivpjzGcUHhL"));
  CHECK_FALSE(Utils::IsValidFingerPrint("0b93c52j"));
  CHECK_FALSE(Utils::IsValidFingerPrint("0b93c5"));

  Utils::SetChain(Chain::TESTNET);
  CHECK_FALSE(Utils::IsValidXPub(
      "xpub6Gs9Gp1P7ov2Xy6XmVBawLUwRgifGMK93K6bYuMdi9PfmJ6y6e7ffzD"
      "7JKCjWgJn71YGCQMozL1284Ywoaptv8UGRsua635k8yELEKk9nhh"));

  CHECK(Utils::IsValidXPub(
      "tpubDHEmo3q4q5sUomHPDgAg9FpJkopKFjpCawgtuTQn449ZWamgArxkpRs"
      "wYMHX3BG1tv5AoysgXRq4pF3ZCSg8oZvZVUesmZjyivpjzGcUHhL"));
  CHECK(Utils::IsValidDerivationPath("m/44h/1h/1h"));
  CHECK(Utils::IsValidDerivationPath("m/48'/1'/0'/7'"));
}

TEST_CASE("testing Amount") {
  using namespace nunchuk;

  CHECK_THROWS(Utils::AmountFromValue("21000001"));
  CHECK_THROWS(Utils::AmountFromValue("-21000001", true));
  CHECK_NOTHROW(Utils::AmountFromValue("21000000"));
  CHECK_NOTHROW(Utils::AmountFromValue("-21000000", true));
  CHECK(Utils::AmountFromValue("0.00010000") == 10000);
  CHECK(Utils::AmountFromValue("-0.00010000", true) == -10000);
  CHECK(Utils::AmountFromValue("21000000") == 2100000000000000);
  CHECK(Utils::AmountFromValue("-21000000", true) == -2100000000000000);

  CHECK(Utils::AmountFromValue("0") == 0LL);
  CHECK(Utils::AmountFromValue("0.00000000") == 0LL);
  CHECK(Utils::AmountFromValue("0.00000001") == 1LL);
  CHECK(Utils::AmountFromValue("0.17622195") == 17622195LL);
  CHECK(Utils::AmountFromValue("0.5") == 50000000LL);
  CHECK(Utils::AmountFromValue("0.50000000") == 50000000LL);
  CHECK(Utils::AmountFromValue("0.89898989") == 89898989LL);
  CHECK(Utils::AmountFromValue("1.00000000") == 100000000LL);
  CHECK(Utils::AmountFromValue("20999999.9999999") == 2099999999999990LL);
  CHECK(Utils::AmountFromValue("20999999.99999999") == 2099999999999999LL);

  CHECK(Utils::AmountFromValue("1e-8") == COIN / 100000000);
  CHECK(Utils::AmountFromValue("0.1e-7") == COIN / 100000000);
  CHECK(Utils::AmountFromValue("0.01e-6") == COIN / 100000000);
  CHECK(Utils::AmountFromValue(
            "0."
            "00000000000000000000000000000000000000000000000000000"
            "00000000000000000000001e+68") == COIN / 100000000);
  CHECK(Utils::AmountFromValue(
            "10000000000000000000000000000000000000000000000000000"
            "000000000000e-64") == COIN);
  CHECK(Utils::AmountFromValue(
            "0."
            "000000000000000000000000000000000000000000000000000000000000000100"
            "000000000000000000000000000000000000000000000000000e64") == COIN);

  CHECK_THROWS(Utils::AmountFromValue("1e-9"));         // should fail
  CHECK_THROWS(Utils::AmountFromValue("0.000000019"));  // should fail
  CHECK(Utils::AmountFromValue("0.00000001000000") ==
        1LL);  // should pass == cut trailing 0
  CHECK_THROWS(Utils::AmountFromValue("19e-9"));  // should fail
  CHECK(Utils::AmountFromValue("0.19e-6") ==
        19);  // should pass == leading 0 is present

  CHECK_THROWS(
      Utils::AmountFromValue("92233720368.54775808"));  // overflow error
  CHECK_THROWS(Utils::AmountFromValue("1e+11"));        // overflow error
  CHECK_THROWS(Utils::AmountFromValue("1e11"));   // overflow error signless
  CHECK_THROWS(Utils::AmountFromValue("93e+9"));  // overflow error

  CHECK(Utils::ValueFromAmount(0LL) == "0.00000000");
  CHECK(Utils::ValueFromAmount(1LL) == "0.00000001");
  CHECK(Utils::ValueFromAmount(17622195LL) == "0.17622195");
  CHECK(Utils::ValueFromAmount(50000000LL) == "0.50000000");
  CHECK(Utils::ValueFromAmount(89898989LL) == "0.89898989");
  CHECK(Utils::ValueFromAmount(100000000LL) == "1.00000000");
  CHECK(Utils::ValueFromAmount(2099999999999990LL) == "20999999.99999990");
  CHECK(Utils::ValueFromAmount(2099999999999999LL) == "20999999.99999999");

  CHECK(Utils::ValueFromAmount(0) == "0.00000000");
  CHECK(Utils::ValueFromAmount((COIN / 10000) * 123456789) == "12345.67890000");
  CHECK(Utils::ValueFromAmount(-COIN) == "-1.00000000");
  CHECK(Utils::ValueFromAmount(-COIN / 10) == "-0.10000000");

  CHECK(Utils::ValueFromAmount(COIN * 100000000) == "100000000.00000000");
  CHECK(Utils::ValueFromAmount(COIN * 10000000) == "10000000.00000000");
  CHECK(Utils::ValueFromAmount(COIN * 1000000) == "1000000.00000000");
  CHECK(Utils::ValueFromAmount(COIN * 100000) == "100000.00000000");
  CHECK(Utils::ValueFromAmount(COIN * 10000) == "10000.00000000");
  CHECK(Utils::ValueFromAmount(COIN * 1000) == "1000.00000000");
  CHECK(Utils::ValueFromAmount(COIN * 100) == "100.00000000");
  CHECK(Utils::ValueFromAmount(COIN * 10) == "10.00000000");
  CHECK(Utils::ValueFromAmount(COIN) == "1.00000000");
  CHECK(Utils::ValueFromAmount(COIN / 10) == "0.10000000");
  CHECK(Utils::ValueFromAmount(COIN / 100) == "0.01000000");
  CHECK(Utils::ValueFromAmount(COIN / 1000) == "0.00100000");
  CHECK(Utils::ValueFromAmount(COIN / 10000) == "0.00010000");
  CHECK(Utils::ValueFromAmount(COIN / 100000) == "0.00001000");
  CHECK(Utils::ValueFromAmount(COIN / 1000000) == "0.00000100");
  CHECK(Utils::ValueFromAmount(COIN / 10000000) == "0.00000010");
  CHECK(Utils::ValueFromAmount(COIN / 100000000) == "0.00000001");
}
