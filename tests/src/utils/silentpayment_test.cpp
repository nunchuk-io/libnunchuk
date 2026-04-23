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
#include <utils/silentpayment.hpp>

#include <doctest.h>

TEST_CASE("silentpayment: long bech32m checksum validation") {
  nunchuk::Utils::SetChain(nunchuk::Chain::MAIN);

  const std::string valid_long_sp =
      "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
  const std::string invalid_long_sp_mutated =
      "sp1qq2ste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";

  auto ok = nunchuk::silentpayment::DecodeSilentPaymentAddress(valid_long_sp, nunchuk::Chain::MAIN);
  CHECK(ok.IsValid());

  auto bad = nunchuk::silentpayment::DecodeSilentPaymentAddress(invalid_long_sp_mutated, nunchuk::Chain::MAIN);
  CHECK_FALSE(bad.IsValid());
}

TEST_CASE("silentpayment: recommended 1023 char limit enforced") {
  nunchuk::Utils::SetChain(nunchuk::Chain::MAIN);

  std::string too_long(1024, 'a');
  auto keys = nunchuk::silentpayment::DecodeSilentPaymentAddress(too_long, nunchuk::Chain::MAIN);
  CHECK_FALSE(keys.IsValid());
}

