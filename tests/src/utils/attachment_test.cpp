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
#include <utils/attachment.hpp>

#include <doctest.h>

TEST_CASE("testing encrypt and descrypt attachment") {
  using namespace nunchuk;
  std::string body = "testtesttest";
  std::string accessToken = "";
  if (accessToken.empty()) return;
  auto event_file = EncryptAttachment(accessToken, body);
  CHECK(!event_file.empty());
  CHECK(DecryptAttachment(event_file) == body);
}
