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

#include "groupdb.h"

namespace nunchuk {

void NunchukGroupDb::Init() {
  CreateTable();
}

void NunchukGroupDb::SetDeviceToken(const std::string& value) {
  PutString(DbKeys::GROUP_DEVICE_TOKEN, value);
}

void NunchukGroupDb::SetEphemeralKey(const std::string& pub, const std::string& priv) {
  PutString(DbKeys::GROUP_EPHEMERAL_PUB, pub);
  PutString(DbKeys::GROUP_EPHEMERAL_PRIV, priv);
}

std::string NunchukGroupDb::GetDeviceToken() const {
  return GetString(DbKeys::GROUP_DEVICE_TOKEN);
}

std::pair<std::string, std::string> NunchukGroupDb::GetEphemeralKey() const {
  return {GetString(DbKeys::GROUP_EPHEMERAL_PUB), GetString(DbKeys::GROUP_EPHEMERAL_PRIV)};
}

}  // namespace nunchuk
