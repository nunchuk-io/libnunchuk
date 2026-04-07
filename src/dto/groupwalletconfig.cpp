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
#include <vector>
#include <descriptor.h>

namespace nunchuk {

GroupWalletConfig::GroupWalletConfig() {}

int GroupWalletConfig::get_chat_retention_days() const {
  return chat_retention_days_;
}

const std::optional<GroupPlatformKey>& GroupWalletConfig::get_platform_key()
    const {
  return platform_key_;
}

std::string GroupWalletConfig::get_platform_key_fingerprint() const {
  return platform_key_fingerprint_;
}

void GroupWalletConfig::set_chat_retention_days(int value) {
  chat_retention_days_ = value;
}

void GroupWalletConfig::set_platform_key(std::optional<GroupPlatformKey> value) {
  platform_key_ = std::move(value);
}

void GroupWalletConfig::set_platform_key_fingerprint(const std::string& value) {
  platform_key_fingerprint_ = value;
}

}  // namespace nunchuk
