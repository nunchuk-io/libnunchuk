/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * libnunchuk is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libnunchuk. If not, see <http://www.gnu.org/licenses/>.
 */

#include "utils/bitbox/pairing_store.hpp"

#include <algorithm>
#include <random.h>
#include <stdexcept>

#include <nunchuk.h>
#include <util/strencodings.h>

#include "utils/bitbox/crypto.hpp"
#include "utils/json.hpp"
#include "utils/loguru.hpp"

namespace nunchuk::bitbox {
namespace {

using json = nlohmann::json;

std::array<unsigned char, 32> ParseKey(const std::string& value) {
  const auto bytes = ParseHex(value);
  if (bytes.size() != 32) {
    throw std::runtime_error("BitBox pairing key has an invalid length");
  }
  std::array<unsigned char, 32> result{};
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}

}  // namespace

PairingStore::PairingStore(Nunchuk& nunchuk) : nunchuk_(nunchuk) {
  loadOrCreate();
}

PairingStore::~PairingStore() {
  SecureClear(private_key_);
}

void PairingStore::loadOrCreate() {
  const auto create = [this] {
    SecureClear(private_key_);
    devices_.clear();
    GetStrongRandBytes(private_key_);
    save();
  };
  try {
    const auto serialized = nunchuk_.GetBitBoxPairingData();
    if (serialized.empty()) {
      create();
      return;
    }
    const auto record = json::parse(serialized);
    if (record.at("version").get<int>() != 1) {
      throw std::runtime_error("unsupported BitBox pairing record version");
    }
    private_key_ =
        ParseKey(record.at("app_static_private_key").get<std::string>());
    for (const auto& device : record.value("device_static_public_keys",
                                           std::vector<std::string>{})) {
      const auto key = ParseKey(device);
      if (std::find(devices_.begin(), devices_.end(), key) == devices_.end()) {
        devices_.push_back(key);
      }
    }
  } catch (const std::exception& e) {
    DLOG_F(WARNING,
           "Could not load BitBox pairing data; creating a new pairing "
           "record: %s",
           e.what());
    (void)e;
    create();
  }
}

void PairingStore::save() const noexcept {
  try {
    json record = {{"version", 1},
                   {"app_static_private_key", HexStr(private_key_)}};
    record["device_static_public_keys"] = json::array();
    for (const auto& device : devices_) {
      record["device_static_public_keys"].push_back(HexStr(device));
    }
    if (!nunchuk_.SetBitBoxPairingData(record.dump())) {
      DLOG_F(WARNING,
             "Could not save BitBox pairing data; the device will need to "
             "pair again");
    }
  } catch (const std::exception& e) {
    DLOG_F(WARNING,
           "Could not save BitBox pairing data; the device will need to pair "
           "again: %s",
           e.what());
    (void)e;
  } catch (...) {
    DLOG_F(WARNING,
           "Could not save BitBox pairing data; the device will need to pair "
           "again");
  }
}

std::array<unsigned char, 32> PairingStore::appStaticPrivateKey() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return private_key_;
}

bool PairingStore::containsDevice(
    std::span<const unsigned char> public_key) const {
  if (public_key.size() != 32) return false;
  std::array<unsigned char, 32> key{};
  std::copy(public_key.begin(), public_key.end(), key.begin());
  std::lock_guard<std::mutex> lock(mutex_);
  return std::find(devices_.begin(), devices_.end(), key) != devices_.end();
}

void PairingStore::addDevice(std::span<const unsigned char> public_key) {
  if (public_key.size() != 32) {
    throw std::invalid_argument("BitBox device static key must be 32 bytes");
  }
  std::array<unsigned char, 32> key{};
  std::copy(public_key.begin(), public_key.end(), key.begin());
  std::lock_guard<std::mutex> lock(mutex_);
  if (std::find(devices_.begin(), devices_.end(), key) == devices_.end()) {
    devices_.push_back(key);
    save();
  }
}

}  // namespace nunchuk::bitbox
