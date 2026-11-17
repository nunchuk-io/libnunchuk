/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */

#include "utils/onekey/wire_framer.hpp"

#include <algorithm>
#include <stdexcept>

namespace nunchuk::onekey {

WireFramer::WireFramer(OneKeyTransport transport) : transport_(transport) {}

std::vector<std::vector<unsigned char>> WireFramer::encode(
    uint16_t type, std::span<const unsigned char> data) {
  if (data.size() > MAX_MESSAGE_SIZE) {
    throw std::invalid_argument("OneKey message is too large");
  }
  const auto size = static_cast<uint32_t>(data.size());
  std::vector<unsigned char> message{'#',
                                     '#',
                                     static_cast<unsigned char>(type >> 8),
                                     static_cast<unsigned char>(type),
                                     static_cast<unsigned char>(size >> 24),
                                     static_cast<unsigned char>(size >> 16),
                                     static_cast<unsigned char>(size >> 8),
                                     static_cast<unsigned char>(size)};
  message.insert(message.end(), data.begin(), data.end());
  std::vector<std::vector<unsigned char>> result;
  for (size_t offset = 0; offset < message.size(); offset += 63) {
    std::vector<unsigned char> packet(64);
    packet[0] = '?';
    std::copy_n(message.begin() + offset,
                std::min(size_t{63}, message.size() - offset),
                packet.begin() + 1);
    result.push_back(std::move(packet));
  }
  return result;
}

void WireFramer::append(std::span<const unsigned char> data) {
  if (message_.size() + data.size() > MAX_MESSAGE_SIZE + 72) {
    throw std::runtime_error("OneKey response is too large");
  }
  message_.insert(message_.end(), data.begin(), data.end());
  if (message_.size() >= 9 && !expected_size_) {
    if (message_[0] != '?' || message_[1] != '#' || message_[2] != '#') {
      throw std::runtime_error("Invalid OneKey response header");
    }
    uint32_t size = 0;
    for (size_t i = 5; i < 9; ++i) size = (size << 8) | message_[i];
    if (size > MAX_MESSAGE_SIZE) {
      throw std::runtime_error("OneKey response is too large");
    }
    expected_size_ = size + 9;
  }
}

std::optional<WireMessage> WireFramer::receive(
    std::span<const unsigned char> data) {
  if (transport_ == OneKeyTransport::BLE) {
    append(data);
  } else {
    while (!data.empty()) {
      if (expected_size_ && message_.size() >= *expected_size_) {
        throw std::runtime_error("Unexpected extra OneKey USB report");
      }
      const size_t count = std::min(64 - packet_.size(), data.size());
      packet_.insert(packet_.end(), data.begin(), data.begin() + count);
      data = data.subspan(count);
      if (packet_.size() == 64) {
        if (packet_[0] != '?') {
          throw std::runtime_error("Invalid OneKey USB report marker");
        }
        append(std::span(packet_).subspan(message_.empty() ? 0 : 1));
        packet_.clear();
      }
    }
  }
  if (!expected_size_ || message_.size() < *expected_size_) return std::nullopt;
  if (message_.size() - *expected_size_ > 63) {
    throw std::runtime_error("Unexpected trailing OneKey response data");
  }
  WireMessage result{
      static_cast<uint16_t>((uint16_t{message_[3]} << 8) | message_[4]),
      {message_.begin() + 9, message_.begin() + *expected_size_}};
  reset();
  return result;
}

void WireFramer::reset() {
  packet_.clear();
  message_.clear();
  expected_size_.reset();
}

}  // namespace nunchuk::onekey
