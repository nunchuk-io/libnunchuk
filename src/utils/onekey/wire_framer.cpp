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

namespace {
uint8_t Crc8(std::span<const unsigned char> bytes) {
  uint8_t crc = 0x30;
  for (auto byte : bytes) {
    crc ^= byte;
    for (int bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ ((crc & 1) ? 0x8c : 0);
  }
  return crc;
}
}  // namespace

V2Framer::V2Framer(OneKeyTransport transport, std::shared_ptr<uint8_t> sequence)
    : router_(transport == OneKeyTransport::BLE ? 1 : 0),
      sequence_(std::move(sequence)) {
  if (!sequence_)
    throw std::invalid_argument("Missing OneKey Protocol V2 sequence");
}

std::vector<std::vector<unsigned char>> V2Framer::encode(
    uint16_t type, std::span<const unsigned char> data) {
  if (data.size() > MAX_FRAME_SIZE - 10)
    throw std::invalid_argument(
        "OneKey Protocol V2 message exceeds 4200-byte frame limit");
  const size_t size = data.size() + 10;
  pending_sequence_ = *sequence_ = *sequence_ == 255 ? 1 : *sequence_ + 1;
  std::vector<unsigned char> frame(size);
  frame[0] = 0x5a;
  frame[1] = size & 0xff;
  frame[2] = size >> 8;
  frame[3] = Crc8(std::span(frame).first(3));
  frame[4] = router_;
  frame[5] = 0;  // Command source, protobuf packet.
  frame[6] = pending_sequence_;
  frame[7] = type & 0xff;
  frame[8] = type >> 8;
  std::copy(data.begin(), data.end(), frame.begin() + 9);
  frame.back() = Crc8(std::span(frame).first(size - 1));
  std::vector<std::vector<unsigned char>> writes;
  // Both USB and BLE carry the raw frame; no HID marker or padding is added.
  for (size_t offset = 0; offset < size; offset += 64) {
    writes.emplace_back(frame.begin() + offset,
                        frame.begin() + std::min(size, offset + 64));
  }
  return writes;
}

std::optional<WireMessage> V2Framer::receive(
    std::span<const unsigned char> data) {
  if (buffer_.size() + data.size() > 2 * MAX_FRAME_SIZE)
    throw std::runtime_error("OneKey Protocol V2 response is too large");
  buffer_.insert(buffer_.end(), data.begin(), data.end());
  std::optional<WireMessage> result;
  while (buffer_.size() >= 4) {
    const auto bytes = std::span(buffer_);
    const size_t size = bytes[1] | (size_t{bytes[2]} << 8);
    if (bytes[0] != 0x5a || bytes[3] != Crc8(bytes.first(3)) || size < 8 ||
        size > MAX_FRAME_SIZE)
      throw std::runtime_error("Invalid OneKey Protocol V2 frame header");
    if (bytes.size() < size) break;
    if (bytes[size - 1] != Crc8(bytes.first(size - 1)))
      throw std::runtime_error("Invalid OneKey Protocol V2 frame CRC");
    if (bytes[4] != router_ || (bytes[5] >> 2) != 0 || bytes[6] == 0)
      throw std::runtime_error("Invalid OneKey Protocol V2 route or sequence");
    const auto kind = bytes[5] & 3;
    if (kind == 1) {
      if (size != 8 || bytes[6] != pending_sequence_)
        throw std::runtime_error("Invalid OneKey Protocol V2 acknowledgment");
    } else if (kind == 0) {
      if (size < 10 || result || bytes[6] == last_response_sequence_)
        throw std::runtime_error(
            "Unexpected OneKey Protocol V2 response sequence");
      last_response_sequence_ = bytes[6];
      result = WireMessage{
          static_cast<uint16_t>(bytes[7] | (uint16_t{bytes[8]} << 8)),
          {bytes.begin() + 9, bytes.begin() + size - 1}};
    } else {
      throw std::runtime_error("Invalid OneKey Protocol V2 packet type");
    }
    buffer_.erase(buffer_.begin(), buffer_.begin() + size);
  }
  return result;
}

void V2Framer::reset() { buffer_.clear(); }

}  // namespace nunchuk::onekey
