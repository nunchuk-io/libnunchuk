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

#include "utils/bitbox/u2f_framer.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace nunchuk::bitbox {
namespace {

constexpr size_t INITIAL_HEADER_SIZE = 7;
constexpr size_t CONTINUATION_HEADER_SIZE = 5;
constexpr size_t INITIAL_PAYLOAD_SIZE =
    U2fFramer::REPORT_SIZE - INITIAL_HEADER_SIZE;
constexpr size_t CONTINUATION_PAYLOAD_SIZE =
    U2fFramer::REPORT_SIZE - CONTINUATION_HEADER_SIZE;
constexpr size_t MAX_CONTINUATION_SEQUENCE = 127;
constexpr size_t MAX_PAYLOAD_SIZE =
    INITIAL_PAYLOAD_SIZE +
    (MAX_CONTINUATION_SEQUENCE + 1) * CONTINUATION_PAYLOAD_SIZE;

uint32_t ReadBe32(std::span<const unsigned char> data) {
  return (static_cast<uint32_t>(data[0]) << 24) |
         (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) |
         static_cast<uint32_t>(data[3]);
}

void WriteBe32(std::vector<unsigned char>& data, uint32_t value) {
  data[0] = static_cast<unsigned char>(value >> 24);
  data[1] = static_cast<unsigned char>(value >> 16);
  data[2] = static_cast<unsigned char>(value >> 8);
  data[3] = static_cast<unsigned char>(value);
}

}  // namespace

U2fFramer::U2fFramer(uint32_t cid, unsigned char command)
    : cid_(cid), command_(command) {
  if (cid_ == 0 || cid_ == 0xffffffffU) {
    throw std::invalid_argument("BitBox U2F channel ID is reserved");
  }
  if ((command_ & 0x80) == 0) {
    throw std::invalid_argument(
        "BitBox U2F command must be an initial-frame command");
  }
}

std::vector<std::vector<unsigned char>> U2fFramer::encode(
    std::span<const unsigned char> payload) const {
  if (payload.size() > MAX_PAYLOAD_SIZE) {
    throw std::invalid_argument("BitBox U2F payload is too large");
  }

  std::vector<std::vector<unsigned char>> reports;
  reports.emplace_back(REPORT_SIZE, 0);
  auto& initial = reports.back();
  WriteBe32(initial, cid_);
  initial[4] = command_;
  initial[5] = static_cast<unsigned char>(payload.size() >> 8);
  initial[6] = static_cast<unsigned char>(payload.size());

  size_t offset = std::min(payload.size(), INITIAL_PAYLOAD_SIZE);
  std::copy_n(payload.begin(), offset, initial.begin() + INITIAL_HEADER_SIZE);

  uint8_t sequence = 0;
  while (offset < payload.size()) {
    reports.emplace_back(REPORT_SIZE, 0);
    auto& continuation = reports.back();
    WriteBe32(continuation, cid_);
    continuation[4] = sequence++;
    const auto length =
        std::min(payload.size() - offset, CONTINUATION_PAYLOAD_SIZE);
    std::copy_n(payload.begin() + offset, length,
                continuation.begin() + CONTINUATION_HEADER_SIZE);
    offset += length;
  }
  return reports;
}

U2fDecodeResult U2fFramer::decode(
    std::span<const unsigned char> reports) {
  if (reports.empty() || reports.size() % REPORT_SIZE != 0) {
    return fail("BitBox transport data is not a sequence of 64-byte reports");
  }

  U2fDecodeResult result;
  for (size_t offset = 0; offset < reports.size(); offset += REPORT_SIZE) {
    result = decodeReport(reports.subspan(offset, REPORT_SIZE));
    if (result.type != U2fDecodeResult::Type::READ_MORE) {
      if (offset + REPORT_SIZE != reports.size()) {
        return fail("BitBox U2F response has trailing reports");
      }
      return result;
    }
  }
  return result;
}

U2fDecodeResult U2fFramer::decodeReport(
    std::span<const unsigned char> report) {
  if (ReadBe32(report.first<4>()) != cid_) {
    return fail("BitBox U2F response has an unexpected channel ID");
  }

  if (!expected_length_.has_value()) {
    if (report[4] != command_) {
      return fail("BitBox U2F response has an unexpected command");
    }
    const size_t length =
        (static_cast<size_t>(report[5]) << 8) | report[6];
    if (length > MAX_PAYLOAD_SIZE) {
      return fail("BitBox U2F response payload is too large");
    }
    expected_length_ = length;
    const auto copy_length = std::min(length, INITIAL_PAYLOAD_SIZE);
    pending_.insert(pending_.end(), report.begin() + INITIAL_HEADER_SIZE,
                    report.begin() + INITIAL_HEADER_SIZE + copy_length);
  } else {
    if ((report[4] & 0x80) != 0 || report[4] != expected_sequence_) {
      return fail("BitBox U2F response has an invalid continuation sequence");
    }
    ++expected_sequence_;
    const auto remaining = *expected_length_ - pending_.size();
    const auto copy_length = std::min(remaining, CONTINUATION_PAYLOAD_SIZE);
    pending_.insert(pending_.end(), report.begin() + CONTINUATION_HEADER_SIZE,
                    report.begin() + CONTINUATION_HEADER_SIZE + copy_length);
  }

  if (pending_.size() < *expected_length_) {
    return {};
  }

  U2fDecodeResult result;
  result.type = U2fDecodeResult::Type::COMPLETE;
  result.payload = std::move(pending_);
  reset();
  return result;
}

U2fDecodeResult U2fFramer::fail(const std::string& message) {
  reset();
  U2fDecodeResult result;
  result.type = U2fDecodeResult::Type::FAILED;
  result.error = message;
  return result;
}

void U2fFramer::reset() {
  pending_.clear();
  expected_length_.reset();
  expected_sequence_ = 0;
}

}  // namespace nunchuk::bitbox
