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

#include <algorithm>
#include <bit>
#include <iterator>
#include <optional>
#include <regex>
#include <sstream>
#include <bitset>
#include "coldcard.hpp"
#include "crypto/common.h"
#include <crypto/aes.h>
#include "crc32.h"
#include "crypto/sha256.h"
#include "span.h"
#include "util/strencodings.h"
#include "utils/stringutils.hpp"

namespace nunchuk {
static constexpr size_t FILE_HEADER_SIZE = 12;
static constexpr size_t SECTION_HEADER_SIZE = 20;
static constexpr std::array<uint8_t, 6> GOOD_MAGIC = {0x37, 0x7A, 0xBC,
                                                      0xAF, 0x27, 0x1C};
static constexpr std::array<uint8_t, 5> AES_SHA_ENCRYPTED = {0x24, 0x06, 0xf1,
                                                             0x07, 0x01};
static constexpr size_t MAX_BACKUP_FILE_SIZE = 128 * 1024;
static constexpr size_t MIN_SALT_LENGTH = 16;
static constexpr size_t MIN_IV_LENGTH = 16;

struct SectionHeader {
  uint64_t offset;
  uint64_t size;
  uint32_t crc;

  SectionHeader(const unsigned char* data)
      : offset(ReadLE64(data)),
        size(ReadLE64(data + 8)),
        crc(ReadLE32(data + 16)) {}
};

static uint32_t MaskedCRC(const unsigned char* data, uint64_t size) {
  return ur_crc32(data, size) & 0xffffffff;
}

uint64_t ReadVar64(Span<const unsigned char>& data) {
  if (data.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, "Empty input");
  }

  uint8_t first = data[0];
  data = data.subspan(1);

  if (first < 128) {
    return first;
  }

  if (first == 0xFE || first == 0xFF) {
    if (data.size() < 8) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Insufficient data for 8-byte value");
    }
    data = data.subspan(8);
    return ReadLE64(data.data());
  }

  int pos = std::bitset<8>(first).to_string().find("10") + 1;

  if (pos < 1 || pos > 6 || data.size() < pos) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Insufficient data for variable-length value");
  }

  std::vector<unsigned char> tmp(data.begin(), data.begin() + pos);
  tmp.resize(8, 0x00);
  data = data.subspan(pos);

  uint64_t y = ReadLE64(tmp.data());
  uint64_t x = first & (0xef >> pos);

  return (x << pos) + y;
}

static std::vector<unsigned char> encode_utf_16_le(
    Span<const unsigned char> input) {
  std::vector<unsigned char> result;
  result.reserve(input.size() * 2);

  for (size_t i = 0; i < input.size(); ++i) {
    result.push_back(input[i]);
    result.push_back(0);
  }

  return result;
};

static std::vector<unsigned char> calculate_key(
    const std::string& password, const std::vector<unsigned char>& salt,
    int rounds_pow) {
  uint64_t rounds = 1ULL << rounds_pow;
  std::vector<unsigned char> key(32);
  auto passwd = encode_utf_16_le(MakeUCharSpan(password));
  CSHA256 hasher;

  for (uint64_t i = 0; i < rounds; i++) {
    hasher.Write(salt.data(), salt.size());
    hasher.Write(passwd.data(), passwd.size());
    uint64_t counter = i;
    hasher.Write(reinterpret_cast<unsigned char*>(&counter), sizeof(counter));
  }
  hasher.Finalize(key.data());
  return key;
}

struct ParseSectionHeaderResult {
  std::string fname;
  uint64_t body_size{};
  uint64_t unpacked_size{};
  uint32_t expect_crc{};
  uint8_t rounds_pow{};
  std::vector<unsigned char> salt;
  std::vector<unsigned char> iv;
};

static ParseSectionHeaderResult ParseSectionHeader(
    Span<const unsigned char> header) {
  auto patmatch = [](const std::string& pattern,
                     Span<const unsigned char> where) {
    auto pat = ParseHex(pattern);
    auto pos = std::search(where.begin(), where.end(), pat.begin(), pat.end());
    if (pos == where.end()) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Corrupt file?");
    }
    return where.subspan(pat.size() + std::distance(where.begin(), pos));
  };

  auto rv = patmatch("01 04 06 00 01 09", header);
  uint64_t body_size = ReadVar64(rv);

  rv = patmatch("07 0b 01 00 01 24 06 f1 07 01", rv);

  uint64_t crypto_props_len = ReadVar64(rv);
  if (rv.size() < 2) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Corrupt file?");
  }
  unsigned char first = rv[0], second = rv[1];
  rv = rv.subspan(2);

  unsigned char rounds_pow = first & 0x3f;

  if ((first & 0xc0) != 0xc0) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Require salt+iv");
  }

  uint64_t salt_len = ((second >> 4) & 0xf) + 1;
  uint64_t iv_len = (second & 0xf) + 1;

  if (salt_len < MIN_SALT_LENGTH || iv_len < MIN_IV_LENGTH ||
      rv.size() < salt_len + iv_len) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid salt or IV length");
  }

  auto salt = rv.subspan(0, salt_len);
  rv = rv.subspan(salt_len);
  auto iv = rv.subspan(0, iv_len);
  rv = rv.subspan(iv_len);

  rv = patmatch("01 00 0c", rv);
  uint64_t unpacked_size = ReadVar64(rv);
  if (rv.empty() || rv.front() != '\0') {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Corrupt file?");
  }
  rv = rv.subspan(1);

  rv = patmatch("08 0a 01", rv);
  if (rv.size() < 4) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Corrupt file?");
  }
  uint32_t expect_crc = ReadLE32(rv.data());
  rv = rv.subspan(4);
  if (rv.empty() || rv.front() != '\0') {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Corrupt file?");
  }
  rv = rv.subspan(1);

  rv = patmatch("05 01 11", rv);
  uint64_t fname_len = ReadVar64(rv) - 1;
  if (rv.empty() || rv.front() != '\0') {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Corrupt file?");
  }
  rv = rv.subspan(1);

  if (rv.size() < fname_len) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Corrupt file?");
  }
  auto fname_span = encode_utf_16_le(rv.first(fname_len));
  std::string fname(fname_span.begin(), fname_span.end());
  rv = rv.subspan(fname_len);

  if (rv.size() < 2 || rv[0] != '\0' || rv[1] != '\0') {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Corrupt file?");
  }

  return ParseSectionHeaderResult{
      fname,
      body_size,
      unpacked_size,
      expect_crc,
      rounds_pow,
      std::vector<unsigned char>(salt.begin(), salt.end()),
      std::vector<unsigned char>(iv.begin(), iv.end()),
  };
}

static ColdcardBackupData ParseColdcardBackupData(const std::string& data) {
  std::istringstream is(data);
  std::string line;

  auto split_key_value = [](const std::string& s) {
    auto pos = s.find(" = ");
    if (pos == std::string::npos) {
      return std::pair<std::string, std::string>();
    }
    std::string key = s.substr(0, pos);
    std::string value = s.substr(pos + 3);

    if (value.size() > 2 && value.front() == '"' && value.back() == '"') {
      value = value.substr(1, value.size() - 2);
    }

    auto ret = std::make_pair(key, value);
    return ret;
  };

  ColdcardBackupData ret{};

  while (safeGetline(is, line)) {
    if (line.empty()) continue;
    if (line.front() == '#') continue;
    auto [key, value] = split_key_value(line);
    if (key == "mnemonic") {
      ret.mnemonic = value;
    } else if (key == "xprv") {
      ret.xprv = value;
    }
  }
  return ret;
}

ColdcardBackupData ExtractColdcardBackup(const std::vector<unsigned char>& data,
                                         const std::string& password) {
  Span<const unsigned char> input(data);
  if (input.size() < FILE_HEADER_SIZE) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "File too short");
  }

  const Span<const unsigned char> magic(input.subspan(0, 6));

  const uint8_t major = data[6];
  const uint8_t minor = data[7];
  if (!std::equal(GOOD_MAGIC.begin(), GOOD_MAGIC.end(), magic.begin()) || major != 0 || minor < 3) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Bad magic bytes");
  }
  input = input.subspan(8);

  const uint32_t header_crc = ReadLE32(input.data());
  input = input.subspan(4);

  while (!input.empty()) {
    if (input.size() < SECTION_HEADER_SIZE) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Truncated file?");
    }
    const SectionHeader sh(input.data());
    input = input.subspan(SECTION_HEADER_SIZE);

    if (input.size() < sh.offset + sh.size) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Truncated file?");
    }
    const Span<const unsigned char> section = input.first(sh.offset);
    const Span<const unsigned char> header = input.subspan(sh.offset, sh.size);
    input = input.subspan(sh.offset + sh.size);

    auto parse_result = ParseSectionHeader(header);
    if (section.size() != parse_result.body_size) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Corrupt file?");
    }

    if (parse_result.unpacked_size > MAX_BACKUP_FILE_SIZE) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Corrupt file?");
    }

    if (section.size() > parse_result.unpacked_size + 16) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Too big, encoded");
    }

    if (section.size() % 16 != 0) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Not blocked");
    }

    auto key =
        calculate_key(password, parse_result.salt, parse_result.rounds_pow);

    std::string out(section.size(), '\0');
    AES256CBCDecrypt decryptor(key.data(), parse_result.iv.data(), false);
    decryptor.Decrypt(section.data(), section.size(),
                      reinterpret_cast<unsigned char*>(out.data()));
    out.resize(parse_result.unpacked_size);
    if (MaskedCRC(reinterpret_cast<unsigned char*>(out.data()), out.size()) !=
        parse_result.expect_crc) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Wrong password given, or damaged file.");
    }
    return ParseColdcardBackupData(out);
  }
  throw NunchukException(NunchukException::INVALID_PARAMETER, "Damaged file");
}
}  // namespace nunchuk
