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

#ifndef NUNCHUK_BCR2_H
#define NUNCHUK_BCR2_H

#include <cbor-lite.hpp>

namespace nunchuk {
namespace bcr2 {
using namespace CborLite;

struct CryptoInfo {
  uint32_t type;
  uint32_t network;
};

template <typename InputIterator>
size_t decodeCryptoInfo(InputIterator& pos, InputIterator end, CryptoInfo& m,
                        Flags flags = Flag::none) {
  size_t nMap = 0;
  auto len = decodeMapSize(pos, end, nMap, flags);
  for (size_t i = 0; i < nMap; i++) {
    unsigned long key;
    len += decodeUnsigned(pos, end, key, flags);
    if (key == 1) {
      len += decodeUnsigned(pos, end, m.type, flags);
    } else if (key == 2) {
      len += decodeUnsigned(pos, end, m.network, flags);
    }
  }
  return len;
}

struct CryptoKeyPath {
  uint32_t sourceFingerprint;
  uint8_t depth;
  uint32_t childNumber;
  std::vector<uint32_t> keypath;
};

template <typename InputIterator>
size_t decodeCryptoKeyPath(InputIterator& pos, InputIterator end,
                           CryptoKeyPath& m, Flags flags = Flag::none) {
  size_t nMap = 0;
  auto len = decodeMapSize(pos, end, nMap, flags);
  for (size_t i = 0; i < nMap; i++) {
    unsigned long key;
    len += decodeUnsigned(pos, end, key, flags);
    if (key == 1) {
      size_t nComponents = 0;
      len += decodeArraySize(pos, end, nComponents, flags);
      m.depth = nComponents / 2;
      for (size_t j = 0; j < m.depth; j++) {
        unsigned long childIndex;
        bool isHardened = false;
        try {
          len += decodeUnsigned(pos, end, childIndex, flags);
          len += decodeBool(pos, end, isHardened, flags);
          m.childNumber = childIndex;
          if (isHardened) m.childNumber |= 0x80000000;
          m.keypath.push_back(m.childNumber);
        } catch (...) {
          Tag tag;
          Tag t;
          len += decodeTagAndValue(pos, end, tag, t, flags);
        }
      }
    } else if (key == 2) {
      len += decodeUnsigned(pos, end, m.sourceFingerprint, flags);
    } else if (key == 3) {
      len += decodeUnsigned(pos, end, m.depth, flags);
    }
  }
  return len;
}

struct CryptoHDKey {
  bool isPrivate = false;
  std::vector<unsigned char> keydata;
  std::vector<unsigned char> chaincode;
  CryptoInfo useInfo;
  CryptoKeyPath origin;
  CryptoKeyPath children;
  uint32_t parentFingerprint;
  std::string scriptType;
};

template <typename InputIterator>
size_t decodeCryptoHDKey(InputIterator& pos, InputIterator end, CryptoHDKey& m,
                         Flags flags = Flag::none) {
  Tag tag;
  Tag t;

  size_t nMap = 0;
  auto len = decodeMapSize(pos, end, nMap, flags);
  for (size_t i = 0; i < nMap; i++) {
    unsigned long key;
    len += decodeUnsigned(pos, end, key, flags);
    if (key == 2) {
      len += decodeBool(pos, end, m.isPrivate, flags);
    } else if (key == 3) {
      len += decodeBytes(pos, end, m.keydata);
    } else if (key == 4) {
      len += decodeBytes(pos, end, m.chaincode);
    } else if (key == 5) {
      len += decodeTagAndValue(pos, end, tag, t, flags);
      len += decodeCryptoInfo(pos, end, m.useInfo, flags);
    } else if (key == 6) {
      len += decodeTagAndValue(pos, end, tag, t, flags);
      len += decodeCryptoKeyPath(pos, end, m.origin, flags);
    } else if (key == 7) {
      len += decodeTagAndValue(pos, end, tag, t, flags);
      len += decodeCryptoKeyPath(pos, end, m.children, flags);
    } else if (key == 8) {
      len += decodeUnsigned(pos, end, m.parentFingerprint, flags);
    }
  }
  return len;
}

struct CryptoAccount {
  uint32_t masterFingerprint;
  std::vector<CryptoHDKey> outputDescriptors;
};

template <typename InputIterator>
size_t decodeCryptoAccount(InputIterator& pos, InputIterator end,
                           CryptoAccount& m, Flags flags = Flag::none) {
  Tag tag;
  Tag t;

  size_t nMap = 0;
  auto len = decodeMapSize(pos, end, nMap, flags);
  for (size_t i = 0; i < nMap; i++) {
    unsigned long key;
    len += decodeUnsigned(pos, end, key, flags);
    if (key == 1) {
      len += decodeUnsigned(pos, end, m.masterFingerprint, flags);
    } else if (key == 2) {
      size_t nOutputDescriptor = 0;
      len += decodeArraySize(pos, end, nOutputDescriptor, flags);
      for (size_t j = 0; j < nOutputDescriptor; j++) {
        CryptoHDKey descriptor;
        len += decodeTagAndValue(pos, end, tag, t, flags);
        if (t == 403) {
          descriptor.scriptType = "PKH";
          len += decodeTagAndValue(pos, end, tag, t, flags);
        } else if (t == 400) {
          len += decodeTagAndValue(pos, end, tag, t, flags);
          if (t == 404) {
            descriptor.scriptType = "SH-WPKH";
            len += decodeTagAndValue(pos, end, tag, t, flags);
          } else if (t == 303) {
            descriptor.scriptType = "SH";
          } else if (t == 401) {
            descriptor.scriptType = "SH-WSH";
            len += decodeTagAndValue(pos, end, tag, t, flags);
          }
        } else if (t == 404) {
          descriptor.scriptType = "WPKH";
          len += decodeTagAndValue(pos, end, tag, t, flags);
        } else if (t == 401) {
          descriptor.scriptType = "WSH";
          len += decodeTagAndValue(pos, end, tag, t, flags);
        }
        len += decodeCryptoHDKey(pos, end, descriptor, flags);
        m.outputDescriptors.push_back(descriptor);
      }
    }
  }
  return len;
}

struct CryptoPSBT {
  std::vector<unsigned char> data;
};

template <typename InputIterator>
size_t decodeCryptoPSBT(InputIterator& pos, InputIterator end, CryptoPSBT& m,
                        Flags flags = Flag::none) {
  return decodeBytes(pos, end, m.data);
}

template <typename Buffer>
size_t encodeCryptoPSBT(Buffer& buffer, const CryptoPSBT& m) {
  return encodeBytes(buffer, m.data);
}

}  // namespace bcr2
}  // namespace nunchuk

#endif  // NUNCHUK_BCR2_H