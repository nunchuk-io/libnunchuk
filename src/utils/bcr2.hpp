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

#include <vector>

#include <nunchuk.h>
#include <cbor-lite.hpp>

#include <util/bip32.h>
#include <uint256.h>
#include <pubkey.h>
#include <key_io.h>

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

template <typename Buffer>
size_t encodeCryptoInfo(Buffer& buffer, const CryptoInfo& m) {
  auto len = encodeMapSize(buffer, (size_t)2);
  len += encodeUnsigned(buffer, (unsigned long)1);
  len += encodeUnsigned(buffer, m.type);
  len += encodeUnsigned(buffer, (unsigned long)2);
  len += encodeUnsigned(buffer, m.network);
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

template <typename Buffer>
size_t encodeCryptoKeyPath(Buffer& buffer, const CryptoKeyPath& m) {
  auto len = encodeMapSize(buffer, (size_t)3);
  len += encodeUnsigned(buffer, (unsigned long)1);
  len += encodeArraySize(buffer, (size_t)(m.keypath.size() * 2));
  for (auto&& childIndex : m.keypath) {
    bool isHardened = (childIndex >> 31);
    len += encodeUnsigned(buffer, (childIndex << 1) >> 1);
    len += encodeBool(buffer, isHardened);
  }
  len += encodeUnsigned(buffer, (unsigned long)2);
  len += encodeUnsigned(buffer, m.sourceFingerprint);
  len += encodeUnsigned(buffer, (unsigned long)3);
  len += encodeUnsigned(buffer, m.depth);
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
  std::string name;
  std::string scriptType;

  void u8from32(uint8_t b[4], uint32_t u32) const {
    b[3] = (uint8_t)u32;
    b[2] = (uint8_t)(u32 >>= 8);
    b[1] = (uint8_t)(u32 >>= 8);
    b[0] = (uint8_t)(u32 >>= 8);
  }

  std::string get_xfp() const {
    std::ostringstream iss;
    iss << std::setfill('0') << std::setw(8) << std::hex
        << origin.sourceFingerprint;
    return iss.str();
  }

  std::string get_xpub() const {
    CExtPubKey xpub{};
    xpub.chaincode = ChainCode(chaincode);
    xpub.pubkey = CPubKey(keydata);
    xpub.nChild = origin.childNumber;
    xpub.nDepth = origin.depth;
    u8from32(xpub.vchFingerprint, parentFingerprint);
    return EncodeExtPubKey(xpub);
  }

  std::string get_path() const {
    std::stringstream path;
    path << "m" << FormatHDKeypath(origin.keypath);
    return path.str();
  }

  static uint32_t u8to32(uint8_t b[4]) {
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 |
           (uint32_t)b[3];
  }

  static CryptoHDKey from_signer(const SingleSigner& signer) {
    auto xpub = DecodeExtPubKey(signer.get_xpub());

    std::vector<uint32_t> keypath;
    std::string formalized = signer.get_derivation_path();
    std::replace(formalized.begin(), formalized.end(), 'h', '\'');
    if (!ParseHDKeypath(formalized, keypath)) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid hd keypath");
    }

    uint32_t parentFp = u8to32(xpub.vchFingerprint);
    std::vector<uint8_t> keydata{xpub.pubkey.begin(), xpub.pubkey.end()};
    std::vector<uint8_t> chaincode{xpub.chaincode.begin(),
                                   xpub.chaincode.end()};
    uint32_t sourceFp =
        u8to32(ParseHex(signer.get_master_fingerprint()).data());
    std::string name = signer.get_name();

    CryptoInfo ci{
        0, static_cast<uint32_t>(Utils::GetChain() == Chain::MAIN ? 0 : 1)};
    CryptoKeyPath ckp{sourceFp, xpub.nDepth, xpub.nChild, keypath};
    return {false, keydata, chaincode, ci, ckp, {}, parentFp, name};
  }
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
    } else if (key == 9) {
      len += decodeText(pos, end, m.name, flags);
    }
  }
  return len;
}

template <typename Buffer>
size_t encodeCryptoHDKey(Buffer& buffer, const CryptoHDKey& m) {
  auto len = encodeMapSize(buffer, (size_t)7);
  len += encodeUnsigned(buffer, (unsigned long)2);
  len += encodeBool(buffer, m.isPrivate);
  len += encodeUnsigned(buffer, (unsigned long)3);
  len += encodeBytes(buffer, m.keydata);
  len += encodeUnsigned(buffer, (unsigned long)4);
  len += encodeBytes(buffer, m.chaincode);
  len += encodeUnsigned(buffer, (unsigned long)5);
  len += encodeTagAndValue(buffer, Major::semantic, (Tag)305);
  len += encodeCryptoInfo(buffer, m.useInfo);
  len += encodeUnsigned(buffer, (unsigned long)6);
  len += encodeTagAndValue(buffer, Major::semantic, (Tag)304);
  len += encodeCryptoKeyPath(buffer, m.origin);
  len += encodeUnsigned(buffer, (unsigned long)8);
  len += encodeUnsigned(buffer, m.parentFingerprint);
  len += encodeUnsigned(buffer, (unsigned long)9);
  len += encodeText(buffer, m.name);
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
        } else if (t == 409) {
          descriptor.scriptType = "P2TR";
          len += decodeTagAndValue(pos, end, tag, t, flags);
        }
        len += decodeCryptoHDKey(pos, end, descriptor, flags);
        m.outputDescriptors.push_back(descriptor);
      }
    }
  }
  return len;
}

struct CryptoOutput {
  AddressType addressType;
  WalletType walletType;
  bool isSorted;
  uint32_t threshold = 1;
  std::vector<CryptoHDKey> outputDescriptors;

  static CryptoOutput from_wallet(const Wallet& wallet) {
    std::vector<CryptoHDKey> outputDescriptors;
    for (auto&& signer : wallet.get_signers()) {
      outputDescriptors.push_back(CryptoHDKey::from_signer(signer));
    }
    return {wallet.get_address_type(), wallet.get_wallet_type(), true,
            (uint32_t)wallet.get_m(), outputDescriptors};
  }
};

template <typename InputIterator>
size_t decodeCryptoOutput(InputIterator& pos, InputIterator end,
                          CryptoOutput& m, Flags flags = Flag::none) {
  Tag tag;
  Tag t;

  auto len = decodeTagAndValue(pos, end, tag, t, flags);
  if (t == 400) {  // sh
    len += decodeTagAndValue(pos, end, tag, t, flags);
    if (t == 404) {  // wpkh
      m.addressType = AddressType::NESTED_SEGWIT;
      m.walletType = WalletType::SINGLE_SIG;
    } else if (t == 401) {  // wsh
      len += decodeTagAndValue(pos, end, tag, t, flags);
      if (t == 406 || t == 407) {
        m.addressType = AddressType::NESTED_SEGWIT;
        m.walletType = WalletType::MULTI_SIG;
      } else {
        throw NunchukException(NunchukException::INVALID_FORMAT,
                               "Not supported");
      }
    } else if (t == 406 || t == 407) {  // multi or sortedmulti
      m.addressType = AddressType::LEGACY;
      m.walletType = WalletType::MULTI_SIG;
    } else {
      throw NunchukException(NunchukException::INVALID_FORMAT, "Not supported");
    }
  } else if (t == 403) {  // pkh
    m.addressType = AddressType::LEGACY;
    m.walletType = WalletType::SINGLE_SIG;
  } else if (t == 404) {  // wpkh
    m.addressType = AddressType::NATIVE_SEGWIT;
    m.walletType = WalletType::SINGLE_SIG;
  } else if (t == 401) {  // wsh
    len += decodeTagAndValue(pos, end, tag, t, flags);
    if (t == 406 || t == 407) {
      m.addressType = AddressType::NATIVE_SEGWIT;
      m.walletType = WalletType::MULTI_SIG;
    } else {
      throw NunchukException(NunchukException::INVALID_FORMAT, "Not supported");
    }
  }

  if (t == 406 || t == 407) {
    m.isSorted = (t == 407);

    if (t == 406) {
      throw NunchukException(
          NunchukException::INVALID_FORMAT,
          "Script ‘multi’ is not supported. Please use ‘sortedmulti’.");
    }
    size_t nMap = 0;
    len += decodeMapSize(pos, end, nMap, flags);
    for (size_t i = 0; i < nMap; i++) {
      unsigned long key;
      len += decodeUnsigned(pos, end, key, flags);
      if (key == 1) {
        len += decodeUnsigned(pos, end, m.threshold, flags);
      } else if (key == 2) {
        size_t nOutputDescriptor = 0;
        len += decodeArraySize(pos, end, nOutputDescriptor, flags);
        for (size_t j = 0; j < nOutputDescriptor; j++) {
          len += decodeTagAndValue(pos, end, tag, t, flags);
          if (t != 303) {
            throw NunchukException(NunchukException::INVALID_FORMAT,
                                   "Not supported");
          }
          CryptoHDKey descriptor;
          len += decodeCryptoHDKey(pos, end, descriptor, flags);
          m.outputDescriptors.push_back(descriptor);
        }
      }
    }
  } else {
    len += decodeTagAndValue(pos, end, tag, t, flags);
    if (t != 303) {
      throw NunchukException(NunchukException::INVALID_FORMAT, "Not supported");
    }
    CryptoHDKey descriptor;
    len += decodeCryptoHDKey(pos, end, descriptor, flags);
    m.outputDescriptors.push_back(descriptor);
  }
  return len;
}

template <typename Buffer>
size_t encodeCryptoOutput(Buffer& buffer, const CryptoOutput& m) {
  size_t len = 0;
  if (m.walletType == WalletType::SINGLE_SIG) {
    if (m.addressType == AddressType::LEGACY) {
      len += encodeTagAndValue(buffer, Major::semantic, (Tag)403);  // pkh
    } else if (m.addressType == AddressType::NESTED_SEGWIT) {
      len += encodeTagAndValue(buffer, Major::semantic, (Tag)400);  // sh
      len += encodeTagAndValue(buffer, Major::semantic, (Tag)404);  // wpkh
    } else if (m.addressType == AddressType::NATIVE_SEGWIT) {
      len += encodeTagAndValue(buffer, Major::semantic, (Tag)404);  // wpkh
    }
    len += encodeTagAndValue(buffer, Major::semantic, (Tag)303);
    len += encodeCryptoHDKey(buffer, m.outputDescriptors[0]);
  } else if (m.walletType == WalletType::MULTI_SIG) {
    if (m.addressType == AddressType::LEGACY) {
      len += encodeTagAndValue(buffer, Major::semantic, (Tag)400);  // sh
    } else if (m.addressType == AddressType::NESTED_SEGWIT) {
      len += encodeTagAndValue(buffer, Major::semantic, (Tag)400);  // sh
      len += encodeTagAndValue(buffer, Major::semantic, (Tag)401);  // wsh
    } else if (m.addressType == AddressType::NATIVE_SEGWIT) {
      len += encodeTagAndValue(buffer, Major::semantic, (Tag)401);  // wsh
    }
    len += encodeTagAndValue(buffer, Major::semantic, (Tag)407);  // sortedmulti
    len += encodeMapSize(buffer, (size_t)2);
    len += encodeUnsigned(buffer, (unsigned long)1);
    len += encodeUnsigned(buffer, m.threshold);
    len += encodeUnsigned(buffer, (unsigned long)2);
    len += encodeArraySize(buffer, (size_t)m.outputDescriptors.size());
    for (auto&& output : m.outputDescriptors) {
      len += encodeTagAndValue(buffer, Major::semantic, (Tag)303);
      len += encodeCryptoHDKey(buffer, output);
    }
  } else {
    throw NunchukException(NunchukException::INVALID_FORMAT,
                           "Escrow wallet is not supported.");
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