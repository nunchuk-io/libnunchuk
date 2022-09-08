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

#ifndef NUNCHUK_NDEF_H
#define NUNCHUK_NDEF_H

#include "key_io.h"
#include "nunchuk.h"
#include "util/strencodings.h"
#include "utils/stringutils.hpp"
#include "utils/multisigconfig.hpp"

namespace nunchuk {
namespace ndef {
static inline std::vector<unsigned char> str_to_bytes(
    const std::string_view str) {
  return {str.begin(), str.end()};
}

template <typename T>
static inline bool is_prefix(T &&arr, T &&pref) {
  return std::size(arr) >= std::size(pref) &&
         std::equal(std::begin(pref), std::end(pref), std::begin(arr));
}

enum class NDEFMessageType {
  UNKNOWN,
  TAPSIGNER,
  SATSCARD,
  JSON,
  PSBT,
  TRANSACTION,
  ADDRESS,
  MULTIPLE_ADDRESSES,
  TEXT,
  WALLET,
};

struct NDEFRecord {
  unsigned char typeNameFormat;
  std::vector<unsigned char> type;
  std::vector<unsigned char> id;
  std::vector<unsigned char> payload;

  NDEFRecord() = default;

  NDEFRecord(unsigned char typeNameFormat, std::vector<unsigned char> type,
             std::vector<unsigned char> id, std::vector<unsigned char> payload)
      : typeNameFormat(typeNameFormat),
        type(std::move(type)),
        id(std::move(id)),
        payload(std::move(payload)) {}

  enum TypeNameFormat : unsigned char {
    TNF_EMPTY,
    TNF_WELLKNOWN,  // NFC Forum well-known type.
    TNF_MIME,       // Media-type as defined in RFC 2046.
    TNF_URI,        // Absolute URI as defined in RFC 3986.
    TNF_EXTERNAL,   // NFC Forum external type.
    TNF_UNKNOWN,
    TNF_UNCHANGED,  // Used for payload chunks.
  };

  inline static const std::vector<unsigned char> TYPE_TEXT = str_to_bytes("T");
  inline static const std::vector<unsigned char> TYPE_URI = str_to_bytes("U");
  inline static const std::vector<unsigned char> TYPE_PSBT =
      str_to_bytes("bitcoin.org:psbt");
  inline static const std::vector<unsigned char> TYPE_TXN =
      str_to_bytes("bitcoin.org:txn");
  inline static const std::vector<unsigned char> TYPE_SHA256 =
      str_to_bytes("bitcoin.org:sha256");
  inline static const std::vector<unsigned char> TYPE_TXID =
      str_to_bytes("bitcoin.org:txid");
  inline static const std::vector<unsigned char> TYPE_JSON =
      str_to_bytes("application/json");

  inline static const std::vector<unsigned char> PAYLOAD_PSBT_PREFIX =
      str_to_bytes("\002enPartly signed PSBT");
  inline static const std::vector<unsigned char>
      PAYLOAD_DEPOSIT_ADDRESS_PREFIX = str_to_bytes("\002enDeposit Address");
  inline static const std::vector<unsigned char> PAYLOAD_TRANSACTION_PREFIX =
      str_to_bytes("\002enSigned Transaction");
};

inline std::tuple<unsigned char /*encoding*/, std::string /*language code*/,
                  std::string /*text*/>
ParseNDEFTextPayload(const std::vector<unsigned char> &payload) {
  if (payload.size() < 1) {
    return {};
  }

  const uint8_t lg_code_length = payload[0] & 0x7f;
  if (payload.size() < 1 + lg_code_length) {
    return {};
  }

  return {
      payload[0] & 0x80,
      std::string(std::begin(payload) + 1,
                  std::begin(payload) + 1 + lg_code_length),
      std::string(std::begin(payload) + 1 + lg_code_length, std::end(payload)),
  };
}

inline std::string NDEFRecordToStr(const NDEFRecord &record) {
  auto [_encoding, _language_code, text] = ParseNDEFTextPayload(record.payload);
  return text;
}

inline std::string NDEFRecordToJSON(const NDEFRecord &record) {
  if (record.typeNameFormat == NDEFRecord::TNF_MIME &&
      record.type == NDEFRecord::TYPE_JSON) {
    return std::string(std::begin(record.payload), std::end(record.payload));
  }
  return {};
}

inline std::string NDEFRecordsToPSBT(const std::vector<NDEFRecord> &records) {
  std::string raw_psbt, sha256;
  for (const auto &record : records) {
    if (record.typeNameFormat == NDEFRecord::TNF_WELLKNOWN &&
        record.type == NDEFRecord::TYPE_TEXT) {
      if (!is_prefix(record.payload, NDEFRecord::PAYLOAD_PSBT_PREFIX)) {
        return {};
      }

    } else if (record.typeNameFormat == NDEFRecord::TNF_EXTERNAL) {
      if (record.type == NDEFRecord::TYPE_SHA256) {
        sha256 =
            std::string(std::begin(record.payload), std::end(record.payload));
      } else if (record.type == NDEFRecord::TYPE_PSBT) {
        raw_psbt =
            std::string(std::begin(record.payload), std::end(record.payload));
      }
    }
  }
  // TODO(giahuy): verify SHA256 psbt
  return EncodeBase64(raw_psbt);
}

inline std::vector<NDEFRecord> NDEFRecordsFromPSBT(const std::string &psbt) {
  std::string raw_psbt = DecodeBase64(psbt);
  // TODO(giahuy): write SHA256 of psbt?
  return {
      NDEFRecord{
          NDEFRecord::TNF_EXTERNAL,
          NDEFRecord::TYPE_PSBT,
          {},
          {std::begin(raw_psbt), std::end(raw_psbt)},
      },
  };
}

inline std::vector<NDEFRecord> NDEFRecordsFromStr(const std::string &str) {
  std::string payload = "\002en" + str;
  return {
      NDEFRecord{
          NDEFRecord::TNF_WELLKNOWN,
          NDEFRecord::TYPE_TEXT,
          {},
          {std::begin(payload), std::end(payload)},
      },
  };
}

inline std::string NDEFRecordsToRawTransaction(
    const std::vector<NDEFRecord> &records) {
  std::string raw_tx, sha256, txid;
  for (const auto &record : records) {
    if (record.typeNameFormat == NDEFRecord::TNF_WELLKNOWN &&
        record.type == NDEFRecord::TYPE_TEXT) {
      if (!is_prefix(record.payload, NDEFRecord::PAYLOAD_TRANSACTION_PREFIX)) {
        return {};
      }

    } else if (record.typeNameFormat == NDEFRecord::TNF_EXTERNAL) {
      if (record.type == NDEFRecord::TYPE_SHA256) {
        sha256 =
            std::string(std::begin(record.payload), std::end(record.payload));
      } else if (record.type == NDEFRecord::TYPE_TXN) {
        raw_tx =
            std::string(std::begin(record.payload), std::end(record.payload));
      } else if (record.type == NDEFRecord::TYPE_TXID) {
        txid =
            std::string(std::begin(record.payload), std::end(record.payload));
      }
    }
  }
  // TODO(giahuy): verify tx info
  return HexStr(raw_tx);
}

inline NDEFMessageType DetectNDEFMessageType(
    const std::vector<NDEFRecord> &records) {
  if (records.empty()) {
    return NDEFMessageType::UNKNOWN;
  }

  auto &&record = records.front();

  if (record.typeNameFormat == NDEFRecord::TNF_WELLKNOWN) {
    // URI record, try to detect TAPSIGNER/SATSCARD
    if (record.type == NDEFRecord::TYPE_URI) {
      std::string_view uri(
          reinterpret_cast<const char *>(record.payload.data()),
          record.payload.size());
      if (uri.find("tapsigner.com") != std::string::npos) {
        return NDEFMessageType::TAPSIGNER;
      }
      if (uri.find("getsatscard.com") != std::string::npos) {
        return NDEFMessageType::SATSCARD;
      }
      return NDEFMessageType::UNKNOWN;
    }

    // Only text
    if (record.type == NDEFRecord::TYPE_TEXT) {
      if (records.size() == 1) {
        auto [_encoding, _language_code, text] =
            ParseNDEFTextPayload(record.payload);

        // Check if is multisig wallet
        {
          std::string name;
          AddressType address_type;
          WalletType wallet_type;
          int m;
          int n;
          std::vector<SingleSigner> signers;
          for (Chain chain : {Chain::MAIN, Chain::TESTNET}) {
            try {
              if (ParseConfig(chain, text, name, address_type, wallet_type, m,
                              n, signers)) {
                return NDEFMessageType::WALLET;
              }
            } catch (...) {
            }
          }
        }

        // Check if is addresses
        // if (auto sp = split(text, '\n'); sp.size() > 1) {
        //  if (std::all_of(std::begin(sp), std::end(sp),
        //                  [](const std::string &address) {
        //                    return IsValidDestinationString(address);
        //                  })) {
        //    return NDEFMessageType::MULTIPLE_ADDRESSES;
        //  }
        //}

        // Check if is address
        // if (IsValidDestinationString(text)) {
        //  return NDEFMessageType::ADDRESS;
        //}

        return NDEFMessageType::TEXT;
      }
    }
  }

  // Mine type
  if (record.typeNameFormat == NDEFRecord::TNF_MIME &&
      record.type == NDEFRecord::TYPE_JSON) {
    return NDEFMessageType::JSON;
  }

  // Multiple records
  for (auto &&record : records) {
    // Text Label
    if (record.typeNameFormat == NDEFRecord::TNF_WELLKNOWN &&
        record.type == NDEFRecord::TYPE_TEXT) {
      if (is_prefix(record.payload, NDEFRecord::PAYLOAD_PSBT_PREFIX)) {
        return NDEFMessageType::PSBT;
      }

      if (is_prefix(record.payload, NDEFRecord::PAYLOAD_TRANSACTION_PREFIX)) {
        return NDEFMessageType::TRANSACTION;
      }
    }
    // NFC Forum external type
    else if (record.typeNameFormat == NDEFRecord::TNF_EXTERNAL) {
      if (record.type == NDEFRecord::TYPE_PSBT) {
        return NDEFMessageType::PSBT;
      }
      if (record.type == NDEFRecord::TYPE_TXN) {
        return NDEFMessageType::TRANSACTION;
      }
    }
  }

  if (record.type == NDEFRecord::TYPE_TEXT) {
    return NDEFMessageType::TEXT;
  }
  return NDEFMessageType::UNKNOWN;
}

}  // namespace ndef
}  // namespace nunchuk

#endif
