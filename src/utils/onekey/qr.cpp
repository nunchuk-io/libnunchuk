/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (c) 2026 Nunchuk.
 * Distributed under the GNU General Public License, version 3.
 */

#include "qr.hpp"

#include <ur-decoder.hpp>
#include <utils/bcr2.hpp>

#include "descriptor.h"

namespace nunchuk {
namespace onekey {
namespace {

using namespace bcr2;

[[noreturn]] void Invalid(const std::string& reason) {
  throw NunchukException(NunchukException::INVALID_FORMAT,
                         "Invalid OneKey QR data: " + reason);
}

template <typename InputIterator>
void decodeCryptoMultiAccounts(InputIterator& pos, InputIterator end,
                               CryptoAccount& account) {
  size_t nMap = 0;
  decodeMapSize(pos, end, nMap);
  bool has_fingerprint = false;
  bool has_keys = false;
  for (size_t i = 0; i < nMap; i++) {
    unsigned long field;
    decodeUnsigned(pos, end, field);
    if (field == 1) {
      decodeUnsigned(pos, end, account.masterFingerprint);
      has_fingerprint = true;
    } else if (field == 2) {
      size_t nKeys = 0;
      decodeArraySize(pos, end, nKeys);
      for (size_t j = 0; j < nKeys; j++) {
        Tag tag;
        Tag value;
        decodeTagAndValue(pos, end, tag, value);
        if (tag != Major::semantic || value != 303) {
          Invalid("unexpected HD key tag");
        }
        CryptoHDKey key{};
        decodeCryptoHDKey(pos, end, key);
        account.outputDescriptors.push_back(key);
      }
      has_keys = true;
    } else {
      // Device name, ID, firmware version, and other optional metadata.
      skipCborValue(pos, end);
    }
  }
  if (!has_fingerprint || !has_keys) Invalid("missing account fields");
}

}  // namespace

std::vector<SingleSigner> ParseSigners(
    const std::vector<std::string>& qr_data) {
  using namespace bcr2;

  auto decoder = ur::URDecoder();
  for (auto&& part : qr_data) decoder.receive_part(part);
  if (!decoder.is_complete() || !decoder.is_success()) {
    Invalid("incomplete or invalid UR");
  }
  auto cbor = decoder.result_ur().cbor();
  auto type = decoder.result_ur().type();
  auto pos = cbor.begin();
  auto end = cbor.end();
  CryptoAccount account{};
  try {
    if (type == "crypto-hdkey") {
      CryptoHDKey key{};
      decodeCryptoHDKey(pos, end, key);
      account.outputDescriptors.push_back(key);
    } else if (type == "crypto-multi-accounts") {
      decodeCryptoMultiAccounts(pos, end, account);
      if (account.masterFingerprint == 0) Invalid("missing master fingerprint");
    } else {
      Invalid("unsupported UR type");
    }
    if (pos != end) Invalid("trailing CBOR data");
  } catch (const CborLite::Exception& e) {
    Invalid(e.what());
  }

  std::vector<SingleSigner> signers;
  for (auto&& key : account.outputDescriptors) {
    if (key.useInfo.type != 0) continue;
    if (key.isPrivate || key.keydata.size() != 33 ||
        key.chaincode.size() != 32 || !CPubKey(key.keydata).IsFullyValid()) {
      Invalid("invalid extended public key");
    }
    auto& origin = key.origin;
    if (origin.keypath.empty() || origin.depth != origin.keypath.size() ||
        origin.childNumber != origin.keypath.back()) {
      Invalid("incomplete origin path");
    }
    if (account.masterFingerprint != 0) {
      if (origin.sourceFingerprint != 0 &&
          origin.sourceFingerprint != account.masterFingerprint) {
        Invalid("master fingerprint mismatch");
      }
      origin.sourceFingerprint = account.masterFingerprint;
    }
    if (origin.sourceFingerprint == 0) Invalid("missing master fingerprint");
    if (key.parentFingerprint == 0 && origin.depth == 1) {
      key.parentFingerprint = origin.sourceFingerprint;
    }
    if (key.parentFingerprint == 0 ||
        (origin.depth == 1 &&
         key.parentFingerprint != origin.sourceFingerprint)) {
      Invalid("invalid parent fingerprint");
    }
    if (key.useInfo.network > 1) Invalid("unsupported Bitcoin network");

    auto path = key.get_path();
    auto name = key.name.empty()
                    ? GetSignerNameFromDerivationPath(path, "OneKey-")
                    : key.name;
    signers.push_back(SingleSigner(name, key.get_xpub(), {}, path, {0, 1},
                                   key.get_xfp(), 0, {}, false,
                                   SignerType::AIRGAP));
  }
  if (signers.empty()) {
    throw NunchukException(NunchukException::INVALID_FORMAT,
                           "No Bitcoin keys found in OneKey QR data");
  }
  return signers;
}

}  // namespace onekey
}  // namespace nunchuk
