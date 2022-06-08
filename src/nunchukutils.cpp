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
#include <coreutils.h>
#include <softwaresigner.h>
#include <utils/addressutils.hpp>
#include <utils/bip32.hpp>
#include <storage/storage.h>

#include <base58.h>
#include <amount.h>
#include <stdlib.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <boost/format.hpp>

namespace nunchuk {

static const std::map<std::string, std::vector<unsigned char>>
    VERSION_PREFIXES = {
        {"xpub", {0x04, 0x88, 0xb2, 0x1e}}, {"ypub", {0x04, 0x9d, 0x7c, 0xb2}},
        {"Ypub", {0x02, 0x95, 0xb4, 0x3f}}, {"zpub", {0x04, 0xb2, 0x47, 0x46}},
        {"Zpub", {0x02, 0xaa, 0x7e, 0xd3}}, {"tpub", {0x04, 0x35, 0x87, 0xcf}},
        {"upub", {0x04, 0x4a, 0x52, 0x62}}, {"Upub", {0x02, 0x42, 0x89, 0xef}},
        {"vpub", {0x04, 0x5f, 0x1c, 0xf6}}, {"Vpub", {0x02, 0x57, 0x54, 0x83}}};

std::string Utils::SanitizeBIP32Input(const std::string& slip132_input,
                                      const std::string& target_format) {
  std::vector<unsigned char> result;
  if (!DecodeBase58Check(std::string(slip132_input), result, 78)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Can not decode slip132 input");
  }
  if (VERSION_PREFIXES.find(target_format) == VERSION_PREFIXES.end()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid target format");
  }
  auto prefix = VERSION_PREFIXES.at(target_format);
  std::copy(prefix.begin(), prefix.end(), result.begin());
  return EncodeBase58Check(result);
}

std::string Utils::GenerateRandomMessage(int message_length) {
  auto randchar = []() -> char {
    const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    const size_t max_index = (sizeof(charset) - 1);
    return charset[rand() % max_index];
  };
  std::string str(message_length, 0);
  std::generate_n(str.begin(), message_length, randchar);
  return str;
}

bool Utils::IsValidXPub(const std::string& value) {
  auto xpub = DecodeExtPubKey(value);
  return xpub.pubkey.IsFullyValid();
}

bool Utils::IsValidPublicKey(const std::string& value) {
  CPubKey pubkey(ParseHex(value));
  return pubkey.IsFullyValid();
}

bool Utils::IsValidDerivationPath(const std::string& value) {
  std::vector<uint32_t> keypath;
  std::string formalized = value;
  std::replace(formalized.begin(), formalized.end(), 'h', '\'');
  return ParseHDKeypath(formalized, keypath);
}

bool Utils::IsValidFingerPrint(const std::string& value) {
  return IsHex(value) && ParseHex(value).size() == 4;
}

Amount Utils::AmountFromValue(const std::string& value,
                              const bool allow_negative) {
  Amount amount;
  if (!ParseFixedPoint(value, 8, &amount))
    throw NunchukException(NunchukException::INVALID_AMOUNT, "Invalid amount");
  if (!allow_negative) {
    if (!MoneyRange(amount))
      throw NunchukException(NunchukException::AMOUNT_OUT_OF_RANGE,
                             "Amount out of range");
  } else {
    if (abs(amount) > MAX_MONEY)
      throw NunchukException(NunchukException::AMOUNT_OUT_OF_RANGE,
                             "Amount out of range");
  }
  return amount;
}

std::string Utils::ValueFromAmount(const Amount& amount) {
  bool sign = amount < 0;
  int64_t n_abs = (sign ? -amount : amount);
  int64_t quotient = n_abs / COIN;
  int64_t remainder = n_abs % COIN;
  return boost::str(boost::format{"%s%d.%08d"} % (sign ? "-" : "") % quotient %
                    remainder);
}

bool Utils::MoneyRange(const Amount& nValue) {
  return (nValue >= 0 && nValue <= MAX_MONEY);
}

std::string Utils::AddressToScriptPubKey(const std::string& address) {
  return ::AddressToScriptPubKey(address);
}

void Utils::SetChain(Chain chain) { CoreUtils::getInstance().SetChain(chain); }

std::string Utils::GenerateMnemonic() {
  return SoftwareSigner::GenerateMnemonic();
}

bool Utils::CheckMnemonic(const std::string& mnemonic) {
  return SoftwareSigner::CheckMnemonic(mnemonic);
}

std::vector<std::string> Utils::GetBIP39WordList() {
  return SoftwareSigner::GetBIP39WordList();
}

void Utils::SetPassPhrase(const std::string& storage_path,
                          const std::string& account,
                          const std::string& old_passphrase,
                          const std::string& new_passphrase) {
  auto storage = NunchukStorage::get(account);
  storage->Init(storage_path, old_passphrase);
  storage->SetPassphrase(new_passphrase);
}

std::string Utils::GetPrimaryKeyAddress(const std::string& mnemonic,
                                        const std::string& passphrase) {
  SoftwareSigner signer{mnemonic, passphrase};
  return signer.GetAddressAtPath(LOGIN_SIGNING_PATH);
}

std::string Utils::SignLoginMessage(const std::string& mnemonic,
                                    const std::string& passphrase,
                                    const std::string& message) {
  SoftwareSigner signer{mnemonic, passphrase};
  return signer.SignMessage(message, LOGIN_SIGNING_PATH);
}

}  // namespace nunchuk
