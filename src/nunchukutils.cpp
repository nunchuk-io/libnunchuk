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
#include <descriptor.h>
#include <softwaresigner.h>
#include <signingprovider.h>
#include <boost/algorithm/string/trim.hpp>
#include <map>
#include <utils/addressutils.hpp>
#include <utils/bip32.hpp>
#include <utils/bsms.hpp>
#include <utils/multisigconfig.hpp>
#include <utils/unchained.hpp>
#include <utils/txutils.hpp>
#include <storage/storage.h>
#include <hwiservice.h>

#include <base58.h>
#include <consensus/amount.h>
#include <stdlib.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <boost/format.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/signals2.hpp>
#include <hash.h>
#include <policy/policy.h>

#include <ur.h>
#include <ur-encoder.hpp>
#include <ur-decoder.hpp>
#include <cbor-lite.hpp>
#include <utils/bcr2.hpp>
#include <utils/passport.hpp>

#include <random.h>
#include <ctime>
#include <iostream>
#include "key_io.h"
#include "tap_protocol/hwi_tapsigner.h"
#include "tap_protocol/tap_protocol.h"
#include "utils/httplib.h"

#include <bbqr/bbqr.hpp>
#include <miniscript/compiler.h>
#include <miniscript/timeline.h>
#include <miniscript/util.h>

using namespace boost::algorithm;
using namespace nunchuk::bcr2;

namespace nunchuk {

static const std::map<std::string, std::vector<unsigned char>>
    VERSION_PREFIXES = {
        {"xpub", {0x04, 0x88, 0xb2, 0x1e}}, {"ypub", {0x04, 0x9d, 0x7c, 0xb2}},
        {"Ypub", {0x02, 0x95, 0xb4, 0x3f}}, {"zpub", {0x04, 0xb2, 0x47, 0x46}},
        {"Zpub", {0x02, 0xaa, 0x7e, 0xd3}}, {"tpub", {0x04, 0x35, 0x87, 0xcf}},
        {"upub", {0x04, 0x4a, 0x52, 0x62}}, {"Upub", {0x02, 0x42, 0x89, 0xef}},
        {"vpub", {0x04, 0x5f, 0x1c, 0xf6}}, {"Vpub", {0x02, 0x57, 0x54, 0x83}}};

static const std::regex BC_UR_REGEX("UR:BYTES/[0-9]+OF[0-9]+/(.+)");

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

std::string Utils::GenerateRandomChainCode() {
  std::vector<unsigned char> buf{};

  // GetStrongRandBytes can only generate up to 32 bytes
  for (int i = 0; i < 4; i++) {
    std::vector<unsigned char> tmp(32);
    GetStrongRandBytes(tmp);
    buf.insert(buf.end(), tmp.begin(), tmp.end());
  }

  std::vector<unsigned char> chain_code(CHash256::OUTPUT_SIZE);
  CHash256 hasher;
  hasher.Write(buf).Finalize(chain_code);

  return HexStr(chain_code);
}

std::string Utils::GenerateHealthCheckMessage() {
  std::time_t t = std::time(0);
  std::tm* now = std::localtime(&t);
  std::stringstream message;
  message << "Health Check " << std::put_time(now, "%b %d %Y") << " ["
          << GenerateRandomMessage(8) << "]";
  return message.str();
}

bool Utils::IsValidXPub(const std::string& value) {
  auto xpub = DecodeExtPubKey(value);
  return xpub.pubkey.IsFullyValid();
}

bool Utils::IsValidXPrv(const std::string& value) {
  auto xprv = DecodeExtKey(value);
  return xprv.key.IsValid();
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

bool Utils::IsDustOutput(const TxOutput& txout) {
  CScript destScript = GetScriptForDestination(DecodeDestination(txout.first));
  CTxOut ctxout(txout.second, destScript);
  return IsDust(ctxout, CFeeRate(DUST_RELAY_TX_FEE));
}

bool Utils::IsValidAddress(const std::string& address) {
  CTxDestination dest = DecodeDestination(address);
  return IsValidDestination(dest);
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

Chain Utils::GetChain() { return CoreUtils::getInstance().GetChain(); }

std::string Utils::GenerateMnemonic(int words) {
  return SoftwareSigner::GenerateMnemonic(words);
}

std::string Utils::GenerateMnemonic12Words() {
  return SoftwareSigner::GenerateMnemonic(12);
}

bool Utils::CheckMnemonic(const std::string& mnemonic) {
  return SoftwareSigner::CheckMnemonic(mnemonic);
}

std::vector<std::string> Utils::GetBIP39WordList() {
  return SoftwareSigner::GetBIP39WordList();
}

std::string Utils::SHA256(const std::string& data) {
  CSHA256 hasher;
  std::vector<unsigned char> stream(data.begin(), data.end());
  hasher.Write((unsigned char*)&(*stream.begin()),
               stream.end() - stream.begin());
  uint8_t hash[32];
  hasher.Finalize(hash);
  return HexStr(hash);
}

void Utils::SetPassPhrase(const std::string& storage_path,
                          const std::string& account, Chain chain,
                          const std::string& old_passphrase,
                          const std::string& new_passphrase) {
  auto storage = NunchukStorage::get(account);
  storage->Init(storage_path, old_passphrase);
  storage->SetPassphrase(chain, new_passphrase);
}

std::vector<PrimaryKey> Utils::GetPrimaryKeys(const std::string& storage_path,
                                              Chain chain) {
  NunchukStorage storage{""};
  storage.Init(storage_path);
  return storage.GetPrimaryKeys(chain);
}

std::string Utils::GetPrimaryKeyAddress(const std::string& mnemonic,
                                        const std::string& passphrase) {
  SoftwareSigner signer{mnemonic, passphrase};
  return signer.GetAddressAtPath(LOGIN_SIGNING_PATH);
}

std::string Utils::GetPrimaryKeyAddress(tap_protocol::Tapsigner* tapsigner,
                                        const std::string& cvc) {
  try {
    auto hwi = tap_protocol::MakeHWITapsigner(tapsigner, cvc);
    const auto xpub = hwi->GetXpubAtPath(LOGIN_SIGNING_PATH);
    const auto epubkey = DecodeExtPubKey(xpub);
    std::string address = EncodeDestination(PKHash(epubkey.pubkey.GetID()));
    return address;
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

std::string Utils::GetPrimaryKeyAddressFromMasterXprv(
    const std::string& master_xprv) {
  SoftwareSigner signer{master_xprv};
  return signer.GetAddressAtPath(LOGIN_SIGNING_PATH);
}

std::string Utils::GetMasterFingerprint(const std::string& mnemonic,
                                        const std::string& passphrase) {
  SoftwareSigner signer{mnemonic, passphrase};
  return signer.GetMasterFingerprint();
}

std::string Utils::GetMasterFingerprint(tap_protocol::Tapsigner* tapsigner,
                                        const std::string& cvc) {
  try {
    return tapsigner->GetXFP(cvc);
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

std::string Utils::GetMasterFingerprintFromMasterXprv(
    const std::string& master_xprv) {
  SoftwareSigner signer{master_xprv};
  return signer.GetMasterFingerprint();
}

std::string Utils::SignLoginMessage(const std::string& mnemonic,
                                    const std::string& passphrase,
                                    const std::string& message) {
  SoftwareSigner signer{mnemonic, passphrase};
  return signer.SignMessage(message, LOGIN_SIGNING_PATH);
}

std::string Utils::SignLoginMessage(tap_protocol::Tapsigner* tapsigner,
                                    const std::string& cvc,
                                    const std::string& message) {
  try {
    auto hwi = tap_protocol::MakeHWITapsigner(tapsigner, cvc);
    return hwi->SignMessage(message, LOGIN_SIGNING_PATH);
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

std::string Utils::SignLoginMessageWithMasterXprv(
    const std::string& master_xprv, const std::string& message) {
  SoftwareSigner signer{master_xprv};
  return signer.SignMessage(message, LOGIN_SIGNING_PATH);
}

std::vector<Device> Utils::GetDevices(const std::string& hwi_path) {
  auto hwi = HWIService(hwi_path, Utils::GetChain());
  return hwi.Enumerate();
}

std::string Utils::SignPsbt(const std::string& mnemonic,
                            const std::string& passphrase,
                            const std::string& psbt) {
  if (psbt.empty()) {
    throw NunchukException(NunchukException::INVALID_PSBT, "Invalid PSBT");
  }
  SoftwareSigner signer{mnemonic, passphrase};
  return signer.SignTx(psbt);
}

std::string Utils::SignPsbt(tap_protocol::Tapsigner* tapsigner,
                            const std::string& cvc, const std::string& psbt) {
  if (psbt.empty()) {
    throw NunchukException(NunchukException::INVALID_PSBT, "Invalid PSBT");
  }

  try {
    auto hwi_tapsigner = tap_protocol::MakeHWITapsigner(tapsigner, cvc);
    return hwi_tapsigner->SignTx(psbt);
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

std::string Utils::SignPsbt(const std::string& hwi_path, const Device& device,
                            const std::string& psbt) {
  auto hwi = HWIService(hwi_path, Utils::GetChain());
  if (psbt.empty()) {
    throw NunchukException(NunchukException::INVALID_PSBT, "Invalid PSBT");
  }
  return hwi.SignTx(device, psbt);
}

Wallet Utils::ParseWalletDescriptor(const std::string& descs) {
  AddressType a;
  WalletType w;
  WalletTemplate t = WalletTemplate::DEFAULT;
  int m;
  int n;
  std::vector<SingleSigner> signers;
  std::string name;

  // Try all possible formats: BSMS, Descriptors, JSON with `descriptor` key,
  // Multisig config
  if (ParseDescriptorRecord(descs, a, w, t, m, n, signers) ||
      ParseDescriptors(descs, a, w, t, m, n, signers) ||
      ParseJSONDescriptors(descs, name, a, w, t, m, n, signers) ||
      ParseUnchainedWallet(descs, name, a, w, m, n, signers) ||
      ParseConfig(Utils::GetChain(), descs, name, a, w, m, n, signers)) {
    std::string id = GetWalletId(signers, m, a, w, t);
    Wallet wallet{id, name, m, n, signers, a, w, std::time(0)};
    wallet.set_wallet_template(t);
    return wallet;
  }

  throw NunchukException(NunchukException::INVALID_PARAMETER,
                         "Could not parse descriptor");
}

static Wallet parseBCR2Wallet(Chain chain,
                              const std::vector<std::string>& qr_data) {
  using namespace nunchuk::bcr2;

  auto decoder = ur::URDecoder();
  for (auto&& part : qr_data) {
    decoder.receive_part(part);
  }
  if (!decoder.is_complete() || !decoder.is_success()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid BC-UR2 input");
  }
  auto cbor = decoder.result_ur().cbor();
  auto i = cbor.begin();
  auto end = cbor.end();
  std::string name;
  AddressType a;
  WalletType w;
  WalletTemplate t = WalletTemplate::DEFAULT;
  int m;
  int n;
  std::vector<SingleSigner> signers;

  if (decoder.result_ur().type() == "crypto-output") {  // BCR-2020-010
    CryptoOutput output{};
    decodeCryptoOutput(i, end, output);

    a = output.addressType;
    w = output.walletType;
    m = output.threshold;
    n = output.outputDescriptors.size();
    std::stringstream s;
    s << "ImportedWallet-" << m << "of" << n;
    name = s.str();

    for (auto&& key : output.outputDescriptors) {
      std::string path = key.get_path();
      signers.push_back(
          SingleSigner(GetSignerNameFromDerivationPath(path, "ImportedKey-"),
                       key.get_xpub(), {}, path, key.get_xfp(), 0));
    }
  } else {  // COLDCARD config format encoded in bytes
    std::vector<char> config;
    CborLite::decodeBytes(i, end, config);
    std::string config_str(config.begin(), config.end());

    if (!ParseConfig(chain, config_str, name, a, w, m, n, signers)) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Could not parse multisig config");
    }
  }
  std::string id = GetWalletId(signers, m, a, w, t);
  Wallet rs{id, name, m, n, signers, a, w, std::time(0)};
  rs.set_wallet_template(t);
  return rs;
}

static Wallet parseBBQRWallet(Chain chain,
                              const std::vector<std::string>& qr_data) {
  try {
    auto join_result = bbqr::join_qrs<std::string>(qr_data);
    if (join_result.is_complete) {
      return Utils::ParseWalletDescriptor(join_result.raw);
    }
    throw NunchukException(NunchukException::INVALID_PARAMETER, "Invalid data");
  } catch (NunchukException& e) {
    throw;
  } catch (std::exception& e) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, "Invalid data");
  }
}

Wallet Utils::ParseKeystoneWallet(Chain chain,
                                  const std::vector<std::string>& qr_data) {
  constexpr auto parseRawWallet = [](const std::vector<std::string>& qr_data) {
    if (qr_data.size() == 1) {
      return ParseWalletDescriptor(qr_data[0]);
    }
    throw NunchukException(NunchukException::INVALID_PARAMETER, "Invalid QR");
  };

  return RunThrowOne(std::bind(parseBCR2Wallet, chain, qr_data),
                     std::bind(parseBBQRWallet, chain, qr_data),
                     std::bind(parseRawWallet, qr_data));
}

BtcUri Utils::ParseBtcUri(const std::string& value) {
  static constexpr auto BITCOIN_SCHEME = "bitcoin:";

  std::string str = boost::trim_copy(value);
  if (boost::algorithm::istarts_with(str, BITCOIN_SCHEME)) {
    const static std::regex BECH32_ADDRESS_URI(
        R"(^bitcoin:([a-zA-Z0-9]+)\??([^#]*))", std::regex::icase);
    static constexpr auto PARAMETER_AMOUNT = "amount";
    static constexpr auto PARAMETER_LABEL = "label";
    static constexpr auto PARAMETER_MESSAGE = "message";
    static constexpr auto PARAMETER_REQ_ = "req-";
    static constexpr size_t PARAMETER_REQ_LENGTH = 4;

    std::smatch sm;
    if (std::regex_match(str, sm, BECH32_ADDRESS_URI)) {
      std::string address = sm[1].str();
      if (!IsValidDestinationString(address)) {
        throw NunchukException(NunchukException::INVALID_ADDRESS,
                               "Invalid address");
      }

      BtcUri ret{address};

      if (sm.size() > 2 && sm[2].length() > 0) {
        std::multimap<std::string, std::string> params;
        httplib::detail::parse_query_text(sm[2].str(), params);

        for (auto&& [key, value] : params) {
          if (key == PARAMETER_AMOUNT) {
            ret.amount = Utils::AmountFromValue(value);
          } else if (key == PARAMETER_LABEL) {
            ret.label = value;
          } else if (key == PARAMETER_MESSAGE) {
            ret.message = value;
          } else if (boost::algorithm::istarts_with(key, PARAMETER_REQ_)) {
            ret.others[key.substr(PARAMETER_REQ_LENGTH)] = value;
          } else {
            ret.others[key] = value;
          }
        }
        return ret;
      }

      return ret;
    }
    throw NunchukException(NunchukException::INVALID_ADDRESS,
                           "Invalid address");
  }

  if (!IsValidDestinationString(str)) {
    throw NunchukException(NunchukException::INVALID_ADDRESS,
                           "Invalid address");
  }
  return {std::move(str)};
}

Wallet Utils::ParseWalletConfig(Chain chain, const std::string& config) {
  std::string name;
  AddressType a;
  WalletType w;
  WalletTemplate t = WalletTemplate::DEFAULT;
  int m;
  int n;
  std::vector<SingleSigner> signers;
  if (!ParseConfig(chain, config, name, a, w, m, n, signers)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Could not parse multisig config");
  }
  std::string id = GetWalletId(signers, m, a, w, t);
  Wallet rs{id, name, m, n, signers, a, w, std::time(0)};
  rs.set_wallet_template(t);
  return rs;
}

BSMSData Utils::ParseBSMSData(const std::string& bsms) {
  return ::ParseBSMSData(bsms);
}

SingleSigner Utils::ParseSignerString(const std::string& signer_str) {
  return nunchuk::ParseSignerString(signer_str);
}

std::vector<Wallet> Utils::ParseJSONWallets(const std::string& json_str,
                                            SignerType signer_type) {
  static const std::array<std::tuple<std::string, std::string, AddressType>, 3>
      FILTER_WALLETS{{
          {"bip84", "m/84h - Native Segwit (Recommended)",
           AddressType::NATIVE_SEGWIT},
          {"bip49", "m/49h - Nested Segwit", AddressType::NESTED_SEGWIT},
          {"bip44", "m/44h - Legacy", AddressType::LEGACY},
      }};

  try {
    const nlohmann::json data = json::parse(json_str);
    const std::string xfp = data["xfp"];

    std::vector<Wallet> result;
    for (auto&& [bip, tmp_name, address_type] : FILTER_WALLETS) {
      auto bip_iter = data.find(bip);
      if (bip_iter == data.end()) {
        continue;
      }

      const std::string xpub = bip_iter.value()["xpub"];
      const std::string derivation_path = bip_iter.value()["deriv"];

      SingleSigner signer = Utils::SanitizeSingleSigner(SingleSigner(
          GetSignerNameFromDerivationPath(derivation_path, "COLDCARD-"), xpub,
          {}, derivation_path, xfp, std::time(nullptr), {}, false,
          signer_type));

      Wallet wallet({}, tmp_name, 1, 1, {std::move(signer)}, address_type,
                    WalletType::SINGLE_SIG, std::time(0));
      result.emplace_back(std::move(wallet));
    }
    return result;
  } catch (BaseException& e) {
    throw;
  } catch (...) {
    throw NunchukException(NunchukException::INVALID_FORMAT,
                           "Invalid data format");
  }
}

std::vector<Wallet> Utils::ParseBBQRWallets(
    const std::vector<std::string>& qr_data) {
  try {
    auto join_result = bbqr::join_qrs<std::string>(qr_data);
    if (join_result.file_type != bbqr::FileType::J ||
        !join_result.is_complete) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid data");
    }
    return ParseJSONWallets(join_result.raw);
  } catch (std::exception& e) {
    throw NunchukException(NunchukException::INVALID_FORMAT, "Invalid data");
  }
}

std::vector<SingleSigner> Utils::ParsePassportSigners(
    Chain chain, const std::vector<std::string>& qr_data) {
  if (qr_data.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "QR data is empty");
  }
  std::smatch sm;
  std::vector<unsigned char> config;

  if (std::regex_match(qr_data[0], sm, BC_UR_REGEX)) {  // BC_UR format
    config = nunchuk::bcr::DecodeUniformResource(qr_data);
  } else {  // BC_UR2 format
    auto decoder = ur::URDecoder();
    for (auto&& part : qr_data) {
      decoder.receive_part(part);
    }
    if (!decoder.is_complete() || !decoder.is_success()) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid BC-UR2 input");
    }
    auto cbor = decoder.result_ur().cbor();
    auto i = cbor.begin();
    auto end = cbor.end();
    bcr2::decodeBytes(i, end, config);
  }

  std::string config_str(config.begin(), config.end());
  std::vector<SingleSigner> signers;
  if (ParsePassportSignerConfig(chain, config_str, signers)) {
    for (auto&& signer : signers) {
      signer.set_type(SignerType::AIRGAP);
    }
    return signers;
  } else {
    throw NunchukException(NunchukException::INVALID_FORMAT,
                           "Invalid data format");
  }
}

SingleSigner Utils::SanitizeSingleSigner(const SingleSigner& signer) {
  std::string target_format =
      Utils::GetChain() == Chain::MAIN ? "xpub" : "tpub";
  std::string sanitized_xpub =
      Utils::SanitizeBIP32Input(signer.get_xpub(), target_format);
  if (!Utils::IsValidXPub(sanitized_xpub) &&
      !Utils::IsValidPublicKey(signer.get_public_key())) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid xpub and public_key");
  }
  if (!Utils::IsValidDerivationPath(signer.get_derivation_path())) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid derivation path");
  }
  if (!Utils::IsValidFingerPrint(signer.get_master_fingerprint())) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid master fingerprint");
  }
  std::string xfp = boost::to_lower_copy(signer.get_master_fingerprint());
  std::string name = boost::trim_copy(signer.get_name());

  return SingleSigner(name, sanitized_xpub, signer.get_public_key(),
                      signer.get_derivation_path(), xfp,
                      signer.get_last_health_check(),
                      signer.get_master_signer_id(), signer.is_used(),
                      signer.get_type(), signer.get_tags());
}

std::vector<SingleSigner> Utils::SanitizeSingleSigners(
    const std::vector<SingleSigner>& signers) {
  std::vector<SingleSigner> ret;
  for (const SingleSigner& signer : signers) {
    ret.emplace_back(SanitizeSingleSigner(signer));
  }
  return ret;
}

std::string Utils::GetHealthCheckMessage(const std::string& body) {
  CSHA256 hasher;
  std::vector<unsigned char> stream(body.begin(), body.end());
  hasher.Write((unsigned char*)&(*stream.begin()),
               stream.end() - stream.begin());
  uint8_t hash[32];
  hasher.Finalize(hash);
  std::stringstream ss;
  ss << std::hex;
  for (int i(0); i < 32; ++i)
    ss << std::setw(2) << std::setfill('0') << (int)hash[i];
  return ss.str();
}

std::string Utils::GetHealthCheckDummyTx(const Wallet& wallet,
                                         const std::string& body) {
  std::string descriptor = wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL);

  // Create UTXO
  std::string body_hash = GetHealthCheckMessage(body);
  auto address = CoreUtils::getInstance().DeriveAddress(descriptor, 1);
  auto prev_psbt = DecodePsbt(CoreUtils::getInstance().CreatePsbt(
      {{body_hash, 0}}, {{address, 10150}}));

  // Create dummy TX
  auto address2 = CoreUtils::getInstance().DeriveAddress(descriptor, 2);
  std::string base64_psbt = CoreUtils::getInstance().CreatePsbt(
      {{prev_psbt.tx->GetHash().GetHex(), 0}}, {{address2, 10000}});

  // Fill PSBT
  auto psbt = DecodePsbt(base64_psbt);
  auto desc = GetDescriptorsImportString(wallet);
  auto provider = SigningProviderCache::getInstance().GetProvider(desc);

  psbt.inputs[0].non_witness_utxo = MakeTransactionRef(*prev_psbt.tx);
  psbt.inputs[0].witness_utxo = prev_psbt.tx->vout[0];

  const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);
  SignPSBTInput(provider, psbt, 0, &txdata, 1);
  UpdatePSBTOutput(provider, psbt, 0);

  for (auto&& signer : wallet.get_signers()) {
    std::vector<unsigned char> key;
    if (DecodeBase58Check(signer.get_xpub(), key, 78)) {
      auto value = ParseHex(signer.get_master_fingerprint());
      std::vector<uint32_t> keypath;
      std::string formalized = signer.get_derivation_path();
      std::replace(formalized.begin(), formalized.end(), 'h', '\'');
      if (ParseHDKeypath(formalized, keypath)) {
        for (uint32_t index : keypath) {
          value.push_back(index);
          value.push_back(index >> 8);
          value.push_back(index >> 16);
          value.push_back(index >> 24);
        }
      }
      key.insert(key.begin(), 1);
      psbt.unknown[key] = value;
    }
  }

  return EncodePsbt(psbt);
}

Transaction Utils::DecodeDummyTx(const Wallet& wallet,
                                 const std::string& psbt) {
  std::string base64_psbt =
      boost::starts_with(psbt, "psbt")
          ? EncodeBase64(MakeUCharSpan(boost::trim_copy(psbt)))
          : boost::trim_copy(psbt);
  auto tx = GetTransactionFromPartiallySignedTransaction(
      DecodePsbt(base64_psbt), wallet);
  tx.set_fee(150);
  tx.set_sub_amount(10000);
  tx.set_change_index(-1);
  tx.set_subtract_fee_from_amount(false);
  tx.set_psbt(base64_psbt);
  tx.set_receive(false);
  return tx;
}

Transaction Utils::DecodeTx(const Wallet& wallet, const std::string& psbt,
                            const Amount& sub_amount, const Amount& fee,
                            const Amount& fee_rate) {
  auto tx =
      GetTransactionFromPartiallySignedTransaction(DecodePsbt(psbt), wallet);
  tx.set_sub_amount(sub_amount);
  tx.set_fee(fee);
  tx.set_fee_rate(fee_rate);
  tx.set_receive(false);
  tx.set_subtract_fee_from_amount(true);
  tx.set_psbt(psbt);
  return tx;
}

std::string Utils::CreateRequestToken(const std::string& signature,
                                      const std::string& fingerprint) {
  return fingerprint + "." + signature;
}

std::string Utils::GetPartialSignature(const SingleSigner& signer,
                                       const std::string& signed_psbt) {
  return ::GetPartialSignature(signed_psbt, signer);
}

std::vector<std::string> Utils::ExportKeystoneTransaction(
    const std::string& psbt, int fragment_len) {
  if (psbt.empty()) {
    throw NunchukException(NunchukException::INVALID_PSBT, "Invalid psbt");
  }
  auto data = DecodeBase64(psbt.c_str());
  if (!data) {
    throw NunchukException(NunchukException::INVALID_PSBT, "Invalid base64");
  }
  bcr2::CryptoPSBT crypto_psbt{*data};
  ur::ByteVector cbor;
  encodeCryptoPSBT(cbor, crypto_psbt);
  auto encoder = ur::UREncoder(ur::UR("crypto-psbt", cbor), fragment_len);
  std::vector<std::string> qr_data;
  do {
    qr_data.push_back(boost::to_upper_copy(encoder.next_part()));
  } while (encoder.seq_num() <= 2 * encoder.seq_len());
  return qr_data;
}

std::vector<std::string> Utils::ExportPassportTransaction(
    const std::string& psbt, int fragment_len) {
  if (psbt.empty()) {
    throw NunchukException(NunchukException::INVALID_PSBT, "Invalid psbt");
  }
  auto data = DecodeBase64(psbt.c_str());
  if (!data) {
    throw NunchukException(NunchukException::INVALID_PSBT, "Invalid base64");
  }
  bcr2::CryptoPSBT crypto_psbt{*data};
  ur::ByteVector cbor;
  encodeCryptoPSBT(cbor, crypto_psbt);
  auto encoder = ur::UREncoder(ur::UR("crypto-psbt", cbor), fragment_len);
  std::vector<std::string> qr_data;
  do {
    qr_data.push_back(boost::to_upper_copy(encoder.next_part()));
  } while (encoder.seq_num() <= 2 * encoder.seq_len());
  return qr_data;
}

std::vector<std::string> Utils::ExportBBQRTransaction(const std::string& psbt,
                                                      int min_version,
                                                      int max_version) {
  auto data = DecodeBase64(psbt.c_str());
  if (!data) {
    throw NunchukException(NunchukException::INVALID_PSBT, "Invalid base64");
  }
  bbqr::SplitOption option{};
  option.min_version = min_version;
  option.max_version = max_version;
  try {
    auto split_result = bbqr::split_qrs(*data, bbqr::FileType::P, option);
    return split_result.parts;
  } catch (std::exception& e) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, e.what());
  }
}

std::vector<std::string> Utils::ExportBBQRWallet(const Wallet& wallet,
                                                 ExportFormat format,
                                                 int min_version,
                                                 int max_version) {
  const auto get_export_data = [&](ExportFormat format) -> std::string {
    switch (format) {
      case ExportFormat::COLDCARD:
        return ::GetMultisigConfig(wallet);
      case ExportFormat::DESCRIPTOR:
        return wallet.get_descriptor(DescriptorPath::ANY);
      case ExportFormat::BSMS:
        return GetDescriptorRecord(wallet);
      case ExportFormat::DB:
        return {};
      case ExportFormat::COBO:
        return {};
      case ExportFormat::CSV:
        return {};
    }
    return {};
  };

  std::string data = get_export_data(format);
  if (data.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid format");
  }
  bbqr::SplitOption option{};
  option.min_version = min_version;
  option.max_version = max_version;
  auto split_result = bbqr::split_qrs(data, bbqr::FileType::U, option);
  return split_result.parts;
}

std::vector<std::string> Utils::ExportKeystoneWallet(const Wallet& wallet,
                                                     int fragment_len) {
  auto content = ::GetMultisigConfig(wallet);
  std::vector<uint8_t> data(content.begin(), content.end());
  ur::ByteVector cbor;
  encodeBytes(cbor, data);
  auto encoder = ur::UREncoder(ur::UR("bytes", cbor), fragment_len);
  std::vector<std::string> parts;
  do {
    parts.push_back(to_upper_copy(encoder.next_part()));
  } while (encoder.seq_num() <= 2 * encoder.seq_len());
  return parts;
}

std::vector<std::string> Utils::ExportBCR2020010Wallet(const Wallet& wallet,
                                                       int fragment_len) {
  CryptoOutput co = CryptoOutput::from_wallet(wallet);
  ur::ByteVector cbor;
  encodeCryptoOutput(cbor, co);
  auto encoder = ur::UREncoder(ur::UR("crypto-output", cbor), fragment_len);
  std::vector<std::string> parts;
  do {
    parts.push_back(to_upper_copy(encoder.next_part()));
  } while (encoder.seq_num() <= 2 * encoder.seq_len());
  return parts;
}

static std::string parseBCR2Transaction(
    const std::vector<std::string>& qr_data) {
  if (qr_data.empty()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "QR data is empty");
  }
  std::smatch sm;
  std::vector<unsigned char> data;
  if (std::regex_match(qr_data[0], sm, BC_UR_REGEX)) {  // BC_UR format
    data = nunchuk::bcr::DecodeUniformResource(qr_data);
  } else {
    auto decoder = ur::URDecoder();
    for (auto&& part : qr_data) {
      decoder.receive_part(part);
    }
    if (!decoder.is_complete() || !decoder.is_success()) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid BC-UR2 input");
    }

    auto decoded = decoder.result_ur();
    auto i = decoded.cbor().begin();
    auto end = decoded.cbor().end();
    bcr2::CryptoPSBT psbt{};
    decodeCryptoPSBT(i, end, psbt);
    data = std::move(psbt.data);
  }

  return EncodeBase64(MakeUCharSpan(data));
}

static std::string parseBBQRTransaction(
    const std::vector<std::string>& qr_data) {
  try {
    auto join_result = bbqr::join_qrs(qr_data);
    if (!join_result.is_complete) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid data");
    }
    switch (join_result.file_type) {
      case bbqr::FileType::P:
        return EncodeBase64(MakeUCharSpan(join_result.raw));
      case bbqr::FileType::T:
        return HexStr(join_result.raw);
      default:
        throw NunchukException(NunchukException::INVALID_PARAMETER,
                               "Invalid data");
    }
  } catch (NunchukException& e) {
    throw;
  } catch (std::exception& e) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, "Invalid data");
  }
}

static std::string parseRawTransaction(
    const std::vector<std::string>& qr_data) {
  if (qr_data.size() != 1) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, "Invalid data");
  }

  // transaction in hex format
  if (boost::starts_with(qr_data[0], "01000000") ||
      boost::starts_with(qr_data[0], "02000000")) {
    return qr_data[0];
  }

  // transaction in hex psbt
  if (boost::starts_with(qr_data[0], "70736274")) {
    return qr_data[0];
  }
  throw NunchukException(NunchukException::INVALID_PARAMETER, "Invalid data");
}

std::string Utils::ParseKeystoneTransaction(
    const std::vector<std::string>& qr_data) {
  return RunThrowOne(std::bind(parseBCR2Transaction, qr_data),
                     std::bind(parseBBQRTransaction, qr_data),
                     std::bind(parseRawTransaction, qr_data));
}

std::string Utils::ParsePassportTransaction(
    const std::vector<std::string>& qr_data) {
  return RunThrowOne(std::bind(parseBCR2Transaction, qr_data),
                     std::bind(parseBBQRTransaction, qr_data),
                     std::bind(parseRawTransaction, qr_data));
}

AnalyzeQRResult Utils::AnalyzeQR(const std::vector<std::string>& qr_data) {
  if (qr_data.size() == 0) {
    return AnalyzeQRResult{};
  }

  auto decoder = ur::URDecoder();
  for (auto&& part : qr_data) {
    decoder.receive_part(part);
  }

  if (decoder.processed_parts_count() != 0) {
    return AnalyzeQRResult{
        decoder.is_success(),
        decoder.is_failure(),
        decoder.is_complete(),
        decoder.expected_part_count(),
        decoder.received_part_indexes(),
        decoder.last_part_indexes(),
        decoder.processed_parts_count(),
        decoder.estimated_percent_complete(),
    };
  }

  // BBQR
  try {
    auto join_result = bbqr::join_qrs(qr_data);
    if (join_result.expected_part_count != 0) {
      return AnalyzeQRResult{
          join_result.is_complete,
          false,
          join_result.is_complete,
          join_result.expected_part_count,
          {},
          {},
          join_result.processed_parts_count,
          1.0 * join_result.processed_parts_count /
              join_result.expected_part_count,
      };
    }
  } catch (std::exception& e) {
  }

  return {};
}

int Utils::GetIndexFromPath(const std::string& path) {
  return ::GetIndexFromPath(path);
}

std::string Utils::GetBip32Path(WalletType wallet_type,
                                AddressType address_type, int index) {
  return ::GetBip32Path(Utils::GetChain(), wallet_type, address_type, index);
}

std::vector<std::string> Utils::DeriveAddresses(const Wallet& wallet,
                                                int from_index, int to_index) {
  std::string external_desc =
      wallet.get_descriptor(DescriptorPath::EXTERNAL_ALL);
  return CoreUtils::getInstance().DeriveAddresses(external_desc, from_index,
                                                  to_index);
}

bool Utils::NewDecoyPin(const std::string& storage_path,
                        const std::string& pin) {
  NunchukStorage storage{""};
  storage.Init(storage_path);
  return storage.NewDecoyPin(pin);
}

bool Utils::IsExistingDecoyPin(const std::string& storage_path,
                               const std::string& pin) {
  NunchukStorage storage{""};
  storage.Init(storage_path);
  return storage.IsExistingDecoyPin(pin);
}

bool Utils::ChangeDecoyPin(const std::string& storage_path,
                           const std::string& old_pin,
                           const std::string& new_pin) {
  NunchukStorage storage{""};
  storage.Init(storage_path);
  return storage.ChangeDecoyPin(old_pin, new_pin);
}

std::vector<std::string> Utils::ListDecoyPin(const std::string& storage_path) {
  NunchukStorage storage{""};
  storage.Init(storage_path);
  return storage.ListDecoyPin();
}

bool Utils::CheckElectrumServer(const std::string& server, int timeout) {
  using namespace boost::asio;
  using ip::tcp;
  using ec = boost::system::error_code;

  std::string server_url = server;
  std::string protocol;
  std::string host;
  unsigned short port = 50001;

  size_t colonDoubleSlash = server_url.find("://");
  if (colonDoubleSlash != std::string::npos) {
    protocol = server_url.substr(0, colonDoubleSlash);
    if (protocol != "tcp" && protocol != "ssl") return false;
    server_url = server_url.substr(colonDoubleSlash + 3);
  }
  size_t colon = server_url.find(":");
  if (colon != std::string::npos) {
    host = server_url.substr(0, colon);
    std::string portStr = server_url.substr(colon + 1);
    port = portStr.empty() ? 50001 : std::stoi(portStr);
    if (port < 0 || port > 65353) return false;
  } else {
    host = server_url;
  }

  bool result = false;
  try {
    io_service svc;
    tcp::socket s(svc);
    deadline_timer tim(svc, boost::posix_time::seconds(timeout));

    tim.async_wait([&](ec) { s.cancel(); });
    s.async_connect({ip::address::from_string(host), port},
                    [&](ec ec) { result = !ec; });

    svc.run();
  } catch (...) {
  }

  return result;
}
std::vector<uint8_t> Utils::HashPreimage(const std::vector<uint8_t>& data,
                                         PreimageHashType hashType) {
  if (data.size() != 32) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid preimage size");
  }
  std::vector<uint8_t> hash;
  switch (hashType) {
    case PreimageHashType::SHA256:
      hash.resize(32);
      CSHA256().Write(data.data(), data.size()).Finalize(hash.data());
      break;
    case PreimageHashType::HASH256:
      hash.resize(32);
      CHash256().Write(data).Finalize(hash);
      break;
    case PreimageHashType::RIPEMD160:
      hash.resize(20);
      CRIPEMD160().Write(data.data(), data.size()).Finalize(hash.data());
      break;
    case PreimageHashType::HASH160:
      hash.resize(20);
      CHash160().Write(data).Finalize(hash);
      break;
    default:
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid hash type");
  }
  return hash;
}

std::string Utils::RevealPreimage(const std::string& psbt,
                                  PreimageHashType hashType,
                                  const std::vector<uint8_t>& hash,
                                  const std::vector<uint8_t>& preimage) {
  auto psbtx = DecodePsbt(psbt);
  if (hash != Utils::HashPreimage(preimage, hashType)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, "Invalid hash");
  }
  for (int i = 0; i < psbtx.inputs.size(); i++) {
    if (hashType == PreimageHashType::SHA256) {
      psbtx.inputs[i].sha256_preimages.emplace(hash, preimage);
    } else if (hashType == PreimageHashType::HASH256) {
      psbtx.inputs[i].hash256_preimages.emplace(hash, preimage);
    } else if (hashType == PreimageHashType::HASH160) {
      psbtx.inputs[i].hash160_preimages.emplace(hash, preimage);
    } else if (hashType == PreimageHashType::RIPEMD160) {
      psbtx.inputs[i].ripemd160_preimages.emplace(hash, preimage);
    }
  }
  return EncodePsbt(psbtx);
}

bool Utils::IsPreimageRevealed(const std::string& psbt,
                               const std::vector<uint8_t>& hash) {
  auto psbtx = DecodePsbt(psbt);
  for (int i = 0; i < psbtx.inputs.size(); i++) {
    if (psbtx.inputs[i].sha256_preimages.contains(uint256(hash)) ||
        psbtx.inputs[i].hash256_preimages.contains(uint256(hash)) ||
        psbtx.inputs[i].hash160_preimages.contains(uint160(hash)) ||
        psbtx.inputs[i].ripemd160_preimages.contains(uint160(hash))) {
      return true;
    }
  }
  return false;
}

bool Utils::IsValidPolicy(const std::string& policy) {
  miniscript::NodeRef<std::string> ret;
  double avgcost;
  return ::Compile(policy, ret, avgcost);
}

std::string Utils::PolicyToMiniscript(
    const std::string& policy,
    const std::map<std::string, SingleSigner>& signers,
    AddressType address_type) {
  auto policy_node = ::ParsePolicy(policy);
  if (!policy_node()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid policy");
  }
  std::map<std::string, std::string> config;
  for (const auto& signer : signers) {
    config[signer.first] =
        GetDescriptorForSigner(signer.second, DescriptorPath::ANY);
  }
  return nunchuk::PolicyToMiniscript(policy_node, config, address_type);
}

bool Utils::IsValidMiniscriptTemplate(const std::string& miniscript_template,
                                      AddressType address_type) {
  auto node = ParseMiniscript(miniscript_template, address_type);
  return node && node->IsValidTopLevel() && node->IsSane() &&
         !node->IsNotSatisfiable();
}

bool Utils::IsValidTapscriptTemplate(const std::string& tapscript_template,
                                     std::string& error) {
  std::string keypath;
  std::vector<std::string> subscripts;
  std::vector<int> depths;
  if (!ParseTapscriptTemplate(tapscript_template, keypath, subscripts, depths,
                              error)) {
    return false;
  }
  for (auto& subscript : subscripts) {
    if (IsValidMusigTemplate(subscript)) continue;
    if (!IsValidMiniscriptTemplate(subscript, AddressType::TAPROOT)) {
      error = strprintf("invalid miniscript template: '%s'", subscript);
      return false;
    }
  }
  return true;
}

bool Utils::IsValidMusigTemplate(const std::string& musig_template) {
  if (musig_template.size() <= 11) return false;
  if (musig_template.find("pk(musig(") != 0) return false;
  if (musig_template.find("))", 9) != musig_template.size() - 2) return false;
  std::string inner = musig_template.substr(9, musig_template.size() - 11);
  std::vector<std::string> inner_parts = split(inner, ',');
  if (inner_parts.size() < 2) return false;
  if (join(inner_parts, ',') != inner) return false;
  return true;
}

struct TemplateContext {
  typedef std::string Key;
  const std::map<std::string, SingleSigner>& signers;
  TemplateContext(const std::map<std::string, SingleSigner>& signers)
      : signers(signers) {}
  std::optional<std::string> ToString(const Key& key) const {
    return GetDescriptorForSigner(signers.at(key), DescriptorPath::ANY);
  }
};

std::string Utils::MiniscriptTemplateToMiniscript(
    const std::string& miniscript_template,
    const std::map<std::string, SingleSigner>& signers) {
  if (IsValidMusigTemplate(miniscript_template)) {
    return GetMusigScript(miniscript_template, signers);
  }
  auto node = ParseMiniscript(miniscript_template, AddressType::ANY);
  if (!node || !node->IsValidTopLevel() || !node->IsSane() ||
      node->IsNotSatisfiable()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid miniscript template");
  }

  return ::Abbreviate(
      *(node->ToString<TemplateContext>(TemplateContext(signers))));
}

std::string Utils::TapscriptTemplateToTapscript(
    const std::string& tapscript_template,
    const std::map<std::string, SingleSigner>& signers, std::string& keypath) {
  std::vector<std::string> subscripts_tmpl;
  std::vector<int> depths;
  std::string error;
  if (!ParseTapscriptTemplate(tapscript_template, keypath, subscripts_tmpl,
                              depths, error)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER, error);
  }

  std::vector<std::string> subscripts;
  for (auto& subscript : subscripts_tmpl) {
    subscripts.push_back(MiniscriptTemplateToMiniscript(subscript, signers));
  }

  std::string ret;
  SubScriptsToString(subscripts, depths, ret);
  return ret;
}

std::string Utils::GetMusigScript(
    const std::string& musig_template,
    const std::map<std::string, SingleSigner>& signers) {
  if (!IsValidMusigTemplate(musig_template))
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid musig template");
  std::string inner = musig_template.substr(9, musig_template.size() - 11);
  std::vector<std::string> parts = split(inner, ',');
  std::stringstream ss;
  ss << "pk(musig(";
  for (int i = 0; i < parts.size(); i++) {
    if (i > 0) ss << ",";
    ss << GetDescriptorForSigner(signers.at(parts[i]), DescriptorPath::ANY);
  }
  ss << "))";
  return ss.str();
}

ScriptNode Utils::GetScriptNode(const std::string& script,
                                std::string& keypath) {
  std::vector<std::string> subscripts;
  std::vector<int> depths;
  std::string error;
  if (ParseTapscriptTemplate(script, keypath, subscripts, depths, error)) {
    auto node = SubScriptsToScriptNode(subscripts, depths);
    node.set_id({1});
    return node;
  }

  auto node = MiniscriptToScriptNode(ParseMiniscript(script, AddressType::ANY));
  node.set_id({1});
  return node;
}

void combinations(const std::vector<std::vector<SigningPath>>& lists,
                  int list_index, std::vector<SigningPath>& current,
                  std::vector<std::vector<SigningPath>>& result) {
  if (list_index == lists.size()) {
    result.push_back(current);
    return;
  }

  for (int i = 0; i < lists[list_index].size(); ++i) {
    current.push_back(lists[list_index][i]);
    combinations(lists, list_index + 1, current, result);
    current.pop_back();
  }
}

std::vector<SigningPath> get_all_paths(const ScriptNode& node) {
  if (node.get_type() != ScriptNode::Type::ANDOR &&
      node.get_type() != ScriptNode::Type::AND &&
      node.get_type() != ScriptNode::Type::THRESH &&
      node.get_type() != ScriptNode::Type::OR &&
      node.get_type() != ScriptNode::Type::OR_TAPROOT) {
    return {{node.get_id()}};
  }
  std::vector<SigningPath> paths;

  if (node.get_type() == ScriptNode::Type::ANDOR) {
    std::map<size_t, std::vector<SigningPath>> sub_paths;
    for (size_t i = 0; i < node.get_subs().size(); i++) {
      sub_paths[i] = get_all_paths(node.get_subs()[i]);
    }
    std::vector<std::vector<SigningPath>> xandy_paths;
    std::vector<SigningPath> current;
    combinations({sub_paths[0], sub_paths[1]}, 0, current, xandy_paths);

    for (const auto& combination : xandy_paths) {
      SigningPath sub_path;
      for (size_t i = 0; i < combination.size(); ++i) {
        sub_path.insert(sub_path.end(), combination[i].begin(),
                        combination[i].end());
      }
      paths.push_back(sub_path);
    }

    for (auto&& sub_path : sub_paths[2]) {
      paths.push_back(sub_path);
    }
  } else if (node.get_type() == ScriptNode::Type::AND ||
             node.get_type() == ScriptNode::Type::THRESH) {
    std::map<size_t, std::vector<SigningPath>> sub_paths;
    for (size_t i = 0; i < node.get_subs().size(); i++) {
      sub_paths[i] = get_all_paths(node.get_subs()[i]);
    }
    std::vector<bool> v(node.get_subs().size());
    auto k = node.get_type() == ScriptNode::Type::THRESH ? node.get_k() : 2;
    std::fill(v.begin(), v.begin() + k, true);
    do {
      std::vector<std::vector<SigningPath>> lists{};

      for (int i = 0; i < node.get_subs().size(); i++) {
        if (v[i]) {
          lists.push_back(sub_paths[i]);
        }
      }

      std::vector<std::vector<SigningPath>> result;
      std::vector<SigningPath> current;
      combinations(lists, 0, current, result);

      for (const auto& combination : result) {
        SigningPath sub_path;
        for (size_t i = 0; i < combination.size(); ++i) {
          sub_path.insert(sub_path.end(), combination[i].begin(),
                          combination[i].end());
        }
        paths.push_back(sub_path);
      }
    } while (std::prev_permutation(v.begin(), v.end()));

  } else if (node.get_type() == ScriptNode::Type::OR ||
             node.get_type() == ScriptNode::Type::OR_TAPROOT) {
    for (size_t i = 0; i <= 1; i++) {
      auto sub_paths = get_all_paths(node.get_subs()[i]);
      for (auto&& sub_path : sub_paths) {
        paths.push_back(sub_path);
      }
    }
  }
  return paths;
}

std::vector<SigningPath> Utils::GetAllSigningPaths(const std::string& script) {
  std::string keypath;
  auto node = GetScriptNode(script, keypath);
  return get_all_paths(node);
}

std::string Utils::ExpandingMultisigMiniscriptTemplate(
    int m, int n, int new_n, bool reuse_signers, const Timelock& timelock,
    AddressType address_type) {
  if (n >= new_n) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "n must be less than new n");
  }
  return FlexibleMultisigMiniscriptTemplate(m, n, m, new_n, reuse_signers,
                                            timelock, address_type);
}

std::string Utils::DecayingMultisigMiniscriptTemplate(
    int m, int n, int new_m, bool reuse_signers, const Timelock& timelock,
    AddressType address_type) {
  if (m <= new_m) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "new m must be less than m");
  }
  return FlexibleMultisigMiniscriptTemplate(m, n, new_m, n, reuse_signers,
                                            timelock, address_type);
}

std::string Utils::FlexibleMultisigMiniscriptTemplate(
    int m, int n, int new_m, int new_n, bool reuse_signers,
    const Timelock& timelock, AddressType address_type) {
  if (m > n) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "m must be less than or equal to n");
  }
  if (new_m > new_n) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "new m must be less than or equal to new n");
  }
  std::stringstream temp;
  if (address_type == AddressType::TAPROOT) {
    temp << "{multi_a(" << m;
    for (int i = 0; i < n; i++) temp << ",key_" << i << "_0";
    temp << "),and_v(v:multi_a(" << new_m;

    int start_index = reuse_signers ? 0 : n;
    for (int i = start_index; i < start_index + new_n; i++)
      temp << ",key_" << i << "_0";
    temp << ")," << timelock.to_miniscript() << ")}";
  } else {
    temp << "andor(ln:" << timelock.to_miniscript();
    temp << ",multi(" << new_m;
    int start_index = reuse_signers ? 0 : n;
    for (int i = start_index; i < start_index + new_n; i++)
      temp << ",key_" << i << (reuse_signers && i < n ? "_1" : "_0");
    temp << "),multi(" << m;

    for (int i = 0; i < n; i++) temp << ",key_" << i << "_0";
    temp << "))";
  }
  return temp.str();
}

std::vector<UnspentOutput> Utils::GetTimelockedCoins(
    const std::string& miniscript, const std::vector<UnspentOutput>& coins,
    int64_t& max_lock_value, int chain_tip) {
  std::string keypath;
  auto node = Utils::GetScriptNode(miniscript, keypath);
  std::vector<UnspentOutput> rs{};
  for (auto&& coin : coins) {
    if (!node.is_locked(coin, chain_tip, max_lock_value)) {
      rs.emplace_back(coin);
    }
  }
  return rs;
}

std::vector<CoinsGroup> Utils::GetCoinsGroupedBySubPolicies(
    const ScriptNode& script_node, const std::vector<UnspentOutput>& coins,
    int chain_tip) {
  if (script_node.get_type() != ScriptNode::Type::ANDOR &&
      script_node.get_type() != ScriptNode::Type::OR &&
      script_node.get_type() != ScriptNode::Type::OR_TAPROOT &&
      script_node.get_type() != ScriptNode::Type::THRESH) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid script node");
  }
  std::vector<CoinsGroup> rs{};
  for (int i = 0; i < script_node.get_subs().size(); i++) {
    rs.push_back(CoinsGroup{std::vector<UnspentOutput>{}, TimeRange{0, 0}});
  }

  for (auto&& coin : coins) {
    for (int i = 0; i < script_node.get_subs().size(); i++) {
      int64_t max_lock = 0;
      if (script_node.get_subs()[i].is_locked(coin, chain_tip, max_lock)) {
        rs[i].first.emplace_back(coin);
      }
      rs[i].second.first = max_lock;
    }
  }
  return rs;
}

}  // namespace nunchuk
