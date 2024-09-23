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
#include <amount.h>
#include <stdlib.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <boost/format.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <hash.h>
#include <policy/policy.h>

#include <ur.h>
#include <ur-encoder.hpp>
#include <ur-decoder.hpp>
#include <cbor-lite.hpp>
#include <utils/bcr2.hpp>
#include <utils/passport.hpp>

#include <ctime>
#include <iostream>
#include "key_io.h"
#include "tap_protocol/hwi_tapsigner.h"
#include "tap_protocol/tap_protocol.h"
#include "utils/httplib.h"

#include <bbqr/bbqr.hpp>

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
  std::vector<unsigned char> buf(128);

  // GetStrongRandBytes can only generate up to 32 bytes
  for (int cur = 0; cur < buf.size(); cur += 32) {
    GetStrongRandBytes(buf.data() + cur, 32);
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
  AddressType address_type;
  WalletType wallet_type;
  int m;
  int n;
  std::vector<SingleSigner> signers;
  std::string name;

  // Try all possible formats: BSMS, Descriptors, JSON with `descriptor` key,
  // Multisig config
  if (ParseDescriptorRecord(descs, address_type, wallet_type, m, n, signers) ||
      ParseDescriptors(descs, address_type, wallet_type, m, n, signers) ||
      ParseJSONDescriptors(descs, name, address_type, wallet_type, m, n,
                           signers) ||
      ParseUnchainedWallet(descs, name, address_type, wallet_type, m, n,
                           signers) ||
      ParseConfig(Utils::GetChain(), descs, name, address_type, wallet_type, m,
                  n, signers)) {
    std::string id = GetWalletId(signers, m, address_type, wallet_type);
    bool is_escrow = wallet_type == WalletType::ESCROW;
    auto wallet =
        Wallet{id, m, n, signers, address_type, is_escrow, std::time(0)};
    wallet.set_name(name);
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
  AddressType address_type;
  WalletType wallet_type;
  int m;
  int n;
  std::vector<SingleSigner> signers;

  if (decoder.result_ur().type() == "crypto-output") {  // BCR-2020-010
    CryptoOutput output{};
    decodeCryptoOutput(i, end, output);

    address_type = output.addressType;
    wallet_type = output.walletType;
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

    if (!ParseConfig(chain, config_str, name, address_type, wallet_type, m, n,
                     signers)) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Could not parse multisig config");
    }
  }
  std::string id = GetWalletId(signers, m, address_type, wallet_type);
  bool is_escrow = wallet_type == WalletType::ESCROW;

  Wallet wallet{id, m, n, signers, address_type, is_escrow, std::time(0)};
  wallet.set_name(name);
  return wallet;
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
  AddressType address_type;
  WalletType wallet_type;
  int m;
  int n;
  std::vector<SingleSigner> signers;
  if (!ParseConfig(chain, config, name, address_type, wallet_type, m, n,
                   signers)) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Could not parse multisig config");
  }
  std::string id = GetWalletId(signers, m, address_type, wallet_type);
  bool is_escrow = wallet_type == WalletType::ESCROW;
  Wallet wallet{id, m, n, signers, address_type, is_escrow, std::time(0)};
  wallet.set_name(name);
  return wallet;
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

      Wallet wallet({}, 1, 1, {std::move(signer)}, address_type, false,
                    std::time(0));
      wallet.set_name(tmp_name);
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
      DecodePsbt(base64_psbt), wallet.get_signers(), wallet.get_m());
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
  auto tx = GetTransactionFromPartiallySignedTransaction(
      DecodePsbt(psbt), wallet.get_signers(), wallet.get_m());
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
  bool invalid;
  auto data = DecodeBase64(psbt.c_str(), &invalid);
  if (invalid) {
    throw NunchukException(NunchukException::INVALID_PSBT, "Invalid base64");
  }
  bcr2::CryptoPSBT crypto_psbt{data};
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
  bool invalid;
  auto data = DecodeBase64(psbt.c_str(), &invalid);
  if (invalid) {
    throw NunchukException(NunchukException::INVALID_PSBT, "Invalid base64");
  }
  bcr2::CryptoPSBT crypto_psbt{data};
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
  bool invalid;
  auto data = DecodeBase64(psbt.c_str(), &invalid);
  if (invalid) {
    throw NunchukException(NunchukException::INVALID_PSBT, "Invalid base64");
  }
  bbqr::SplitOption option{};
  option.min_version = min_version;
  option.max_version = max_version;
  try {
    auto split_result = bbqr::split_qrs(data, bbqr::FileType::P, option);
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
    if (join_result.file_type != bbqr::FileType::P ||
        !join_result.is_complete) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Invalid data");
    }
    return EncodeBase64(MakeUCharSpan(join_result.raw));
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

}  // namespace nunchuk
