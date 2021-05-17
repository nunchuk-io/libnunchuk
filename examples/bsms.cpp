
#include <nunchuk.h>
#include <random.h>

extern "C" {
#include <bip39.h>
#include <pbkdf2.h>
// #include <sha2.h>
#include <hmac.h>
#include <aes/aes.h>

// void random_buffer(uint8_t* buf, size_t len) { GetStrongRandBytes(buf, len);
// }
}

#include <iostream>
#include <sstream>
#include <iomanip>

#include <key_io.h>
#include <key.h>
#include <util/message.h>

#include <descriptor.h>
#include <utils/loguru.hpp>
#include <coreutils.h>

std::string hexStr(const uint8_t* data, int len) {
  std::stringstream ss;
  ss << std::hex;

  for (int i(0); i < len; ++i)
    ss << std::setw(2) << std::setfill('0') << (int)data[i];

  return ss.str();
}

std::vector<uint8_t> generate(size_t entropy) {
  std::vector<uint8_t> bts(entropy / 8);
  GetStrongRandBytes(bts.data(), bts.size());
  return bts;
}

nunchuk::SingleSigner round1_signer(int id, const std::string& hex_token,
                                    const uint8_t encryption_key[256 / 8],
                                    nunchuk::Chain chain,
                                    nunchuk::AddressType addressType,
                                    bool escrow) {
  std::cout << "\n## Signer " << id + 1 << std::endl;
  if (hex_token != "00") {
    std::cout << "- ENCRYPTION_KEY (hex): " << hexStr(encryption_key, 32)
              << std::endl;
  }

  uint8_t seed[512 / 8];
  auto entropy = generate(256).data();
  auto words = mnemonic_from_data(entropy, 256 / 8);
  mnemonic_to_seed(words, "", seed, nullptr);

  // KEY_RECORD
  CExtKey bip32rootkey{};
  bip32rootkey.SetSeed(seed, 512 / 8);

  CExtKey masterkey{};
  bip32rootkey.Derive(masterkey, 0);
  std::string master_fingerprint = hexStr(masterkey.vchFingerprint, 4);
  std::cout << "- MASTER_KEY_FINGERPRINT: " << master_fingerprint << std::endl;

  int coinType = chain == nunchuk::Chain::MAIN ? 0 : 1;
  int scriptType = addressType == nunchuk::AddressType::NATIVE_SEGWIT ? 2 : 1;

  std::stringstream path_builder;
  path_builder << "/48'/" << coinType << "'/0'/" << scriptType << "'";
  std::string path = path_builder.str();

  CExtKey xkey{};
  bip32rootkey.Derive(xkey, 48 | 0x80000000);
  xkey.Derive(xkey, coinType | 0x80000000);
  xkey.Derive(xkey, 0 | 0x80000000);
  xkey.Derive(xkey, scriptType | 0x80000000);
  std::string xpub = EncodeExtPubKey(xkey.Neuter());
  std::string pubkey = HexStr(xkey.Neuter().pubkey);
  std::cout << "- PRIVATE_KEY (m" << path << "): " << EncodeSecret(xkey.key)
            << std::endl;
  if (escrow) {
    std::cout << "- PUBKEY (m" << path << "): " << pubkey << std::endl;
  } else {
    std::cout << "- XPUB (m" << path << "): " << xpub << std::endl;
  }

  std::stringstream key_record;
  key_record << "BSMS 1.0" << std::endl;
  key_record << hex_token << std::endl;
  key_record << "[" << master_fingerprint << path << "]"
             << (escrow ? pubkey : xpub) << std::endl;
  key_record << "Signer " << id + 1 << " key";

  std::string signature;
  MessageSign(xkey.key, key_record.str(), signature);
  key_record << std::endl << signature;

  std::string key_record_str = key_record.str();
  std::cout << "- KEY_RECORD: \n\n```\n" << key_record_str << "\n```\n\n";

  if (hex_token != "00") {
    // HMAC
    uint8_t hmac_key[32];
    sha256_Raw(encryption_key, 32, hmac_key);
    std::cout << "- HMAC_KEY (hex): " << hexStr(hmac_key, 32) << std::endl;

    auto data = hex_token + key_record_str;
    std::vector<uint8_t> hmac_data(data.begin(), data.end());
    uint8_t hmac[256 / 8];
    hmac_sha256(hmac_key, 32, &hmac_data[0], data.length(), hmac);
    auto hex_hmac = hexStr(hmac, 32);
    std::cout << "- MAC (hex): " << hex_hmac << std::endl;

    // Encrypt
    std::vector<uint8_t> plaintext(key_record_str.begin(),
                                   key_record_str.end());
    unsigned char ciphertext[plaintext.size()];
    aes_encrypt_ctx cx[1];
    aes_init();
    aes_encrypt_key256(encryption_key, cx);
    aes_ctr_crypt(&plaintext[0], ciphertext, plaintext.size(), hmac,
                  aes_ctr_cbuf_inc, cx);
    std::cout << "- CIPHERTEXT (hex): " << hexStr(ciphertext, plaintext.size())
              << std::endl;
    std::cout << "- RESULT (hex): "
              << hex_hmac + hexStr(ciphertext, plaintext.size()) << std::endl;
  }

  return {"signer", xpub, {}, "m" + path, master_fingerprint, 0};
}

void round2_coordinator(int id, const std::string& descriptor_record_str,
                        const std::string& hex_token,
                        const uint8_t encryption_key[256 / 8]) {
  if (hex_token == "00") return;

  std::cout << "\n## Send to Signer " << id + 1 << std::endl;

  uint8_t hmac_key[32];
  sha256_Raw(encryption_key, 32, hmac_key);
  std::cout << "- HMAC_KEY (hex): " << hexStr(hmac_key, 32) << std::endl;

  auto data2 = hex_token + descriptor_record_str;
  std::vector<uint8_t> hmac_data2(data2.begin(), data2.end());
  uint8_t hmac2[256 / 8];
  hmac_sha256(hmac_key, 32, &hmac_data2[0], data2.length(), hmac2);
  auto hex_hmac = hexStr(hmac2, 32);
  std::cout << "- MAC (hex): " << hex_hmac << std::endl;

  std::vector<uint8_t> plaintext2(descriptor_record_str.begin(),
                                  descriptor_record_str.end());

  unsigned char ciphertext2[plaintext2.size()];
  aes_encrypt_ctx cx[1];
  aes_init();
  aes_encrypt_key256(encryption_key, cx);
  aes_ctr_crypt(&plaintext2[0], ciphertext2, plaintext2.size(), hmac2,
                aes_ctr_cbuf_inc, cx);
  std::cout << "- CIPHERTEXT (hex): " << hexStr(ciphertext2, plaintext2.size())
            << std::endl;
  std::cout << "- RESULT (hex): "
            << hex_hmac + hexStr(ciphertext2, plaintext2.size()) << std::endl;
}

int main(int argc, char** argv) {
  // Config
  if (argc != 10) {
    std::cout << "./bip39 network m n tokenlen sametoken addresstype "
                 "sortedmulti restrictpath escrow"
              << std::endl;
    std::cout << "        network:  main, test" << std::endl;
    std::cout << "       tokenlen:  0, 64, 96" << std::endl;
    std::cout << "      sametoken:  true, false" << std::endl;
    std::cout << "    addresstype:  native, nested, legacy" << std::endl;
    std::cout << "    sortedmulti:  true (sortedmulti), false (multi)"
              << std::endl;
    std::cout << "   restrictpath:  true, false (No path restrictions)"
              << std::endl;
    std::cout << "         escrow:  true (pubkey), false (xpub)" << std::endl;
    std::cout << "\nExample: ./bip39 main 2 5 96 false native true true false"
              << std::endl;
    return 1;
  }

  int M = std::stoi(std::string(argv[2]));
  int N = std::stoi(std::string(argv[3]));
  if (M > N) {
    std::cout << "Invalid M/N: " << M << "/" << N << std::endl;
    std::cout << "M must less than or equal N" << std::endl;
    return 1;
  }

  size_t token_len = std::stoi(std::string(argv[4]));

  nunchuk::Chain chain = nunchuk::Chain::MAIN;
  if (std::string(argv[1]) == "main")
    chain = nunchuk::Chain::MAIN;
  else if (std::string(argv[1]) == "test")
    chain = nunchuk::Chain::TESTNET;
  else {
    std::cout << "Invalid network type: " << argv[1] << std::endl;
    std::cout << "Valid value: main, test" << std::endl;
    return 1;
  }

  nunchuk::AddressType addressType = nunchuk::AddressType::NATIVE_SEGWIT;
  if (std::string(argv[6]) == "nested")
    addressType = nunchuk::AddressType::NESTED_SEGWIT;
  else if (std::string(argv[6]) == "legacy")
    addressType = nunchuk::AddressType::LEGACY;
  else if (std::string(argv[6]) == "native")
    addressType = nunchuk::AddressType::NATIVE_SEGWIT;
  else {
    std::cout << "Invalid address type: " << argv[6] << std::endl;
    std::cout << "Valid value: native, nested, legacy" << std::endl;
    return 1;
  }

  bool sametoken = std::string(argv[5]) == "true";
  bool sorted = std::string(argv[7]) == "true";
  bool retrictpath = std::string(argv[8]) == "true";
  bool escrow = std::string(argv[9]) == "true";

  // Start
  loguru::g_stderr_verbosity = loguru::Verbosity_OFF;
  nunchuk::Utils::SetChain(chain);
  // ECC_Start();

  std::cout << "# ROUND 1" << std::endl;

  std::cout << "\n## Coordinator" << std::endl;
  std::cout << "- M-of-N: " << M << "/" << N << std::endl;
  std::cout << "- ADDRESS_TYPE: "
            << (addressType == nunchuk::AddressType::NATIVE_SEGWIT
                    ? "NATIVE_SEGWIT"
                    : (addressType == nunchuk::AddressType::NESTED_SEGWIT
                           ? "NESTED_SEGWIT"
                           : "LEGACY"))
            << std::endl;

  // TOKEN and ENCRYPTION_KEY
  std::vector<std::string> hex_tokens{};
  std::vector<nunchuk::SingleSigner> signers{};
  uint8_t encryption_keys[N][256 / 8];

  static const unsigned char password[] = {'N', 'o', ' ', 'S', 'P', 'O', 'F'};
  auto token = generate(token_len);

  for (int i = 0; i < N; i++) {
    if (token_len == 0) {
      hex_tokens.push_back("00");
      continue;
    }

    if (!sametoken) token = generate(token_len);

    std::cout << "\n## Send to Signer " << i + 1 << std::endl;

    pbkdf2_hmac_sha512(password, 8, token.data(), token_len / 8, 2048,
                       encryption_keys[i], 32);
    auto hex_token = hexStr(token.data(), token_len / 8);
    std::cout << "- TOKEN (hex): " << hex_token << std::endl;
    std::cout << "- TOKEN (mnemonic): "
              << mnemonic_from_data(token.data(), token_len / 8) << std::endl;

    hex_tokens.push_back(hex_token);
  }

  for (int i = 0; i < N; i++) {
    signers.push_back(round1_signer(i, hex_tokens[i], encryption_keys[i], chain,
                                    addressType, escrow));
  }

  std::cout << "\n\n# ROUND 2" << std::endl;

  std::cout << "\n## Coordinator" << std::endl;

  std::stringstream descriptor_record;
  descriptor_record << "BSMS 1.0" << std::endl;
  descriptor_record << GetDescriptorForSigners(
                           signers, M,
                           retrictpath ? nunchuk::DescriptorPath::TEMPLATE
                                       : nunchuk::DescriptorPath::ANY,
                           addressType,
                           escrow ? nunchuk::WalletType::ESCROW
                                  : nunchuk::WalletType::MULTI_SIG,
                           0, sorted)
                    << std::endl;
  descriptor_record << (retrictpath ? "/0/*,/1/*" : "No path restrictions")
                    << std::endl;
  descriptor_record << nunchuk::CoreUtils::getInstance().DeriveAddresses(
      GetDescriptorForSigners(
          signers, M, nunchuk::DescriptorPath::EXTERNAL_ALL, addressType,
          escrow ? nunchuk::WalletType::ESCROW : nunchuk::WalletType::MULTI_SIG,
          escrow ? -1 : 0, sorted),
      escrow ? -1 : 0);

  std::string descriptor_record_str = descriptor_record.str();
  std::cout << "- DESCRIPTOR_RECORD: \n\n```\n"
            << descriptor_record_str << "\n```\n\n";

  for (int i = 0; i < N; i++) {
    round2_coordinator(i, descriptor_record_str, hex_tokens[i],
                       encryption_keys[i]);
  }
  ECC_Stop();
  return 0;
}
