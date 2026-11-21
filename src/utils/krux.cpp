#include "krux.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <string_view>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <zlib.h>

extern "C" {
#include <bip39.h>
}

#include "crypto/sha256.h"
#include "nunchuk.h"
#include "support/allocators/secure.h"
#include "util/strencodings.h"
#include "utils/json.hpp"

namespace nunchuk {
namespace {

using SecureBytes = std::vector<unsigned char, secure_allocator<unsigned char>>;

struct KruxCipher {
  const EVP_CIPHER* cipher = nullptr;
  int version = 0;
  int iv_size = 0;
  int auth_size = 0;
  bool pkcs_pad = false;
  bool null_pad = true;
  bool compressed = false;
  bool gcm = false;
};

[[noreturn]] void InvalidBackup() {
  throw NunchukException(NunchukException::INVALID_PARAMETER,
                         "Invalid Krux backup or decryption key");
}

std::vector<unsigned char> DecodeKruxQR(
    const std::vector<unsigned char>& data) {
  constexpr std::string_view alphabet =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:";
  if (!std::all_of(data.begin(), data.end(), [&](unsigned char c) {
        return alphabet.find(c) != std::string_view::npos;
      })) {
    return data;
  }
  std::vector<unsigned char> decoded;
  for (unsigned char c : data) {
    unsigned int carry = alphabet.find(c);
    for (auto& byte : decoded) {
      carry += byte * 43;
      byte = carry & 0xff;
      carry >>= 8;
    }
    while (carry) {
      decoded.push_back(carry & 0xff);
      carry >>= 8;
    }
  }
  decoded.insert(decoded.end(),
                 std::find_if(data.begin(), data.end(),
                              [](unsigned char c) { return c != '0'; }) -
                     data.begin(),
                 0);
  std::reverse(decoded.begin(), decoded.end());
  return decoded;
}

KruxCipher GetKruxCipher(int version, bool legacy) {
  KruxCipher config;
  config.version = version;
  config.compressed =
      version == 7 || version == 12 || version == 16 || version == 21;
  config.gcm = version == 20 || version == 21;
  switch (version) {
    case 0:
    case 5:
    case 6:
    case 7:
      config.cipher = EVP_aes_256_ecb();
      config.auth_size = version == 0 ? -16 : (version == 5 ? 3 : -4);
      config.pkcs_pad = version >= 6;
      break;
    case 1:
    case 10:
    case 11:
    case 12:
      config.cipher = EVP_aes_256_cbc();
      config.iv_size = 16;
      config.auth_size = version == 1 ? -16 : (version == 10 ? 4 : -4);
      config.pkcs_pad = version >= 11;
      break;
    case 15:
    case 16:
    case 20:
    case 21:
      config.cipher = config.gcm ? EVP_aes_256_gcm() : EVP_aes_256_ctr();
      config.iv_size = 12;
      config.auth_size = config.gcm ? 4 : -4;
      config.null_pad = false;
      break;
    default:
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Unsupported Krux backup version");
  }
  if (legacy) {
    if (version != 0 && version != 1) InvalidBackup();
    config.auth_size = 0;
  }
  config.null_pad = config.null_pad && !config.pkcs_pad;
  return config;
}

SecureBytes DeriveKruxKey(const std::string& password, const std::string& salt,
                          int iterations) {
  if (iterations < 10000 || iterations > 100000000 ||
      password.size() > std::numeric_limits<int>::max() ||
      salt.size() > std::numeric_limits<int>::max()) {
    InvalidBackup();
  }
  SecureBytes key(32);
  if (PKCS5_PBKDF2_HMAC(password.data(), password.size(),
                        reinterpret_cast<const unsigned char*>(salt.data()),
                        salt.size(), iterations, EVP_sha256(), key.size(),
                        key.data()) != 1) {
    InvalidBackup();
  }
  return key;
}

int GetKruxCiphertextSize(const std::vector<unsigned char>& payload,
                          const KruxCipher& config) {
  const int public_auth_size = std::max(config.auth_size, 0);
  if (payload.size() <= config.iv_size + public_auth_size ||
      payload.size() > 1024) {
    InvalidBackup();
  }
  const int encrypted_size = payload.size() - config.iv_size - public_auth_size;
  if ((config.null_pad || config.pkcs_pad) && encrypted_size % 16 != 0) {
    InvalidBackup();
  }
  return encrypted_size;
}

SecureBytes DecryptKruxPayload(const std::vector<unsigned char>& payload,
                               const KruxCipher& config, const SecureBytes& key,
                               int encrypted_size) {
  const int public_auth_size = std::max(config.auth_size, 0);
  std::array<unsigned char, 16> iv{};
  std::copy_n(payload.begin(), config.iv_size, iv.begin());
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
      EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!ctx || EVP_DecryptInit_ex(ctx.get(), config.cipher, nullptr, key.data(),
                                 config.iv_size ? iv.data() : nullptr) != 1 ||
      EVP_CIPHER_CTX_set_padding(ctx.get(), config.pkcs_pad) != 1) {
    InvalidBackup();
  }
  if (config.gcm &&
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, public_auth_size,
                          const_cast<unsigned char*>(payload.data() +
                                                      payload.size() -
                                                      public_auth_size)) != 1) {
    InvalidBackup();
  }
  SecureBytes plain(encrypted_size + 16);
  int written = 0, final_size = 0;
  if (EVP_DecryptUpdate(ctx.get(), plain.data(), &written,
                        payload.data() + config.iv_size, encrypted_size) != 1 ||
      EVP_DecryptFinal_ex(ctx.get(), plain.data() + written, &final_size) != 1) {
    InvalidBackup();
  }
  plain.resize(written + final_size);
  return plain;
}

bool AuthenticateKruxPayload(const std::vector<unsigned char>& payload,
                              const KruxCipher& config, const SecureBytes& key,
                              const SecureBytes& plain, size_t size) {
  if (config.gcm) return true;
  CSHA256 hasher;
  const unsigned char version_byte = config.version;
  if (config.auth_size > 0) {
    hasher.Write(&version_byte, 1).Write(payload.data(), config.iv_size);
  }
  hasher.Write(plain.data(), size);
  if (config.auth_size > 0) hasher.Write(key.data(), key.size());
  std::array<unsigned char, 32> hash{};
  hasher.Finalize(hash.data());
  const unsigned char* auth =
      config.auth_size > 0
          ? payload.data() + payload.size() - config.auth_size
          : plain.data() + size;
  const int auth_size =
      config.auth_size > 0 ? config.auth_size : -config.auth_size;
  return CRYPTO_memcmp(hash.data(), auth, auth_size) == 0;
}

std::string InflateKruxMnemonic(SecureBytes& plain, size_t size) {
  SecureBytes entropy(33);
  z_stream stream{};
  stream.next_in = plain.data();
  stream.avail_in = size;
  stream.next_out = entropy.data();
  stream.avail_out = entropy.size();
  if (inflateInit2(&stream, -10) != Z_OK) InvalidBackup();
  const int result = inflate(&stream, Z_FINISH);
  inflateEnd(&stream);
  if (result != Z_STREAM_END || stream.avail_in != 0 ||
      stream.total_out < 16 || stream.total_out > 32 ||
      stream.total_out % 4 != 0) {
    InvalidBackup();
  }
  return mnemonic_from_data(entropy.data(), stream.total_out);
}

std::string DecodeKruxMnemonic(const std::vector<unsigned char>& payload,
                               const KruxCipher& config, const SecureBytes& key,
                               SecureBytes& plain) {
  const size_t encrypted_auth_size = std::max(-config.auth_size, 0);
  if (config.compressed) {
    if (plain.size() <= encrypted_auth_size) InvalidBackup();
    const size_t size = plain.size() - encrypted_auth_size;
    if (!AuthenticateKruxPayload(payload, config, key, plain, size)) {
      InvalidBackup();
    }
    return InflateKruxMnemonic(plain, size);
  }

  // Preserve trailing zeros in entropy/checksums when removing NUL padding.
  for (size_t size = 16; size <= 32; size += 4) {
    const size_t content_size = size + encrypted_auth_size;
    const size_t padded_size = (content_size + 15) / 16 * 16;
    if (plain.size() != (config.null_pad ? padded_size : content_size)) continue;
    if (config.null_pad &&
        !std::all_of(plain.begin() + content_size, plain.end(),
                     [](unsigned char c) { return c == 0; })) {
      continue;
    }
    if (!AuthenticateKruxPayload(payload, config, key, plain, size)) {
      continue;
    }
    return mnemonic_from_data(plain.data(), size);
  }
  InvalidBackup();
}

std::string DecryptKrux(const std::vector<unsigned char>& payload,
                        const std::string& password, const std::string& salt,
                        int version, int iterations, bool legacy) {
  const auto config = GetKruxCipher(version, legacy);
  const int encrypted_size = GetKruxCiphertextSize(payload, config);
  const auto key = DeriveKruxKey(password, salt, iterations);
  auto plain = DecryptKruxPayload(payload, config, key, encrypted_size);
  if (legacy) {
    while (!plain.empty() && plain.back() == 0) plain.pop_back();
    std::string mnemonic(plain.begin(), plain.end());
    if (!Utils::CheckMnemonic(mnemonic)) InvalidBackup();
    return mnemonic;
  }
  return DecodeKruxMnemonic(payload, config, key, plain);
}

std::string DecryptKruxEnvelope(const std::vector<unsigned char>& envelope,
                                const std::string& password) {
  if (envelope.empty()) InvalidBackup();
  const size_t id_size = envelope[0];
  if (envelope.size() < id_size + 5) InvalidBackup();
  const std::string salt(envelope.begin() + 1, envelope.begin() + 1 + id_size);
  const int version = envelope[id_size + 1];
  int iterations = (envelope[id_size + 2] << 16) |
                   (envelope[id_size + 3] << 8) | envelope[id_size + 4];
  if (iterations <= 10000) iterations *= 10000;
  return DecryptKrux(
      std::vector<unsigned char>(envelope.begin() + id_size + 5, envelope.end()),
      password, salt, version, iterations, false);
}

std::string DecryptKruxJsonBackup(const nlohmann::json& seeds,
                                  const std::string& password,
                                  const std::string& mnemonic_id) {
  try {
    if (seeds.empty()) InvalidBackup();
    if (mnemonic_id.empty() && seeds.size() != 1) {
      throw NunchukException(NunchukException::INVALID_PARAMETER,
                             "Select a mnemonic ID from the Krux backup");
    }
    auto entry = mnemonic_id.empty() ? seeds.begin() : seeds.find(mnemonic_id);
    if (entry == seeds.end() || !entry->is_object()) InvalidBackup();
    const bool kef = entry->contains("b64_kef");
    auto decoded = DecodeBase64(
        entry->at(kef ? "b64_kef" : "data").get<std::string>());
    if (!decoded) InvalidBackup();
    if (kef) return DecryptKruxEnvelope(*decoded, password);

    const auto& version = entry->at("version");
    const auto& iterations = entry->at("key_iterations");
    if (!version.is_number_integer() || (version != 0 && version != 1) ||
        !iterations.is_number_integer() || iterations < 10000 ||
        iterations > 100000000) {
      InvalidBackup();
    }
    return DecryptKrux(*decoded, password, entry.key(), version.get<int>(),
                       iterations.get<int>(), true);
  } catch (const nlohmann::json::exception&) {
    InvalidBackup();
  }
}

}  // namespace

std::string ExtractKruxBackup(const std::vector<unsigned char>& data,
                              const std::string& password,
                              const std::string& mnemonic_id) {
  if (data.empty()) InvalidBackup();
  const auto seeds = nlohmann::json::parse(data.begin(), data.end(), nullptr, false);
  if (seeds.is_object()) {
    return DecryptKruxJsonBackup(seeds, password, mnemonic_id);
  }
  if (data.size() > 1024) InvalidBackup();
  return DecryptKruxEnvelope(DecodeKruxQR(data), password);
}

}  // namespace nunchuk
