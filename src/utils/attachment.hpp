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

#ifndef NUNCHUK_ATTACHMENT_H
#define NUNCHUK_ATTACHMENT_H

#include <nunchuk.h>
#include <boost/algorithm/string.hpp>
#include <sstream>
#include <iostream>
#include <fstream>
#include <regex>

#include <util/strencodings.h>
#include <random.h>
#include <crypto/sha256.h>
#include <crypto/aes.h>

#include <utils/json.hpp>
#include <utils/loguru.hpp>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <utils/httplib.h>

namespace {

static const std::string DEFAULT_MATRIX_SERVER = "https://matrix.nunchuk.io";

inline std::vector<unsigned char> DownloadAttachment(const std::string& url) {
  auto id = url.substr(5);
  std::string body;
  httplib::Client cli(DEFAULT_MATRIX_SERVER.c_str());
  auto res = cli.Get(("/_matrix/media/r0/download" + id).c_str(),
                     [&](const char* data, size_t data_length) {
                       body.append(data, data_length);
                       return true;
                     });
  if (!res || res->status != 200) {
    throw nunchuk::NunchukException(
        nunchuk::NunchukException::SERVER_REQUEST_ERROR, "download file error");
  }
  return std::vector<unsigned char>(body.begin(), body.end());
}

inline std::string UploadAttachment(const std::string& accessToken,
                                    const char* body, size_t length) {
  std::string auth = (std::string("Bearer ") + accessToken);
  httplib::Headers headers = {{"Authorization", auth}};
  httplib::Client cli(DEFAULT_MATRIX_SERVER.c_str());
  auto res = cli.Post("/_matrix/media/r0/upload", headers, body, length,
                      "application/octet-stream");
  if (!res || res->status != 200) {
    throw nunchuk::NunchukException(
        nunchuk::NunchukException::SERVER_REQUEST_ERROR, "upload file error");
  }
  return res->body;
}

inline std::vector<unsigned char> LoadAttachmentFile(const std::string& path) {
  std::ifstream infile(path, std::ios_base::binary);
  return std::vector<unsigned char>{std::istreambuf_iterator<char>(infile),
                                    std::istreambuf_iterator<char>()};
}

inline std::string DecryptAttachment(
    const std::vector<unsigned char>& file_data,
    const std::string& event_file) {
  using json = nlohmann::json;
  json file = json::parse(event_file);
  if ("v3" != file["v"].get<std::string>()) {
    throw nunchuk::NunchukException(
        nunchuk::NunchukException::VERSION_NOT_SUPPORTED,
        "version not supported");
  }

  auto key = DecodeBase64(file["key"]["k"].get<std::string>().c_str());
  auto iv = DecodeBase64(file["iv"].get<std::string>().c_str());

  std::vector<unsigned char> decrypted(file_data.size());
  AES256CBCDecrypt dec(key.data(), iv.data(), true);
  int size = dec.Decrypt(file_data.data(), file_data.size(), decrypted.data());
  decrypted.resize(size);
  return std::string(decrypted.begin(), decrypted.end());
}

inline std::string DecryptAttachment(
    const nunchuk::DownloadFileFunc& downloadfunc,
    const std::string& event_file) {
  using json = nlohmann::json;
  json file = json::parse(event_file);
  if ("v3" != file["v"].get<std::string>()) {
    throw nunchuk::NunchukException(
        nunchuk::NunchukException::VERSION_NOT_SUPPORTED,
        "version not supported");
  }

  auto buf = downloadfunc("Backup", "application/octet-stream", event_file,
                          file["url"]);
  if (buf.empty()) return "";
  return DecryptAttachment(buf, event_file);
}

inline std::string EncryptAttachment(const nunchuk::UploadFileFunc& uploadfunc,
                                     const std::string& body) {
  using json = nlohmann::json;
  json file;
  file["v"] = "v3";

  std::vector<unsigned char> key(32, 0);
  GetStrongRandBytes(key.data(), 32);
  file["key"] = {{"alg", "A256CBC"},
                 {"ext", true},
                 {"k", EncodeBase64(key)},
                 {"key_ops", {"encrypt", "decrypt"}},
                 {"kty", "oct"}};

  std::vector<unsigned char> iv(16, 0);
  GetStrongRandBytes(iv.data(), 8);
  file["iv"] = EncodeBase64(iv);
  iv.resize(8);

  std::vector<unsigned char> buf(body.begin(), body.end());
  std::vector<unsigned char> encrypted(buf.size() + 16);
  AES256CBCEncrypt enc(key.data(), iv.data(), true);
  int size = enc.Encrypt(buf.data(), buf.size(), encrypted.data());
  encrypted.resize(size);

  CSHA256 hasher;
  hasher.Write(&encrypted[0], encrypted.size());
  uint256 hash;
  hasher.Finalize(hash.begin());

  file["hashes"] = {{"sha256", EncodeBase64(hash)}};
  file["mimetype"] = "application/octet-stream";
  auto url = uploadfunc("Backup", file["mimetype"], file.dump(),
                        (char*)(&encrypted[0]), encrypted.size());
  if (url.empty()) return "";

  file["url"] = url;
  return file.dump();
}

inline std::string DecryptTxId(const std::string& descriptor,
                               const std::string& encrypted) {
  using json = nlohmann::json;
  json file = json::parse(encrypted);
  if ("v2" != file["v"].get<std::string>()) {
    throw nunchuk::NunchukException(
        nunchuk::NunchukException::VERSION_NOT_SUPPORTED,
        "version not supported");
  }

  std::vector<unsigned char> key(32, 0);
  CSHA256 hasher;
  std::vector<unsigned char> stream(descriptor.begin(), descriptor.end());
  hasher.Write((unsigned char*)&(*stream.begin()),
               stream.end() - stream.begin());
  hasher.Finalize(key.data());

  auto iv = DecodeBase64(file["iv"].get<std::string>().c_str());
  auto buf = DecodeBase64(file["d"].get<std::string>().c_str());

  std::vector<unsigned char> decrypted(buf.size());
  AES256CBCDecrypt dec(key.data(), iv.data(), true);
  int size = dec.Decrypt(buf.data(), buf.size(), decrypted.data());
  decrypted.resize(size);
  return std::string(decrypted.begin(), decrypted.end());
}

inline std::string EncryptTxId(const std::string& descriptor,
                               const std::string& txId) {
  using json = nlohmann::json;
  json encrypted;
  encrypted["v"] = "v2";

  std::vector<unsigned char> key(32, 0);
  CSHA256 hasher;
  std::vector<unsigned char> stream(descriptor.begin(), descriptor.end());
  hasher.Write((unsigned char*)&(*stream.begin()),
               stream.end() - stream.begin());
  hasher.Finalize(key.data());

  std::vector<unsigned char> iv(16, 0);
  GetStrongRandBytes(iv.data(), 8);
  encrypted["iv"] = EncodeBase64(iv);
  iv.resize(8);

  std::vector<unsigned char> buf(txId.begin(), txId.end());
  std::vector<unsigned char> ciphertext(buf.size() + 16);
  AES256CBCEncrypt enc(key.data(), iv.data(), true);
  int size = enc.Encrypt(buf.data(), buf.size(), ciphertext.data());
  ciphertext.resize(size);
  encrypted["d"] = EncodeBase64(ciphertext);
  return encrypted.dump();
}

}  // namespace

#endif  // NUNCHUK_ATTACHMENT_H