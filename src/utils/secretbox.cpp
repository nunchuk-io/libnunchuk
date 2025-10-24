/*
 * This file is part of the Nunchuk software (https://nunchuk.io/)
 * Copyright (C) 2022, 2023 Nunchuk
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "secretbox.h"
#include <cstring>
#include <iostream>
#include <util/strencodings.h>
#include <utils/stringutils.hpp>
#include <random.h>

extern "C" {
void randombytes(unsigned char *buf, unsigned long long len) {
  std::span<unsigned char> bytes(buf, len);
  GetStrongRandBytes(bytes);
}
#include <utils/tweetnacl.h>
}

namespace nunchuk {

Secretbox::Secretbox(const std::vector<unsigned char> &key) : key_(key) {
  if (key_.size() != crypto_secretbox_KEYBYTES) {
    throw std::runtime_error("Incorrect key length");
  }
}

std::string Secretbox::Box(const std::string &plain) {
  std::vector<unsigned char> m(crypto_secretbox_ZEROBYTES, 0);
  m.insert(m.end(), plain.begin(), plain.end());
  std::vector<unsigned char> c(m.size(), 0);
  std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES, 0);
  randombytes(nonce.data(), nonce.size());
  crypto_secretbox(c.data(), m.data(), m.size(), nonce.data(), key_.data());
  std::vector<unsigned char> cipher(c.begin() + crypto_secretbox_BOXZEROBYTES,
                                    c.end());
  return EncodeBase64(nonce) + "." + EncodeBase64(cipher);
}

std::string Secretbox::Open(const std::string &box) {
  auto part = split(box, '.');
  auto nonce = DecodeBase64(part[0].c_str());
  if (!nonce) {
    throw std::runtime_error("Invalid nonce");
  }
  auto cipher = DecodeBase64(part[1].c_str());
  if (!cipher) {
    throw std::runtime_error("Invalid cipher");
  }

  std::vector<unsigned char> c(crypto_secretbox_BOXZEROBYTES, 0);
  c.insert(c.end(), cipher->begin(), cipher->end());
  std::vector<unsigned char> m(c.size(), 0);

  if (crypto_secretbox_open(m.data(), c.data(), c.size(), nonce->data(),
                            key_.data()) != 0) {
    throw std::runtime_error("Fails verification");
  }
  std::string rs(m.begin() + crypto_secretbox_ZEROBYTES, m.end());
  return rs;
}

std::pair<std::string, std::string> Publicbox::GenerateKeyPair() {
  std::vector<unsigned char> skey(crypto_box_SECRETKEYBYTES, 0);
  std::vector<unsigned char> pkey(crypto_box_PUBLICKEYBYTES, 0);
  crypto_box_keypair(pkey.data(), skey.data());
  return {EncodeBase64(pkey), EncodeBase64(skey)};
}

Publicbox::Publicbox(const std::string &pkey, const std::string &skey)
    : pkey_(*DecodeBase64(pkey)), skey_(*DecodeBase64(skey)) {
  if (skey_.size() != crypto_box_SECRETKEYBYTES ||
      pkey_.size() != crypto_box_PUBLICKEYBYTES) {
    throw std::runtime_error("Incorrect key length");
  }
}

std::string Publicbox::Box(const std::string &plain, const std::string &pkey) {
  auto receiver_pkey = DecodeBase64(pkey);
  if (!receiver_pkey) {
    throw std::runtime_error("Invalid sender public key");
  }

  std::vector<unsigned char> m(crypto_box_ZEROBYTES, 0);
  m.insert(m.end(), plain.begin(), plain.end());
  std::vector<unsigned char> c(m.size(), 0);
  std::vector<unsigned char> nonce(crypto_box_NONCEBYTES, 0);
  randombytes(nonce.data(), nonce.size());
  crypto_box(c.data(), m.data(), m.size(), nonce.data(), receiver_pkey->data(),
             skey_.data());
  std::vector<unsigned char> cipher(c.begin() + crypto_box_BOXZEROBYTES,
                                    c.end());
  return EncodeBase64(pkey_) + "." + EncodeBase64(nonce) + "." +
         EncodeBase64(cipher);
}

std::string Publicbox::Open(const std::string &box) {
  auto part = split(box, '.');
  auto sender_pkey = DecodeBase64(part[0].c_str());
  if (!sender_pkey) {
    throw std::runtime_error("Invalid sender public key");
  }
  auto nonce = DecodeBase64(part[1].c_str());
  if (!nonce) {
    throw std::runtime_error("Invalid nonce");
  }
  auto cipher = DecodeBase64(part[2].c_str());
  if (!cipher) {
    throw std::runtime_error("Invalid cipher");
  }

  std::vector<unsigned char> c(crypto_box_BOXZEROBYTES, 0);
  c.insert(c.end(), cipher->begin(), cipher->end());
  std::vector<unsigned char> m(c.size(), 0);

  if (crypto_box_open(m.data(), c.data(), c.size(), nonce->data(),
                      sender_pkey->data(), skey_.data()) != 0) {
    throw std::runtime_error("Fails verification");
  }
  std::string rs(m.begin() + crypto_box_ZEROBYTES, m.end());
  return rs;
}

}  // namespace nunchuk
