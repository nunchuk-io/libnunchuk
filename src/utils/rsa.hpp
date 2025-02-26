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

#ifndef NUNCHUK_RSA_H
#define NUNCHUK_RSA_H

#include <iostream>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <vector>
#include <fstream>
#include <string.h>
#include <sstream>

#include <utils/stringutils.hpp>
#include <util/strencodings.h>

namespace nunchuk {
namespace rsa {

inline std::pair<std::string, std::string> GenerateKeypair() {
  BIGNUM *bne = BN_new();
  BN_set_word(bne, RSA_F4);

  int bits = 2048;
  RSA *r = RSA_new();
  RSA_generate_key_ex(r, bits, bne, NULL);

  BIO *bp_public = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPublicKey(bp_public, r);
  BIO *bp_private = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

  ssize_t pri_len = BIO_pending(bp_private);
  ssize_t pub_len = BIO_pending(bp_public);
  char *pri_key = (char *)malloc(pri_len + 1);
  char *pub_key = (char *)malloc(pub_len + 1);

  BIO_read(bp_private, pri_key, pri_len);
  BIO_read(bp_public, pub_key, pub_len);

  pri_key[pri_len] = '\0';
  pub_key[pub_len] = '\0';

  std::string pub_str(pub_key);
  std::string pri_str(pri_key);
  free(pri_key);
  free(pub_key);
  BIO_free_all(bp_public);
  BIO_free_all(bp_private);
  BN_free(bne);
  RSA_free(r);
  return {pub_str, pri_str};
}

inline std::string EnvelopeSeal(const std::string &pub_key,
                                const std::string &plain) {
  BIO *pbkeybio = NULL;
  pbkeybio = BIO_new_mem_buf((void *)pub_key.c_str(), pub_key.size());
  RSA *pb_rsa = NULL;
  pb_rsa = PEM_read_bio_RSAPublicKey(pbkeybio, &pb_rsa, NULL, NULL);
  EVP_PKEY *evp_pbkey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(evp_pbkey, pb_rsa);

  std::vector<unsigned char> iv(EVP_MAX_IV_LENGTH, 0);
  unsigned char *encrypted_key =
      (unsigned char *)malloc(EVP_PKEY_size(evp_pbkey));
  int encrypted_key_len = EVP_PKEY_size(evp_pbkey);

  EVP_CIPHER_CTX *ctx;
  int ciphertext_len;
  int len;

  ctx = EVP_CIPHER_CTX_new();
  EVP_SealInit(ctx, EVP_aes_256_cbc(), &encrypted_key, &encrypted_key_len,
               iv.data(), &evp_pbkey, 1);

  int blocksize = EVP_CIPHER_CTX_block_size(ctx);

  unsigned char plaintext[plain.size()];
  int plaintext_len = plain.size();
  strcpy((char *)plaintext, plain.c_str());

  std::vector<unsigned char> cyphered(plaintext_len + blocksize - 1);
  len = cyphered.size();
  EVP_SealUpdate(ctx, &cyphered[0], &len, plaintext, plaintext_len);
  ciphertext_len = len;

  EVP_SealFinal(ctx, &cyphered[0] + len, &len);
  ciphertext_len += len;
  cyphered.resize(ciphertext_len);

  std::string rs =
      EncodeBase64(cyphered) + "-" + EncodeBase64(iv) + "-" +
      EncodeBase64({encrypted_key, encrypted_key + encrypted_key_len});

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  BIO_free(pbkeybio);
  free(encrypted_key);
  EVP_PKEY_free(evp_pbkey);
  return rs;
}

inline std::string Encrypt(const std::string &pub_key,
                           const std::string &input) {
  BIO *pbkeybio = NULL;
  pbkeybio = BIO_new_mem_buf((void *)pub_key.c_str(), pub_key.size());
  RSA *pb_rsa = NULL;
  pb_rsa = PEM_read_bio_RSAPublicKey(pbkeybio, &pb_rsa, NULL, NULL);

  int cipherTextSize = RSA_size(pb_rsa);
  void *plaintext = malloc(cipherTextSize);
  if (plaintext == NULL) {
    throw std::runtime_error(std::string(strerror(errno)));
  }
  memset(plaintext, 0, cipherTextSize);
  void *ciphertext = malloc(cipherTextSize);
  if (ciphertext == NULL) {
    throw std::runtime_error(std::string(strerror(errno)));
  }
  memset(ciphertext, 0, cipherTextSize);

  if (input.size() > (size_t)cipherTextSize) {
    throw std::runtime_error("Data size exceeds the limit");
  }
  memcpy(plaintext, input.data(), input.size());
  if (RSA_public_encrypt(input.size(), (unsigned char *)plaintext,
                         (unsigned char *)ciphertext, pb_rsa,
                         RSA_PKCS1_PADDING) < 0) {
    throw std::runtime_error("Encrypt " + std::string(strerror(errno)));
  }
  Span<unsigned char> cipher{(unsigned char *)ciphertext,
                             (size_t)cipherTextSize};
  std::string output = EncodeBase64(cipher);
  free(ciphertext);
  free(plaintext);

  BIO_free(pbkeybio);
  return output;
}

inline std::string EnvelopeOpen(const std::string &pub_key,
                                const std::string &priv_key,
                                const std::string &cyphered) {
  BIO *pbkeybio = NULL;
  pbkeybio = BIO_new_mem_buf((void *)pub_key.c_str(), pub_key.size());
  RSA *pb_rsa = NULL;
  pb_rsa = PEM_read_bio_RSAPublicKey(pbkeybio, &pb_rsa, NULL, NULL);
  EVP_PKEY *evp_pbkey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(evp_pbkey, pb_rsa);

  BIO *prkeybio = NULL;
  prkeybio = BIO_new_mem_buf((void *)priv_key.c_str(), priv_key.size());
  RSA *p_rsa = NULL;
  p_rsa = PEM_read_bio_RSAPrivateKey(prkeybio, &p_rsa, NULL, NULL);
  EVP_PKEY *evp_prkey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(evp_prkey, p_rsa);

  std::vector<std::string> parts = split(cyphered, '-');
  std::vector<unsigned char> iv = *DecodeBase64(parts[1].c_str());
  std::vector<unsigned char> encrypted_key = *DecodeBase64(parts[2].c_str());
  std::vector<unsigned char> ciphertext = *DecodeBase64(parts[0].c_str());

  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  ctx = EVP_CIPHER_CTX_new();
  EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key.data(),
               encrypted_key.size(), iv.data(), evp_prkey);

  std::vector<unsigned char> plaintext(ciphertext.size());
  EVP_OpenUpdate(ctx, &plaintext[0], &len, ciphertext.data(),
                 ciphertext.size());
  plaintext_len = len;
  EVP_OpenFinal(ctx, &plaintext[0] + len, &len);
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  plaintext.resize(plaintext_len);
  BIO_free(pbkeybio);
  BIO_free(prkeybio);
  EVP_PKEY_free(evp_pbkey);
  EVP_PKEY_free(evp_prkey);
  return {plaintext.begin(), plaintext.end()};
}

inline std::string Decrypt(const std::string &priv_key,
                           const std::string &base64cipherText) {
  BIO *prkeybio = NULL;
  prkeybio = BIO_new_mem_buf((void *)priv_key.c_str(), priv_key.size());
  RSA *p_rsa = NULL;
  p_rsa = PEM_read_bio_RSAPrivateKey(prkeybio, &p_rsa, NULL, NULL);

  auto input = *DecodeBase64(base64cipherText.c_str());

  int cipherTextSize = RSA_size(p_rsa);
  void *plaintext = malloc(cipherTextSize);
  if (plaintext == NULL) {
    throw std::runtime_error(std::string(strerror(errno)));
  }
  memset(plaintext, 0, cipherTextSize);
  void *ciphertext = malloc(cipherTextSize);
  if (ciphertext == NULL) {
    throw std::runtime_error(std::string(strerror(errno)));
  }
  memset(ciphertext, 0, cipherTextSize);

  if (input.size() > (size_t)cipherTextSize) {
    throw std::runtime_error("Data size exceeds the limit");
  }
  memcpy(ciphertext, input.data(), input.size());
  if (RSA_private_decrypt(cipherTextSize, (unsigned char *)ciphertext,
                          (unsigned char *)plaintext, p_rsa,
                          RSA_PKCS1_PADDING) < 0) {
    throw std::runtime_error("Decrypt " + std::string(strerror(errno)));
  }
  std::string output{(char *)plaintext};
  free(ciphertext);
  free(plaintext);
  BIO_free(prkeybio);
  return output;
}

}  // namespace rsa
}  // namespace nunchuk

#endif  //  NUNCHUK_RSA_H
