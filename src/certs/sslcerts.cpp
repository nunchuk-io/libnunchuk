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

#include "sslcerts.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstring>
#include <stdexcept>

#include "cacert_data.h"

namespace nunchuk {
namespace {

// SHA-256 of DER SubjectPublicKeyInfo, covering all eight compromised eMudhra
// intermediates and their cross-signs. Do not match certificate names or
// hashes: the same compromised key can appear in certificates with different
// metadata. Source (2026-10-22):
// https://emudhra.we-have-a-problem.com/impacted-intermediates.json
constexpr const char* kCompromisedSpkiSha256[] = {
    "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
    "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
    "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
    "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
    "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
    "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
    "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
    "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
};

bool CheckCertificateKey(X509_STORE_CTX* ctx, X509* cert) {
  unsigned char* der = nullptr;
  const int der_size = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der);
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_size = 0;
  const bool ok =
      der_size > 0 && EVP_Digest(der, der_size, digest, &digest_size,
                                 EVP_sha256(), nullptr) == 1;
  OPENSSL_free(der);
  if (!ok || digest_size != 32) {
    X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
    return false;
  }

  constexpr char hex[] = "0123456789abcdef";
  char fingerprint[65] = {};
  for (unsigned int i = 0; i < digest_size; ++i) {
    fingerprint[2 * i] = hex[digest[i] >> 4];
    fingerprint[2 * i + 1] = hex[digest[i] & 15];
  }
  for (const char* blocked : kCompromisedSpkiSha256) {
    if (std::strcmp(fingerprint, blocked) == 0) {
      X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
      return false;
    }
  }
  return true;
}

}  // namespace

bool CheckCertificateChainForCompromisedKeys(X509_STORE_CTX* ctx) {
  if (!ctx) return false;
  X509* leaf = X509_STORE_CTX_get0_cert(ctx);
  if (!leaf) {
    X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
    return false;
  }
  if (!CheckCertificateKey(ctx, leaf)) return false;

  // Check the peer-supplied certificates even when chain building failed before
  // reaching a compromised intermediate (as can happen after root removal).
  for (STACK_OF(X509)* chain :
       {X509_STORE_CTX_get0_chain(ctx), X509_STORE_CTX_get0_untrusted(ctx)}) {
    for (int i = 0; i < sk_X509_num(chain); ++i) {
      if (!CheckCertificateKey(ctx, sk_X509_value(chain, i))) return false;
    }
  }
  return true;
}

X509_STORE* CreateEmbeddedCaCertStore() {
  BIO* bio = BIO_new_mem_buf(kEmbeddedCaCertificates, -1);
  if (!bio) {
    throw std::runtime_error("Failed to allocate BIO for embedded CA bundle");
  }

  X509_STORE* store = X509_STORE_new();
  if (!store) {
    BIO_free(bio);
    throw std::runtime_error("Failed to allocate X509_STORE for embedded CA");
  }

  int count = 0;
  while (true) {
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert) {
      break;
    }
    // X509_STORE_add_cert fails on duplicates; ignore those.
    if (X509_STORE_add_cert(store, cert) == 1) {
      ++count;
    }
    X509_free(cert);
  }
  BIO_free(bio);
  ERR_clear_error();

  if (count == 0) {
    X509_STORE_free(store);
    throw std::runtime_error("Embedded CA bundle contained no certificates");
  }
  X509_STORE_set_verify_cb(store, [](int preverified, X509_STORE_CTX* ctx) {
    return CheckCertificateChainForCompromisedKeys(ctx) && preverified ? 1 : 0;
  });
  return store;
}

}  // namespace nunchuk
