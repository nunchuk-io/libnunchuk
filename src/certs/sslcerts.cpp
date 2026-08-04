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
#include "cacert_data.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdexcept>

namespace nunchuk {

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
  return store;
}

}  // namespace nunchuk
