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

#include <limits>
#include <stdexcept>
#include <string_view>

namespace nunchuk {
namespace {

void AddPemCertificates(X509_STORE* store, std::string_view pem,
                        const char* empty_bundle_error) {
  if (pem.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    throw std::runtime_error("CA certificate bundle is too large");
  }

  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) {
    throw std::runtime_error(
        "Failed to allocate BIO for CA certificate bundle");
  }

  size_t count = 0;
  while (true) {
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert) break;
    ++count;
    // X509_STORE_add_cert fails on duplicates; ignore those.
    X509_STORE_add_cert(store, cert);
    X509_free(cert);
    ERR_clear_error();
  }
  BIO_free(bio);
  ERR_clear_error();

  if (count == 0) throw std::runtime_error(empty_bundle_error);
}

}  // namespace

X509_STORE* CreateEmbeddedCaCertStore() {
  X509_STORE* store = X509_STORE_new();
  if (!store) {
    throw std::runtime_error("Failed to allocate X509_STORE for embedded CA");
  }

  try {
    AddPemCertificates(store, kEmbeddedCaCertificates,
                       "Embedded CA bundle contained no certificates");
  } catch (...) {
    X509_STORE_free(store);
    throw;
  }
  return store;
}

X509_STORE* CreateCaCertStore(
    const std::string& ca_cert_file,
    const std::vector<std::string>& additional_ca_certificates) {
  X509_STORE* store = CreateEmbeddedCaCertStore();
  try {
    if (!ca_cert_file.empty() &&
        X509_STORE_load_locations(store, ca_cert_file.c_str(), nullptr) != 1) {
      throw std::runtime_error("Unable to load configured CA certificate file");
    }
    for (const auto& pem : additional_ca_certificates) {
      AddPemCertificates(store, pem,
                         "Additional CA bundle contained no certificates");
    }
  } catch (...) {
    X509_STORE_free(store);
    throw;
  }
  return store;
}

}  // namespace nunchuk
