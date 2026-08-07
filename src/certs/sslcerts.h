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

#ifndef NUNCHUK_SSLCERTS_H
#define NUNCHUK_SSLCERTS_H

#include <string>

typedef struct x509_store_st X509_STORE;

namespace nunchuk {

// Build an X509_STORE from the embedded Mozilla/curl CA bundle.
// Returns a new store (refcount 1). Ownership is transferred to the caller;
// pass it to httplib via set_ca_cert_store, or to Boost.Asio via
// SSL_CTX_set_cert_store, both of which take ownership.
// Works on Android/iOS/Windows/macOS/Linux without writing a PEM to disk
// (static OpenSSL often has empty default verify paths).
X509_STORE* CreateEmbeddedCaCertStore();

// Configure an httplib TLS client for server certificate verification.
// If ca_cert_file is non-empty, that PEM is used; otherwise the embedded
// CA bundle is loaded in-memory.
template <typename HttpClient>
void ConfigureTlsVerification(HttpClient& cli,
                              const std::string& ca_cert_file = {}) {
  if (!ca_cert_file.empty()) {
    cli.set_ca_cert_path(ca_cert_file.c_str());
  } else {
    cli.set_ca_cert_store(CreateEmbeddedCaCertStore());
  }
  cli.enable_server_certificate_verification(true);
}

}  // namespace nunchuk

#endif  // NUNCHUK_SSLCERTS_H
