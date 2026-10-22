#include <certs/cacert_data.h>
#include <certs/sslcerts.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_THREAD_POOL_COUNT 2
#include <doctest.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <utils/httplib.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <thread>
#include <vector>

namespace {

using Cert = std::unique_ptr<X509, decltype(&X509_free)>;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Store = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using Context = std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>;

const auto kRepo =
    std::filesystem::path(__FILE__).parent_path().parent_path().parent_path();

std::string ReadFile(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  REQUIRE(input.good());
  return {std::istreambuf_iterator<char>(input), {}};
}

std::vector<Cert> ReadCertificates(const std::string& pem) {
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(
      BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
  REQUIRE(bio);
  std::vector<Cert> certs;
  while (X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)) {
    certs.emplace_back(cert, X509_free);
  }
  ERR_clear_error();
  REQUIRE_FALSE(certs.empty());
  return certs;
}

struct StackDeleter {
  void operator()(STACK_OF(X509) * stack) const { sk_X509_free(stack); }
};
using BorrowedChain = std::unique_ptr<STACK_OF(X509), StackDeleter>;

Key MakeKey() {
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
  REQUIRE(ctx);
  REQUIRE(EVP_PKEY_keygen_init(ctx.get()) == 1);
  REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(),
                                                 NID_X9_62_prime256v1) == 1);
  EVP_PKEY* key = nullptr;
  REQUIRE(EVP_PKEY_keygen(ctx.get(), &key) == 1);
  return Key(key, EVP_PKEY_free);
}

Cert MakeCertificate(EVP_PKEY* key, X509* issuer, EVP_PKEY* issuer_key) {
  Cert cert(X509_new(), X509_free);
  REQUIRE(cert);
  REQUIRE(X509_set_version(cert.get(), 2) == 1);
  REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), issuer ? 2 : 1) ==
          1);
  REQUIRE(X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60));
  REQUIRE(X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600));
  REQUIRE(X509_set_pubkey(cert.get(), key) == 1);
  auto name = X509_get_subject_name(cert.get());
  const auto cn = reinterpret_cast<const unsigned char*>(
      issuer ? "localhost" : "libnunchuk TLS regression CA");
  REQUIRE(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cn, -1, -1, 0) ==
          1);
  REQUIRE(X509_set_issuer_name(
              cert.get(), issuer ? X509_get_subject_name(issuer) : name) == 1);
  for (const auto& extension : std::vector<std::pair<int, const char*>>{
           {NID_basic_constraints,
            issuer ? "critical,CA:FALSE" : "critical,CA:TRUE"},
           {NID_key_usage, issuer ? "critical,digitalSignature"
                                  : "critical,keyCertSign,cRLSign"},
           {NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1"}}) {
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext(
        X509V3_EXT_conf_nid(nullptr, nullptr, extension.first,
                            const_cast<char*>(extension.second)),
        X509_EXTENSION_free);
    REQUIRE(ext);
    REQUIRE(X509_add_ext(cert.get(), ext.get(), -1) == 1);
  }
  REQUIRE(X509_sign(cert.get(), issuer_key ? issuer_key : key, EVP_sha256()) >
          0);
  return cert;
}

}  // namespace

TEST_CASE("embedded CA bundle matches the PEM and excludes distrusted roots") {
  const auto pem = ReadFile(kRepo / "src/certs/cacert.pem");
  CHECK(std::string(nunchuk::kEmbeddedCaCertificates) == "\n" + pem);
  const auto certs = ReadCertificates(pem);
  Store store(nunchuk::CreateEmbeddedCaCertStore(), X509_STORE_free);
  REQUIRE(store);
  CHECK(sk_X509_OBJECT_num(X509_STORE_get0_objects(store.get())) ==
        certs.size());
  bool found_g1 = false;
  for (const auto& cert : certs) {
    char cn[256] = {};
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert.get()), NID_commonName,
                              cn, sizeof(cn));
    const std::string name(cn);
    CHECK(name != "emSign ECC Root CA - G3");
    CHECK(name != "emSign Root TLS CA - G3");
    CHECK(name != "emSign ECC Root CA - C3");
    CHECK(name != "emSign Root CA - C1");
    CHECK(name != "AAA Certificate Services");
    found_g1 |= name == "emSign Root CA - G1";
  }
  CHECK(found_g1);
}

TEST_CASE("compromised keys are rejected before untrusted-CA fallback") {
  const auto certs = ReadCertificates(
      ReadFile(kRepo / "tests/data/certs/emudhra-intermediates.pem"));
  REQUIRE(certs.size() == 16);
  auto key = MakeKey();
  auto clean = MakeCertificate(key.get(), nullptr, nullptr);
  Store empty(X509_STORE_new(), X509_STORE_free);
  Context ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
  REQUIRE(empty);
  REQUIRE(ctx);
  REQUIRE(X509_STORE_CTX_init(ctx.get(), empty.get(), clean.get(), nullptr) ==
          1);
  CHECK(nunchuk::CheckCertificateChainForCompromisedKeys(ctx.get()));

  for (const auto& compromised : certs) {
    CAPTURE(X509_get_serialNumber(compromised.get()));
    BorrowedChain supplied(sk_X509_new_null());
    REQUIRE(supplied);
    REQUIRE(sk_X509_push(supplied.get(), compromised.get()) == 1);
    X509_STORE_CTX_cleanup(ctx.get());
    REQUIRE(X509_STORE_CTX_init(ctx.get(), empty.get(), clean.get(),
                                supplied.get()) == 1);
    // The bad intermediate has not been added to a built chain yet.
    CHECK_FALSE(nunchuk::CheckCertificateChainForCompromisedKeys(ctx.get()));
    CHECK(X509_STORE_CTX_get_error(ctx.get()) == X509_V_ERR_CERT_REVOKED);

    X509_STORE_CTX_cleanup(ctx.get());
    REQUIRE(X509_STORE_CTX_init(ctx.get(), empty.get(), compromised.get(),
                                nullptr) == 1);
    // Model Electrum's permissive fallback, with the mandatory key check first.
    X509_STORE_CTX_set_verify_cb(ctx.get(), [](int, X509_STORE_CTX* context) {
      return nunchuk::CheckCertificateChainForCompromisedKeys(context) ? 1 : 0;
    });
    CHECK(X509_verify_cert(ctx.get()) == 0);
    CHECK(X509_STORE_CTX_get_error(ctx.get()) == X509_V_ERR_CERT_REVOKED);

    // A renamed/reissued certificate with the same key is still blocked.
    Cert renamed(X509_dup(compromised.get()), X509_free);
    REQUIRE(renamed);
    REQUIRE(X509_set_subject_name(renamed.get(),
                                  X509_get_subject_name(clean.get())) == 1);
    X509_STORE_CTX_cleanup(ctx.get());
    REQUIRE(X509_STORE_CTX_init(ctx.get(), empty.get(), renamed.get(),
                                nullptr) == 1);
    CHECK_FALSE(nunchuk::CheckCertificateChainForCompromisedKeys(ctx.get()));

    // Also inspect a built chain when the key came from a supplied trust store.
    X509_STORE_CTX_cleanup(ctx.get());
    REQUIRE(X509_STORE_CTX_init(ctx.get(), empty.get(), clean.get(), nullptr) ==
            1);
    auto built = sk_X509_new_null();
    REQUIRE(built);
    REQUIRE(X509_up_ref(compromised.get()) == 1);
    REQUIRE(sk_X509_push(built, compromised.get()) == 1);
    X509_STORE_CTX_set0_verified_chain(ctx.get(),
                                       built);  // Transfers ownership.
    CHECK_FALSE(nunchuk::CheckCertificateChainForCompromisedKeys(ctx.get()));
  }
}

TEST_CASE("embedded store rejects compromised keys even if explicitly added") {
  const auto certs = ReadCertificates(
      ReadFile(kRepo / "tests/data/certs/emudhra-intermediates.pem"));
  for (const auto& cert : certs) {
    Store store(nunchuk::CreateEmbeddedCaCertStore(), X509_STORE_free);
    REQUIRE(X509_STORE_add_cert(store.get(), cert.get()) == 1);
    REQUIRE(X509_STORE_set_flags(store.get(), X509_V_FLAG_PARTIAL_CHAIN) == 1);
    Context ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    REQUIRE(ctx);
    REQUIRE(X509_STORE_CTX_init(ctx.get(), store.get(), cert.get(), nullptr) ==
            1);
    CHECK(X509_verify_cert(ctx.get()) == 0);
    CHECK(X509_STORE_CTX_get_error(ctx.get()) == X509_V_ERR_CERT_REVOKED);
  }
}

#ifndef _WIN32
namespace {

class ScopedEnvironment {
 public:
  ScopedEnvironment(const char* name, const std::string& value) : name_(name) {
    if (const char* old = std::getenv(name)) {
      had_value_ = true;
      old_ = old;
    }
    REQUIRE(setenv(name, value.c_str(), 1) == 0);
  }
  ~ScopedEnvironment() {
    if (had_value_)
      setenv(name_.c_str(), old_.c_str(), 1);
    else
      unsetenv(name_.c_str());
  }

 private:
  std::string name_, old_;
  bool had_value_ = false;
};

struct TemporaryDirectory {
  std::filesystem::path path =
      std::filesystem::temp_directory_path() /
      ("libnunchuk-tls-" +
       std::to_string(
           std::chrono::steady_clock::now().time_since_epoch().count()));
  TemporaryDirectory() { REQUIRE(std::filesystem::create_directory(path)); }
  ~TemporaryDirectory() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
};

struct RunningServer {
  httplib::SSLServer server;
  int port;
  std::thread thread;
  RunningServer(X509* cert, EVP_PKEY* key) : server(cert, key) {
    REQUIRE(server.is_valid());
    server.Get("/", [](const httplib::Request&, httplib::Response& response) {
      response.set_content("ok", "text/plain");
    });
    port = server.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    thread = std::thread([this] { server.listen_after_bind(); });
  }
  ~RunningServer() {
    server.stop();
    if (thread.joinable()) thread.join();
  }
};

}  // namespace

TEST_CASE("explicit HTTP trust stores do not import system roots") {
  auto root_key = MakeKey();
  auto root = MakeCertificate(root_key.get(), nullptr, nullptr);
  auto key = MakeKey();
  auto cert = MakeCertificate(key.get(), root.get(), root_key.get());
  TemporaryDirectory tmp;
  const auto ca_path = (tmp.path / "ca.pem").string();
  {
    std::unique_ptr<BIO, decltype(&BIO_free)> pem(
        BIO_new_file(ca_path.c_str(), "w"), BIO_free);
    REQUIRE(pem);
    REQUIRE(PEM_write_bio_X509(pem.get(), root.get()) == 1);
  }
  ScopedEnvironment ca_file("SSL_CERT_FILE", ca_path);
  ScopedEnvironment ca_dir("SSL_CERT_DIR", tmp.path.string());
  RunningServer server(cert.get(), key.get());

  // Control: system defaults really do trust the test CA.
  httplib::SSLClient system("127.0.0.1", server.port);
  system.enable_server_certificate_verification(true);
  auto result = system.Get("/");
  REQUIRE(result);
  CHECK(result->body == "ok");

  httplib::SSLClient embedded("127.0.0.1", server.port);
  nunchuk::ConfigureTlsVerification(embedded);
  CHECK_FALSE(embedded.Get("/"));
  CHECK(embedded.get_openssl_verify_result() != X509_V_OK);

  // Caller-supplied private CA files still work.
  httplib::SSLClient custom("127.0.0.1", server.port);
  nunchuk::ConfigureTlsVerification(custom, ca_path);
  auto custom_result = custom.Get("/");
  REQUIRE(custom_result);
  CHECK(custom_result->body == "ok");

  // A matching explicit in-memory store still succeeds.
  httplib::SSLClient trusted("127.0.0.1", server.port);
  Store store(nunchuk::CreateEmbeddedCaCertStore(), X509_STORE_free);
  REQUIRE(X509_STORE_add_cert(store.get(), root.get()) == 1);
  trusted.set_ca_cert_store(store.release());
  trusted.enable_server_certificate_verification(true);
  REQUIRE(trusted.Get("/"));
}
#endif
