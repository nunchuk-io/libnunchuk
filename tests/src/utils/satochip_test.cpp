#include <nunchuk.h>
#include <doctest.h>

#include <future>
#include <stdexcept>

namespace {

const std::string kMnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about";

struct SeedVector {
  std::string passphrase;
  std::string seed;
};

// Standard BIP39 vectors plus byte-for-byte compatibility cases generated
// independently with Python's hashlib.pbkdf2_hmac("sha512", ..., 2048, 64).
const std::vector<SeedVector> kVectors = {
    {"",
     "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19"
     "a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"},
    {"TREZOR",
     "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f"
     "09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"},
    {std::string(257, 'p'),
     "f8b834d9c4025c2f79638a7c38e61c8133d9066343d7c9bc7cbdc19ec70b2681"
     "a30147082b80f0c92bf3307e2d8f832a5dffce43a725a1434d60999ebada7b3c"},
    {std::string("TREZOR\0extra", 12),
     "13d625a8eacafc35894833cf43d8ec7bb4a5e66a51ab59517c467afb375ece883"
     "b59d800952e6bda99f42007000e2a07703e69774177cba775d94e582f95c06b"},
    {"cafe\xcc\x81",
     "af8bbd2566df7b69d926f2b09dfdbd75db6c994a3399b2cc65f928d63e3fd4e61"
     "218ee0d15f8c810be4d45e66d47b43c15a5cc753976b1666912377ff7ae9818"},
};

std::string ImportSeed(const std::string& passphrase) {
  std::string hex;
  nunchuk::SatochipImportSeedFromMnemonic(
      [&](const std::vector<unsigned char>& seed) {
        constexpr char digits[] = "0123456789abcdef";
        for (const auto byte : seed) {
          hex.push_back(digits[byte >> 4]);
          hex.push_back(digits[byte & 15]);
        }
      },
      kMnemonic, passphrase);
  return hex;
}

}  // namespace

TEST_CASE("Satochip seed import preserves BIP39 passphrase bytes") {
  for (const auto& vector : kVectors) {
    CHECK(ImportSeed(vector.passphrase) == vector.seed);
  }
}

TEST_CASE("Satochip seed import validates input and propagates card errors") {
  using namespace nunchuk;
  bool called = false;
  const auto import = [&](const std::vector<unsigned char>&) { called = true; };
  CHECK_THROWS_AS(SatochipImportSeedFromMnemonic({}, kMnemonic),
                  NunchukException);
  CHECK_THROWS_AS(SatochipImportSeedFromMnemonic(import, "invalid mnemonic"),
                  NunchukException);
  CHECK_THROWS_AS(
      SatochipImportSeedFromMnemonic(import, kMnemonic + '\0' + "extra"),
      NunchukException);
  CHECK_FALSE(called);
  CHECK_THROWS_WITH(
      SatochipImportSeedFromMnemonic(
          [](const std::vector<unsigned char>&) {
            throw std::runtime_error("card disconnected");
          },
          kMnemonic),
      "card disconnected");
  CHECK(ImportSeed("") == kVectors.front().seed);
}

TEST_CASE("Satochip seed derivations have independent contexts") {
  std::promise<void> start;
  auto ready = start.get_future().share();
  std::vector<std::future<std::string>> results;
  for (const auto& vector : kVectors) {
    results.push_back(std::async(std::launch::async, [ready, vector] {
      ready.wait();
      return ImportSeed(vector.passphrase);
    }));
  }
  start.set_value();
  for (size_t i = 0; i < results.size(); ++i) {
    CHECK(results[i].get() == kVectors[i].seed);
  }
}
