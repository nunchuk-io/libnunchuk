#include <nunchuk.h>
#include <utils/attachment.hpp>

#include <doctest.h>

TEST_CASE("testing encrypt and descrypt attachment") {
  using namespace nunchuk;
  std::string body = "testtesttest";
  std::string accessToken = "";
  if (accessToken.empty()) return;
  auto event_file = EncryptAttachment(accessToken, body);
  CHECK(!event_file.empty());
  CHECK(DecryptAttachment(event_file) == body);
}
