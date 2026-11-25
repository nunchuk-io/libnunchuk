#ifndef NUNCHUK_KRUX_H
#define NUNCHUK_KRUX_H

#include <string>
#include <vector>

namespace nunchuk {

std::string ExtractKruxBackup(const std::vector<unsigned char>& data,
                              const std::string& password,
                              const std::string& mnemonic_id = {});

}  // namespace nunchuk

#endif
