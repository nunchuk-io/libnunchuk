/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 * Distributed under the GNU General Public License, version 3.
 */
#ifndef NUNCHUK_ONEKEY_PSBT_HPP
#define NUNCHUK_ONEKEY_PSBT_HPP

#include <nunchuk.h>
#include "utils/json.hpp"

namespace nunchuk::onekey {

struct PreparedPsbt {
  std::string original;
  std::string signing_psbt;
  std::string fingerprint;
  nlohmann::json transaction;
  std::string raw_psbt;
};

PreparedPsbt PreparePsbt(const Wallet& wallet, const std::string& psbt,
                         const std::string& fingerprint, Chain chain);
nlohmann::json TransactionAck(const PreparedPsbt& psbt,
                              const nlohmann::json& request);
std::string MergeSignatures(const PreparedPsbt& psbt,
                            const std::vector<std::string>& signatures);
std::string MergeSignedPsbt(const PreparedPsbt& psbt,
                            const std::string& signed_psbt_hex);

}  // namespace nunchuk::onekey
#endif  // NUNCHUK_ONEKEY_PSBT_HPP
