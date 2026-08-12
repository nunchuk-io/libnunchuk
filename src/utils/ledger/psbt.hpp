/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (c) 2020 Enigmo.
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * libnunchuk is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libnunchuk. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NUNCHUK_LEDGER_PSBT_H
#define NUNCHUK_LEDGER_PSBT_H

#include <cstddef>
#include <string>
#include <vector>

#include "utils/ledger/continuation.hpp"
#include "utils/ledger/types.hpp"

namespace nunchuk::ledger {

struct LedgerPsbtCommitment {
  std::vector<unsigned char> global_commitment;
  size_t inputs_count = 0;
  std::vector<unsigned char> inputs_root;
  size_t outputs_count = 0;
  std::vector<unsigned char> outputs_root;
};

LedgerPsbtCommitment PreparePsbtSigningContext(
    LedgerContinuationContext& context,
    const std::string& psbt);

SignPsbtResult BuildSignedPsbtResult(
    const std::string& psbt,
    const std::vector<std::vector<unsigned char>>& yielded_results);

}  // namespace nunchuk::ledger

#endif  // NUNCHUK_LEDGER_PSBT_H
