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

#ifndef NUNCHUK_SPENDER_H
#define NUNCHUK_SPENDER_H

#include <utils/addressutils.hpp>
#include <selector.h>
#include <key_io.h>
#include <signingprovider.h>

namespace wallet {

using namespace nunchuk;

util::Result<CreatedTransactionResult> CreateTransaction(
    const std::vector<UnspentOutput>& coins,
    const std::vector<UnspentOutput>& listSelected,
    const std::vector<TxOutput>& recipients, const bool subtract_fee_outputs,
    const std::vector<std::string>& descriptors,
    const std::string& change_address, const Amount fee_rate, int& change_pos,
    int& signedVSize, bool use_script_path, uint32_t sequence);

int EstimateScriptPathVSize(const std::vector<std::string>& descriptors,
                            const CTransaction ctx);

int EstimateKeyPathVSize(const std::vector<std::string>& descriptors,
                         const CTransaction ctx);

}  // namespace wallet

#endif  // NUNCHUK_SPENDER_H
