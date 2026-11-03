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

#ifndef NUNCHUK_ELECTRUM_CHECKRAWTX_H
#define NUNCHUK_ELECTRUM_CHECKRAWTX_H

#include <backend/electrum/client.h>
#include <string>

namespace nunchuk {

enum class RawTxCheck { Ok, Invalid, Unavailable };

// Verify every input of an unconfirmed transaction against the previous
// outputs fetched from the Electrum server. A missing previous output is
// retried; an invalid signature is not stored. Liquid transactions use a
// different serialization and are left to the Liquid synchronizer.
RawTxCheck CheckPendingRawTx(ElectrumClient* client, bool liquid,
                             const std::string& raw_tx);

}  // namespace nunchuk

#endif  // NUNCHUK_ELECTRUM_CHECKRAWTX_H
