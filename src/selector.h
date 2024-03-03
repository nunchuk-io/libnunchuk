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

#ifndef NUNCHUK_SELECTOR_H
#define NUNCHUK_SELECTOR_H
#define HAVE_CONFIG_H
#ifdef NDEBUG
#undef NDEBUG
#endif

#include <algorithm>
// #include <common/args.h>
// #include <common/system.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
// #include <interfaces/chain.h>
#include <numeric>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <util/check.h>
#include <util/fees.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/trace.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
// #include <wallet/fees.h>
// #include <wallet/receive.h>
#include <wallet/spend.h>
// #include <wallet/transaction.h>
// #include <wallet/wallet.h>

#include <cmath>

namespace wallet {

util::Result<SelectionResult> SelectCoins(
    CoinsResult& available_coins, const PreSelectedInputs& pre_set_inputs,
    const CAmount& nTargetValue, const CCoinControl& coin_control,
    const CoinSelectionParams& coin_selection_params);

}  // namespace wallet

#endif  // NUNCHUK_SELECTOR_H
