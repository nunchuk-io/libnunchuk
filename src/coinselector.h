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

#ifndef NUNCHUK_COINSELECTOR_H
#define NUNCHUK_COINSELECTOR_H
#define HAVE_CONFIG_H
#ifdef NDEBUG
#undef NDEBUG
#endif

#include <nunchuk.h>
#include <univalue.h>
#include <rpc/util.h>
#include <policy/policy.h>
#include <wallet/coinselection.h>
#include <primitives/transaction.h>

#include <memory>
#include <vector>

namespace nunchuk {

struct CoinSelectionParams {
  bool use_bnb = true;
  size_t change_output_size = 0;
  size_t change_spend_size = 0;
  CFeeRate effective_fee = CFeeRate(0);
  size_t tx_noinputs_size = 0;
  //! Indicate that we are subtracting the fee from outputs
  bool m_subtract_fee_outputs = false;

  CoinSelectionParams(bool use_bnb, size_t change_output_size,
                      size_t change_spend_size, CFeeRate effective_fee,
                      size_t tx_noinputs_size)
      : use_bnb(use_bnb),
        change_output_size(change_output_size),
        change_spend_size(change_spend_size),
        effective_fee(effective_fee),
        tx_noinputs_size(tx_noinputs_size) {}
  CoinSelectionParams() {}
};

class CoinSelector {
 public:
  CoinSelector(const std::string descriptors,
               const std::string example_address);
  void set_fee_rate(CFeeRate value);
  void set_discard_rate(CFeeRate value);

  bool Select(const std::vector<UnspentOutput>& vAvailableCoins,
              const std::vector<UnspentOutput>& presetInputs,
              const std::string& changeAddress, bool subtractFeeFromAmount,
              std::vector<TxOutput>& vecSend, std::vector<TxInput>& vecInput,
              CAmount& nFeeRet, std::string& error, int& nChangePosInOut);

 private:
  // Since scriptSig and scriptWitness for each descriptor have fixed sizes, we
  // cache the sizes here to optimize CalculateMaximumSignedTxSize performance
  static std::map<std::string, CScript> scriptsig_cache_;
  static std::map<std::string, CScriptWitness> scriptwitness_cache_;
  bool SelectCoinsMinConf(const CAmount& nTargetValue,
                          const CoinEligibilityFilter& eligibility_filter,
                          std::vector<OutputGroup> groups,
                          std::set<CInputCoin>& setCoinsRet, CAmount& nValueRet,
                          const CoinSelectionParams& coin_selection_params,
                          bool& bnb_used);
  bool SelectCoins(const std::vector<UnspentOutput>& vAvailableCoins,
                   const std::vector<UnspentOutput>& presetInputs,
                   const CAmount& nTargetValue,
                   std::set<CInputCoin>& setCoinsRet, CAmount& nValueRet,
                   CoinSelectionParams& coin_selection_params, bool& bnb_used);
  int64_t CalculateMaximumSignedTxSize(const CTransaction& tx);

  CFeeRate fee_rate_;
  CFeeRate discard_rate_{DUST_RELAY_TX_FEE};
  CScript dummy_scriptsig_;
  CScriptWitness dummy_scriptwitness_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_COINSELECTOR_H
