#include <spender.h>
#include <utils/addressutils.hpp>
#include <selector.h>
#include <key_io.h>
#include <signingprovider.h>

namespace wallet {

using namespace nunchuk;

/** Whether the descriptor represents, directly or not, a witness program. */
static bool IsSegwit(const Descriptor& desc) {
  if (const auto typ = desc.GetOutputType()) return *typ != OutputType::LEGACY;
  return false;
}

/** Get the size of an input (in witness units) once it's signed.
 *
 * @param desc The output script descriptor of the coin spent by this input.
 * @param tx_is_segwit Whether the transaction has at least a single input
 * spending a segwit coin.
 * @param can_grind_r Whether the signer will be able to grind the R of the
 * signature.
 */
static std::optional<int64_t> MaxInputWeight(const Descriptor& desc,
                                             const bool tx_is_segwit,
                                             const bool can_grind_r) {
  if (const auto sat_weight = desc.MaxSatisfactionWeight(!can_grind_r)) {
    if (const auto elems_count = desc.MaxSatisfactionElems()) {
      const bool is_segwit = IsSegwit(desc);
      // Account for the size of the scriptsig and the number of elements on the
      // witness stack. Note that if any input in the transaction is spending a
      // witness program, we need to specify the witness stack size for every
      // input regardless of whether it is segwit itself. NOTE: this also works
      // in case of mixed scriptsig-and-witness such as in p2sh-wrapped segwit
      // v0 outputs. In this case the size of the scriptsig length will always
      // be one (since the redeemScript is always a push of the witness program
      // in this case, which is smaller than 253 bytes).
      const int64_t scriptsig_len =
          is_segwit ? 1
                    : GetSizeOfCompactSize(*sat_weight / WITNESS_SCALE_FACTOR);
      const int64_t witstack_len = is_segwit
                                       ? GetSizeOfCompactSize(*elems_count)
                                       : (tx_is_segwit ? 1 : 0);
      // previous txid + previous vout + sequence + scriptsig len + witstack
      // size + scriptsig or witness NOTE: sat_weight already accounts for the
      // witness discount accordingly.
      return (32 + 4 + 4 + scriptsig_len) * WITNESS_SCALE_FACTOR +
             witstack_len + *sat_weight;
    }
  }

  return {};
}

util::Result<PreSelectedInputs> FetchSelectedInputs(
    const std::vector<std::unique_ptr<Descriptor>>& desc, const std::vector<UnspentOutput>& listSelected,
    bool substract_fee_from_amount, CFeeRate feerate) {
  PreSelectedInputs result;
  const bool can_grind_r = false;
  for (const UnspentOutput& coin : listSelected) {
    COutPoint outpoint(Txid::FromUint256(*uint256::FromHex(coin.get_txid())),
                       coin.get_vout());
    CTxOut txout{coin.get_amount(), AddressToCScriptPubKey(coin.get_address())};
    auto input_weight = MaxInputWeight(*desc.front(), true, can_grind_r);
    int input_bytes =
        static_cast<int>(GetVirtualTransactionSize(*input_weight, 0, 0));

    /* Set some defaults for depth, spendable, solvable, safe, time, and from_me
     * as these don't matter for preset inputs since no selection is being done.
     */
    COutput output(outpoint, txout, 0, input_bytes, true, true, true, 0, false,
                   feerate);
    // output.ApplyBumpFee(map_of_bump_fees.at(output.outpoint));
    result.Insert(output, substract_fee_from_amount);
  }
  return result;
}

CoinsResult AvailableCoins(const std::vector<std::unique_ptr<Descriptor>>& desc,
                           const std::vector<UnspentOutput>& coins,
                           const std::vector<UnspentOutput>& listSelected,
                           CFeeRate feerate) {
  CoinsResult result;
  const bool can_grind_r = false;
  auto isSelected = [&](const UnspentOutput& coin) {
    for (auto&& input : listSelected) {
      if (input.get_txid() == coin.get_txid() && input.get_vout() == coin.get_vout())
        return true;
    }
    return false;
  };
  for (const UnspentOutput& coin : coins) {
    if (isSelected(coin)) continue;
    COutPoint outpoint(Txid::FromUint256(*uint256::FromHex(coin.get_txid())),
                       coin.get_vout());
    CTxOut txout{coin.get_amount(), AddressToCScriptPubKey(coin.get_address())};
    auto input_weight = MaxInputWeight(*desc.front(), true, can_grind_r);
    int input_bytes =
        static_cast<int>(GetVirtualTransactionSize(*input_weight, 0, 0));

    COutput output(outpoint, txout, coin.get_height(), input_bytes, true, true,
                   true, coin.get_blocktime(), coin.is_change(), feerate);
    result.Add(OutputType::UNKNOWN, output);  // TODO: get outputtype
  }
  return result;
}

/** Infer the maximum size of this input after it will be signed. */
static std::optional<int64_t> GetSignedTxinWeight(const Descriptor& desc,
                                                  const CTxIn& txin,
                                                  const bool tx_is_segwit,
                                                  const bool can_grind_r) {
  return MaxInputWeight(desc, tx_is_segwit, can_grind_r);
}

// txouts needs to be in the order of tx.vin
TxSize CalculateMaximumSignedTxSize(const CTransaction& tx,
                                    const Descriptor& desc) {
  // nVersion + nLockTime + input count + output count
  int64_t weight = (4 + 4 + GetSizeOfCompactSize(tx.vin.size()) +
                    GetSizeOfCompactSize(tx.vout.size())) *
                   WITNESS_SCALE_FACTOR;
  // Whether any input spends a witness program. Necessary to run before the
  // next loop over the inputs in order to accurately compute the compactSize
  // length for the witness data per input.
  bool is_segwit = IsSegwit(desc);
  // Segwit marker and flag
  if (is_segwit) weight += 2;

  // Add the size of the transaction outputs.
  for (const auto& txo : tx.vout)
    weight += GetSerializeSize(txo) * WITNESS_SCALE_FACTOR;

  // Add the size of the transaction inputs as if they were signed.
  for (uint32_t i = 0; i < tx.vin.size(); i++) {
    const auto txin_weight =
        GetSignedTxinWeight(desc, tx.vin[i], is_segwit, false);
    if (!txin_weight) return TxSize{-1, -1};
    assert(*txin_weight > -1);
    weight += *txin_weight;
  }

  // It's ok to use 0 as the number of sigops since we never create any
  // pathological transaction.
  return TxSize{GetVirtualTransactionSize(weight, 0, 0), weight};
}

util::Result<CreatedTransactionResult> CreateTransaction(
    const std::vector<UnspentOutput>& coins,
    const std::vector<UnspentOutput>& listSelected,
    const std::vector<TxOutput>& recipients,
    const bool substract_fee_from_amount, const std::string& descriptor,
    const std::string& change_address, const Amount fee_rate, int& change_pos,
    int& signedVSize) {
  std::vector<CRecipient> vecSend;
  for (const auto& recipient : recipients) {
    vecSend.push_back({DecodeDestination(recipient.first), recipient.second,
                       substract_fee_from_amount});
  }

  FlatSigningProvider provider;
  std::string error;
  auto desc = Parse(descriptor, provider, error, true);

  // out variables, to be packed into returned result structure
  int nChangePosInOut = change_pos;

  FastRandomContext rng_fast;
  CMutableTransaction txNew;  // The resulting transaction that we make

  CCoinControl coin_control;
  coin_control.m_allow_other_inputs = true;
  coin_control.destChange = DecodeDestination(change_address);
  coin_control.m_feerate = CFeeRate(fee_rate);

  CoinSelectionParams coin_selection_params{rng_fast};
  coin_selection_params.m_avoid_partial_spends = false;
  coin_selection_params.m_include_unsafe_inputs = false;
  coin_selection_params.m_long_term_feerate = CFeeRate(10000);

  CAmount recipients_sum = 0;
  unsigned int outputs_to_subtract_fee_from = 0;
  for (const auto& recipient : vecSend) {
    recipients_sum += recipient.nAmount;

    if (recipient.fSubtractFeeFromAmount) {
      outputs_to_subtract_fee_from++;
      coin_selection_params.m_subtract_fee_outputs = true;
    }
  }

  CScript scriptChange = GetScriptForDestination(coin_control.destChange);
  CTxOut change_prototype_txout(0, scriptChange);
  coin_selection_params.change_output_size =
      GetSerializeSize(change_prototype_txout);
  coin_selection_params.change_spend_size = DUMMY_NESTED_P2WPKH_INPUT_SIZE;
  coin_selection_params.m_discard_feerate = CFeeRate(3000);
  coin_selection_params.m_effective_feerate = *coin_control.m_feerate;

  // Calculate the cost of change
  // Cost of change is the cost of creating the change output + cost of spending
  // the change output in the future. For creating the change output now, we use
  // the effective feerate. For spending the change output in the future, we use
  // the discard feerate for now. So cost of change = (change output size *
  // effective feerate) + (size of spending change output * discard feerate)
  coin_selection_params.m_change_fee =
      coin_selection_params.m_effective_feerate.GetFee(
          coin_selection_params.change_output_size);
  coin_selection_params.m_cost_of_change =
      coin_selection_params.m_discard_feerate.GetFee(
          coin_selection_params.change_spend_size) +
      coin_selection_params.m_change_fee;

  coin_selection_params.m_min_change_target =
      GenerateChangeTarget(std::floor(recipients_sum / vecSend.size()),
                           coin_selection_params.m_change_fee, rng_fast);

  // The smallest change amount should be:
  // 1. at least equal to dust threshold
  // 2. at least 1 sat greater than fees to spend it at m_discard_feerate
  const auto dust = GetDustThreshold(change_prototype_txout,
                                     coin_selection_params.m_discard_feerate);
  const auto change_spend_fee = coin_selection_params.m_discard_feerate.GetFee(
      coin_selection_params.change_spend_size);
  coin_selection_params.min_viable_change =
      std::max(change_spend_fee + 1, dust);

  // Static vsize overhead + outputs vsize. 4 nVersion, 4 nLocktime, 1 input
  // count, 1 witness overhead (dummy, flag, stack size)
  coin_selection_params.tx_noinputs_size =
      10 + GetSizeOfCompactSize(vecSend.size());  // bytes for output count

  // vouts to the payees
  for (const auto& recipient : vecSend) {
    CTxOut txout(recipient.nAmount, GetScriptForDestination(recipient.dest));

    // Include the fee cost for outputs.
    coin_selection_params.tx_noinputs_size += ::GetSerializeSize(txout);

    if (IsDust(txout, coin_selection_params.m_discard_feerate)) {
      return util::Error{_("Transaction amount too small")};
    }
    txNew.vout.push_back(txout);
  }

  // Include the fees for things that aren't inputs, excluding the change output
  const CAmount not_input_fees =
      coin_selection_params.m_effective_feerate.GetFee(
          coin_selection_params.m_subtract_fee_outputs
              ? 0
              : coin_selection_params.tx_noinputs_size);
  CAmount selection_target = recipients_sum + not_input_fees;

  // This can only happen if feerate is 0, and requested destinations are value
  // of 0 (e.g. OP_RETURN) and no pre-selected inputs. This will result in
  // 0-input transaction, which is consensus-invalid anyways
  if (selection_target == 0 && !coin_control.HasSelected()) {
    return util::Error{
        _("Transaction requires one destination of non-0 value, a non-0 "
          "feerate, or a pre-selected input")};
  }

  // Fetch manually selected coins
  PreSelectedInputs preset_inputs;  // TODO: preset_inputs
  auto res_fetch_inputs =
      FetchSelectedInputs(desc, listSelected, substract_fee_from_amount,
                          coin_selection_params.m_effective_feerate);
  if (!res_fetch_inputs)
    return util::Error{util::ErrorString(res_fetch_inputs)};
  preset_inputs = *res_fetch_inputs;

  // Fetch wallet available coins if "other inputs" are
  // allowed (coins automatically selected by the wallet)
  CoinsResult available_coins;  // TODO: available_coins
  if (coin_control.m_allow_other_inputs) {
    available_coins =
        AvailableCoins(desc, coins, listSelected, coin_selection_params.m_effective_feerate);
  }

  // Choose coins to use
  auto select_coins_res = SelectCoins(available_coins, preset_inputs,
                                      /*nTargetValue=*/selection_target,
                                      coin_control, coin_selection_params);
  if (!select_coins_res) {
    // 'SelectCoins' either returns a specific error message or, if empty, means
    // a general "Insufficient funds".
    const bilingual_str& err = util::ErrorString(select_coins_res);
    return util::Error{err.empty() ? _("Insufficient funds") : err};
  }
  const SelectionResult& result = *select_coins_res;

  const CAmount change_amount =
      result.GetChange(coin_selection_params.min_viable_change,
                       coin_selection_params.m_change_fee);
  if (change_amount > 0) {
    CTxOut newTxOut(change_amount, scriptChange);
    if (nChangePosInOut == -1) {
      // Insert change txn at random position:
      nChangePosInOut = rng_fast.randrange(txNew.vout.size() + 1);
    } else if ((unsigned int)nChangePosInOut > txNew.vout.size()) {
      return util::Error{_("Transaction change output index out of range")};
    }
    txNew.vout.insert(txNew.vout.begin() + nChangePosInOut, newTxOut);
  } else {
    nChangePosInOut = -1;
  }

  // Shuffle selected coins and fill in final vin
  std::vector<std::shared_ptr<COutput>> selected_coins =
      result.GetShuffledInputVector();

  // The sequence number is set to non-maxint so that DiscourageFeeSniping
  // works.
  //
  // BIP125 defines opt-in RBF as any nSequence < maxint-1, so
  // we use the highest possible value in that range (maxint-2)
  // to avoid conflicting with other possible uses of nSequence,
  // and in the spirit of "smallest possible change from prior
  // behavior."
  const uint32_t nSequence{MAX_BIP125_RBF_SEQUENCE};
  for (const auto& coin : selected_coins) {
    txNew.vin.emplace_back(coin->outpoint, CScript(), nSequence);
  }

  // Calculate the transaction fee
  // TODO: CalculateMaximumSignedTxSize(CTransaction(txNew), &wallet,
  // &coin_control);
  TxSize tx_sizes = CalculateMaximumSignedTxSize(CTransaction(txNew), *desc.front());
  signedVSize = tx_sizes.vsize;

  int nBytes = tx_sizes.vsize;
  if (nBytes == -1) {
    return util::Error{
        _("Missing solving data for estimating transaction size")};
  }
  CAmount fee_needed =
      coin_selection_params.m_effective_feerate.GetFee(nBytes) +
      result.GetTotalBumpFees();
  const CAmount output_value = CalculateOutputValue(txNew);
  Assume(recipients_sum + change_amount == output_value);
  CAmount current_fee = result.GetSelectedValue() - output_value;

  // Sanity check that the fee cannot be negative as that means we have more
  // output value than input value
  if (current_fee < 0) {
    return util::Error{Untranslated(STR_INTERNAL_BUG("Fee paid < 0"))};
  }

  // If there is a change output and we overpay the fees then increase the
  // change to match the fee needed
  if (nChangePosInOut != -1 && fee_needed < current_fee) {
    auto& change = txNew.vout.at(nChangePosInOut);
    change.nValue += current_fee - fee_needed;
    current_fee = result.GetSelectedValue() - CalculateOutputValue(txNew);
    if (fee_needed != current_fee) {
      return util::Error{Untranslated(
          STR_INTERNAL_BUG("Change adjustment: Fee needed != fee paid"))};
    }
  }

  // Reduce output values for subtractFeeFromAmount
  if (coin_selection_params.m_subtract_fee_outputs) {
    CAmount to_reduce = fee_needed - current_fee;
    int i = 0;
    bool fFirst = true;
    for (const auto& recipient : vecSend) {
      if (i == nChangePosInOut) {
        ++i;
      }
      CTxOut& txout = txNew.vout[i];

      if (recipient.fSubtractFeeFromAmount) {
        txout.nValue -=
            to_reduce /
            outputs_to_subtract_fee_from;  // Subtract fee equally from each
                                           // selected recipient

        if (fFirst)  // first receiver pays the remainder not divisible by
                     // output count
        {
          fFirst = false;
          txout.nValue -= to_reduce % outputs_to_subtract_fee_from;
        }

        // Error if this output is reduced to be below dust
        if (IsDust(txout, coin_selection_params.m_discard_feerate)) {
          if (txout.nValue < 0) {
            return util::Error{
                _("The transaction amount is too small to pay the fee")};
          } else {
            return util::Error{
                _("The transaction amount is too small to send after the fee "
                  "has been deducted")};
          }
        }
      }
      ++i;
    }
    current_fee = result.GetSelectedValue() - CalculateOutputValue(txNew);
    if (fee_needed != current_fee) {
      return util::Error{
          Untranslated(STR_INTERNAL_BUG("SFFO: Fee needed != fee paid"))};
    }
  }

  // fee_needed should now always be less than or equal to the current fees that
  // we pay. If it is not, it is a bug.
  if (fee_needed > current_fee) {
    return util::Error{Untranslated(STR_INTERNAL_BUG("Fee needed > fee paid"))};
  }

  // Return the constructed transaction data.
  CTransactionRef tx = MakeTransactionRef(std::move(txNew));
  FeeCalculation feeCalc;
  change_pos = nChangePosInOut;
  return CreatedTransactionResult(tx, current_fee, nChangePosInOut, feeCalc);
}  // namespace wallet

}  // namespace wallet