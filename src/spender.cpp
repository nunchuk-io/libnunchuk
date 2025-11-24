#include <spender.h>
#include <utils/addressutils.hpp>
#include <selector.h>
#include <key_io.h>
#include <signingprovider.h>
#include <miniscript/util.h>

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
 * @param max_sat_weight The maximum satisfaction weight.
 * @param max_sat_elems The maximum satisfaction elements.
 */
static std::optional<int64_t> MaxInputWeight(
    const Descriptor& desc, const bool tx_is_segwit, const bool can_grind_r,
    const std::optional<int64_t>& max_sat_weight = std::nullopt,
    const std::optional<int64_t>& max_sat_elems = std::nullopt) {
  const auto weight = max_sat_weight ? max_sat_weight
                                     : desc.MaxSatisfactionWeight(!can_grind_r);
  if (weight) {
    const auto elems =
        max_sat_elems ? max_sat_elems : desc.MaxSatisfactionElems();
    if (elems) {
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
          is_segwit ? 1 : GetSizeOfCompactSize(*weight / WITNESS_SCALE_FACTOR);
      const int64_t witstack_len =
          is_segwit ? GetSizeOfCompactSize(*elems) : (tx_is_segwit ? 1 : 0);
      // previous txid + previous vout + sequence + scriptsig len + witstack
      // size + scriptsig or witness NOTE: sat_weight already accounts for the
      // witness discount accordingly.
      return (32 + 4 + 4 + scriptsig_len) * WITNESS_SCALE_FACTOR +
             witstack_len + *weight;
    }
  }

  return {};
}

static COutput CreateCOutput(const UnspentOutput& coin, const Descriptor& desc,
                             CFeeRate feerate,
                             const std::optional<int64_t>& max_sat_weight,
                             const std::optional<int64_t>& max_sat_elems) {
  const bool can_grind_r = false;
  COutPoint outpoint(Txid::FromUint256(*uint256::FromHex(coin.get_txid())),
                     coin.get_vout());
  CTxOut txout{coin.get_amount(), AddressToCScriptPubKey(coin.get_address())};
  auto input_weight =
      MaxInputWeight(desc, true, can_grind_r, max_sat_weight, max_sat_elems);
  int input_bytes =
      static_cast<int>(GetVirtualTransactionSize(*input_weight, 0, 0));

  return COutput(outpoint, txout, coin.get_height(), input_bytes, true, true,
                 coin.get_blocktime(), true);
}

util::Result<PreSelectedInputs> FetchSelectedInputs(
    const std::vector<std::unique_ptr<Descriptor>>& desc,
    const std::vector<UnspentOutput>& listSelected, bool subtract_fee_outputs,
    CFeeRate feerate, const std::optional<int64_t>& max_sat_weight,
    const std::optional<int64_t>& max_sat_elems) {
  PreSelectedInputs result;
  for (const UnspentOutput& coin : listSelected) {
    auto output = CreateCOutput(coin, *desc.front(), feerate, max_sat_weight,
                                max_sat_elems);
    // output.ApplyBumpFee(map_of_bump_fees.at(output.outpoint));
    result.Insert(output, subtract_fee_outputs);
  }
  return result;
}

CoinsResult AvailableCoins(const std::vector<std::unique_ptr<Descriptor>>& desc,
                           const std::vector<UnspentOutput>& coins,
                           const std::vector<UnspentOutput>& listSelected,
                           bool subtract_fee_outputs, CFeeRate feerate,
                           const std::optional<int64_t>& max_sat_weight,
                           const std::optional<int64_t>& max_sat_elems,
                           CAmount remain_target) {
  CoinsResult result;
  const bool can_grind_r = false;
  auto isSelected = [&](const UnspentOutput& coin) {
    for (auto&& input : listSelected) {
      if (input.get_txid() == coin.get_txid() &&
          input.get_vout() == coin.get_vout())
        return true;
    }
    return false;
  };
  std::vector<UnspentOutput> sorted_coins = coins;
  std::sort(sorted_coins.begin(), sorted_coins.end(),
            [](const UnspentOutput& a, const UnspentOutput& b) {
              if (a.get_height() <= 0) return false;
              if (b.get_height() <= 0) return true;
              return a.get_height() < b.get_height();
            });
  CAmount total_amount{0};
  for (const UnspentOutput& coin : sorted_coins) {
    if (total_amount >= remain_target) break;
    if (isSelected(coin)) continue;
    auto output = CreateCOutput(coin, *desc.front(), feerate, max_sat_weight,
                                max_sat_elems);
    result.Add(OutputType::UNKNOWN, output);  // TODO: get outputtype

    total_amount +=
        subtract_fee_outputs ? output.txout.nValue : output.GetEffectiveValue();
  }
  return result;
}

// txouts needs to be in the order of tx.vin
TxSize CalculateMaximumSignedTxSize(
    const CTransaction& tx, const Descriptor& desc,
    const std::optional<int64_t>& max_sat_weight = std::nullopt,
    const std::optional<int64_t>& max_sat_elems = std::nullopt) {
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
        MaxInputWeight(desc, is_segwit, false, max_sat_weight, max_sat_elems);
    if (!txin_weight) return TxSize{-1, -1};
    assert(*txin_weight > -1);
    weight += *txin_weight;
  }

  // It's ok to use 0 as the number of sigops since we never create any
  // pathological transaction.
  return TxSize{GetVirtualTransactionSize(weight, 0, 0), weight};
}

std::pair<int64_t, int64_t> GetStackAndWitnessSize(
    const std::string& tapscript) {
  std::pair<int64_t, int64_t> rs = {-1, -1};
  auto updateRs = [&](const miniscript::NodeRef<std::string>& node) -> bool {
    bool isValid = node && node->IsValidTopLevel() && node->IsSane() &&
                   !node->IsNotSatisfiable();
    if (!isValid) return false;
    if (node->GetStackSize() && *node->GetStackSize() > rs.first) {
      rs.first = *node->GetStackSize();
    }
    if (node->GetWitnessSize() && *node->GetWitnessSize() > rs.second) {
      rs.second = *node->GetWitnessSize();
    }
    return true;
  };
  if (updateRs(ParseMiniscript(tapscript, AddressType::TAPROOT))) return rs;

  std::vector<std::string> names;
  std::vector<std::string> subscripts;
  std::vector<int> depths;
  std::pair<int, int> eii;
  std::string error;
  if (!ParseTapscriptTemplate(tapscript, names, eii, subscripts, depths, error))
    return rs;
  if (subscripts.empty()) return rs;

  int keypath_m;
  for (auto& subscript : subscripts) {
    if (IsValidMusigTemplate(subscript)) continue;
    updateRs(ParseMiniscript(subscript, AddressType::TAPROOT));
  }
  return rs;
}

util::Result<CreatedTransactionResult> CreateTransaction(
    const std::vector<UnspentOutput>& coins,
    const std::vector<UnspentOutput>& listSelected,
    const std::vector<TxOutput>& recipients, const bool subtract_fee_outputs,
    const std::vector<std::string>& descriptors, const std::string& miniscript,
    const std::string& change_address, const Amount fee_rate, int& change_pos,
    int& signedVSize, bool use_script_path, uint32_t sequence) {
  std::vector<CRecipient> vecSend;
  for (const auto& recipient : recipients) {
    std::string error;
    auto dest = DecodeDestination(recipient.first, error);
    if (!error.empty()) {
      throw NunchukException(NunchukException::INVALID_ADDRESS, error);
    }
    vecSend.push_back(
        {std::move(dest), recipient.second, subtract_fee_outputs});
  }

  FlatSigningProvider provider;
  std::string error;
  std::vector<std::unique_ptr<Descriptor>> desc;
  std::vector<CScript> output_scripts;

  for (auto&& descriptor : descriptors) {
    for (auto&& parsed : Parse(descriptor, provider, error, true)) {
      parsed->Expand(0, provider, output_scripts, provider);
      desc.emplace_back(std::move(parsed));
    }
  }

  std::optional<int64_t> max_sat_weight = std::nullopt;
  std::optional<int64_t> max_sat_elems = std::nullopt;
  if (use_script_path && !provider.tr_trees.empty()) {
    auto spendData = provider.tr_trees.begin()->second.GetSpendData();
    size_t max_control_block_size = 0;
    for (const auto& [leaf_script, control_blocks] : spendData.scripts) {
      for (const auto& control_block : control_blocks) {
        if (max_control_block_size < control_block.size()) {
          max_control_block_size = control_block.size();
        }
      }
    }
    int64_t weight = 1 + 65 + 1 + 33;
    if (!miniscript.empty()) {
      auto [stack_size, witness_size] = GetStackAndWitnessSize(miniscript);
      if (stack_size > 0) max_sat_elems = stack_size;
      if (witness_size > weight) weight = witness_size;
    }
    max_sat_weight = std::optional<int64_t>{
        1 + weight + GetSizeOfCompactSize(max_control_block_size) +
        max_control_block_size};
  }

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
  coin_selection_params.m_include_unsafe_inputs = true;
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
  auto res_fetch_inputs = FetchSelectedInputs(
      desc, listSelected, subtract_fee_outputs,
      coin_selection_params.m_effective_feerate, max_sat_weight, max_sat_elems);
  if (!res_fetch_inputs)
    return util::Error{util::ErrorString(res_fetch_inputs)};
  PreSelectedInputs preset_inputs = *res_fetch_inputs;

  // Fetch wallet available coins if "other inputs" are
  // allowed (coins automatically selected by the wallet)
  CoinsResult available_coins;  // TODO: available_coins
  if (coin_control.m_allow_other_inputs) {
    CAmount remain_target = MAX_MONEY;
    if (sequence != MAX_BIP125_RBF_SEQUENCE && sequence != 0) {
      remain_target = selection_target - preset_inputs.total_amount;
    }
    available_coins =
        AvailableCoins(desc, coins, listSelected, subtract_fee_outputs,
                       coin_selection_params.m_effective_feerate,
                       max_sat_weight, max_sat_elems, remain_target);
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
  const uint32_t nSequence{sequence};
  for (const auto& coin : selected_coins) {
    txNew.vin.emplace_back(coin->outpoint, CScript(), nSequence);
  }

  // Calculate the transaction fee
  // TODO: CalculateMaximumSignedTxSize(CTransaction(txNew), &wallet,
  // &coin_control);
  TxSize tx_sizes = CalculateMaximumSignedTxSize(
      CTransaction(txNew), *desc.front(), max_sat_weight, max_sat_elems);
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
}

int EstimateScriptPathVSize(const std::vector<std::string>& descriptors,
                            const CTransaction ctx) {
  FlatSigningProvider provider;
  std::string error;
  std::vector<std::unique_ptr<Descriptor>> desc;
  std::vector<CScript> output_scripts;

  for (auto&& descriptor : descriptors) {
    for (auto&& parsed : Parse(descriptor, provider, error, true)) {
      parsed->Expand(0, provider, output_scripts, provider);
      desc.emplace_back(std::move(parsed));
    }
  }
  if (provider.tr_trees.empty()) {
    return CalculateMaximumSignedTxSize(ctx, *desc.front()).vsize;
  }

  auto spendData = provider.tr_trees.begin()->second.GetSpendData();
  size_t max_control_block_size = 0;
  for (const auto& [leaf_script, control_blocks] : spendData.scripts) {
    for (const auto& control_block : control_blocks) {
      if (max_control_block_size < control_block.size()) {
        max_control_block_size = control_block.size();
      }
    }
  }
  int64_t sat_weight = 1 + 1 + 65 + 1 + 33 +
                       GetSizeOfCompactSize(max_control_block_size) +
                       max_control_block_size;
  return CalculateMaximumSignedTxSize(ctx, *desc.front(), sat_weight).vsize;
}

int EstimateKeyPathVSize(const std::vector<std::string>& descriptors,
                         const CTransaction ctx) {
  FlatSigningProvider provider;
  std::string error;
  std::vector<std::unique_ptr<Descriptor>> desc;

  for (auto&& descriptor : descriptors) {
    for (auto&& parsed : Parse(descriptor, provider, error, true)) {
      desc.emplace_back(std::move(parsed));
    }
  }
  return CalculateMaximumSignedTxSize(ctx, *desc.front()).vsize;
}

}  // namespace wallet
