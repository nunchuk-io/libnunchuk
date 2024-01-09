
#define HAVE_CONFIG_H

#include <algorithm>
#include <common/args.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <interfaces/chain.h>
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
#include <wallet/fees.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

#include <cmath>

using interfaces::FoundBlock;

namespace wallet {
static constexpr size_t OUTPUT_GROUP_MAX_ENTRIES{100};

// Returns true if the result contains an error and the message is not empty
static bool HasErrorMsg(const util::Result<SelectionResult>& res) { return !util::ErrorString(res).empty(); }

FilteredOutputGroups GroupOutputs(
    const CWallet& wallet, const CoinsResult& coins,
    const CoinSelectionParams& coin_sel_params,
    const std::vector<SelectionFilter>& filters,
    std::vector<OutputGroup>& ret_discarded_groups) {
  FilteredOutputGroups filtered_groups;

  if (!coin_sel_params.m_avoid_partial_spends) {
    // Allowing partial spends means no grouping. Each COutput gets its own
    // OutputGroup
    for (const auto& [type, outputs] : coins.coins) {
      for (const COutput& output : outputs) {
        // Get mempool info
        size_t ancestors, descendants;
        wallet.chain().getTransactionAncestry(output.outpoint.hash, ancestors,
                                              descendants);

        // Create a new group per output and add it to the all groups vector
        OutputGroup group(coin_sel_params);
        group.Insert(std::make_shared<COutput>(output), ancestors, descendants);

        // Each filter maps to a different set of groups
        bool accepted = false;
        for (const auto& sel_filter : filters) {
          const auto& filter = sel_filter.filter;
          if (!group.EligibleForSpending(filter)) continue;
          filtered_groups[filter].Push(group, type, /*insert_positive=*/true,
                                       /*insert_mixed=*/true);
          accepted = true;
        }
        if (!accepted) ret_discarded_groups.emplace_back(group);
      }
    }
    return filtered_groups;
  }

  // We want to combine COutputs that have the same scriptPubKey into single
  // OutputGroups except when there are more than OUTPUT_GROUP_MAX_ENTRIES
  // COutputs grouped in an OutputGroup. To do this, we maintain a map where the
  // key is the scriptPubKey and the value is a vector of OutputGroups. For each
  // COutput, we check if the scriptPubKey is in the map, and if it is, the
  // COutput is added to the last OutputGroup in the vector for the
  // scriptPubKey. When the last OutputGroup has OUTPUT_GROUP_MAX_ENTRIES
  // COutputs, a new OutputGroup is added to the end of the vector.
  typedef std::map<std::pair<CScript, OutputType>, std::vector<OutputGroup>>
      ScriptPubKeyToOutgroup;
  const auto& insert_output = [&](const std::shared_ptr<COutput>& output,
                                  OutputType type, size_t ancestors,
                                  size_t descendants,
                                  ScriptPubKeyToOutgroup& groups_map) {
    std::vector<OutputGroup>& groups =
        groups_map[std::make_pair(output->txout.scriptPubKey, type)];

    if (groups.size() == 0) {
      // No OutputGroups for this scriptPubKey yet, add one
      groups.emplace_back(coin_sel_params);
    }

    // Get the last OutputGroup in the vector so that we can add the COutput to
    // it A pointer is used here so that group can be reassigned later if it is
    // full.
    OutputGroup* group = &groups.back();

    // Check if this OutputGroup is full. We limit to OUTPUT_GROUP_MAX_ENTRIES
    // when using -avoidpartialspends to avoid surprising users with very high
    // fees.
    if (group->m_outputs.size() >= OUTPUT_GROUP_MAX_ENTRIES) {
      // The last output group is full, add a new group to the vector and use
      // that group for the insertion
      groups.emplace_back(coin_sel_params);
      group = &groups.back();
    }

    group->Insert(output, ancestors, descendants);
  };

  ScriptPubKeyToOutgroup spk_to_groups_map;
  ScriptPubKeyToOutgroup spk_to_positive_groups_map;
  for (const auto& [type, outs] : coins.coins) {
    for (const COutput& output : outs) {
      size_t ancestors, descendants;
      wallet.chain().getTransactionAncestry(output.outpoint.hash, ancestors,
                                            descendants);

      const auto& shared_output = std::make_shared<COutput>(output);
      // Filter for positive only before adding the output
      if (output.GetEffectiveValue() > 0) {
        insert_output(shared_output, type, ancestors, descendants,
                      spk_to_positive_groups_map);
      }

      // 'All' groups
      insert_output(shared_output, type, ancestors, descendants,
                    spk_to_groups_map);
    }
  }

  // Now we go through the entire maps and pull out the OutputGroups
  const auto& push_output_groups = [&](const ScriptPubKeyToOutgroup& groups_map,
                                       bool positive_only) {
    for (const auto& [script, groups] : groups_map) {
      // Go through the vector backwards. This allows for the first item we deal
      // with being the partial group.
      for (auto group_it = groups.rbegin(); group_it != groups.rend();
           group_it++) {
        const OutputGroup& group = *group_it;

        // Each filter maps to a different set of groups
        bool accepted = false;
        for (const auto& sel_filter : filters) {
          const auto& filter = sel_filter.filter;
          if (!group.EligibleForSpending(filter)) continue;

          // Don't include partial groups if there are full groups too and we
          // don't want partial groups
          if (group_it == groups.rbegin() && groups.size() > 1 &&
              !filter.m_include_partial_groups) {
            continue;
          }

          OutputType type = script.second;
          // Either insert the group into the positive-only groups or the mixed
          // ones.
          filtered_groups[filter].Push(group, type, positive_only,
                                       /*insert_mixed=*/!positive_only);
          accepted = true;
        }
        if (!accepted) ret_discarded_groups.emplace_back(group);
      }
    }
  };

  push_output_groups(spk_to_groups_map, /*positive_only=*/false);
  push_output_groups(spk_to_positive_groups_map, /*positive_only=*/true);

  return filtered_groups;
}

FilteredOutputGroups GroupOutputs(const CWallet& wallet,
                                  const CoinsResult& coins,
                                  const CoinSelectionParams& params,
                                  const std::vector<SelectionFilter>& filters) {
  std::vector<OutputGroup> unused;
  return GroupOutputs(wallet, coins, params, filters, unused);
}

util::Result<SelectionResult> SelectCoins(
    const CWallet& wallet, CoinsResult& available_coins,
    const PreSelectedInputs& pre_set_inputs, const CAmount& nTargetValue,
    const CCoinControl& coin_control,
    const CoinSelectionParams& coin_selection_params) {
  // Deduct preset inputs amount from the search target
  CAmount selection_target = nTargetValue - pre_set_inputs.total_amount;

  // Return if automatic coin selection is disabled, and we don't cover the
  // selection target
  if (!coin_control.m_allow_other_inputs && selection_target > 0) {
    return util::Error{
        _("The preselected coins total amount does not cover the transaction "
          "target. "
          "Please allow other inputs to be automatically selected or include "
          "more coins manually")};
  }

  // Return if we can cover the target only with the preset inputs
  if (selection_target <= 0) {
    SelectionResult result(nTargetValue, SelectionAlgorithm::MANUAL);
    result.AddInputs(pre_set_inputs.coins,
                     coin_selection_params.m_subtract_fee_outputs);
    result.ComputeAndSetWaste(coin_selection_params.min_viable_change,
                              coin_selection_params.m_cost_of_change,
                              coin_selection_params.m_change_fee);
    return result;
  }

  // Return early if we cannot cover the target with the wallet's UTXO.
  // We use the total effective value if we are not subtracting fee from outputs
  // and 'available_coins' contains the data.
  CAmount available_coins_total_amount =
      coin_selection_params.m_subtract_fee_outputs
          ? available_coins.GetTotalAmount()
          : (available_coins.GetEffectiveTotalAmount().has_value()
                 ? *available_coins.GetEffectiveTotalAmount()
                 : 0);
  if (selection_target > available_coins_total_amount) {
    return util::Error();  // Insufficient funds
  }

  // Start wallet Coin Selection procedure
  auto op_selection_result = AutomaticCoinSelection(
      wallet, available_coins, selection_target, coin_selection_params);
  if (!op_selection_result) return op_selection_result;

  // If needed, add preset inputs to the automatic coin selection result
  if (!pre_set_inputs.coins.empty()) {
    SelectionResult preselected(pre_set_inputs.total_amount,
                                SelectionAlgorithm::MANUAL);
    preselected.AddInputs(pre_set_inputs.coins,
                          coin_selection_params.m_subtract_fee_outputs);
    op_selection_result->Merge(preselected);
    op_selection_result->ComputeAndSetWaste(
        coin_selection_params.min_viable_change,
        coin_selection_params.m_cost_of_change,
        coin_selection_params.m_change_fee);
  }
  return op_selection_result;
}

util::Result<SelectionResult> AutomaticCoinSelection(
    const CWallet& wallet, CoinsResult& available_coins,
    const CAmount& value_to_select,
    const CoinSelectionParams& coin_selection_params) {
  unsigned int limit_ancestor_count = 0;
  unsigned int limit_descendant_count = 0;
  wallet.chain().getPackageLimits(limit_ancestor_count, limit_descendant_count);
  const size_t max_ancestors =
      (size_t)std::max<int64_t>(1, limit_ancestor_count);
  const size_t max_descendants =
      (size_t)std::max<int64_t>(1, limit_descendant_count);
  const bool fRejectLongChains = gArgs.GetBoolArg(
      "-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS);

  // Cases where we have 101+ outputs all pointing to the same destination may
  // result in privacy leaks as they will potentially be deterministically
  // sorted. We solve that by explicitly shuffling the outputs before processing
  if (coin_selection_params.m_avoid_partial_spends &&
      available_coins.Size() > OUTPUT_GROUP_MAX_ENTRIES) {
    available_coins.Shuffle(coin_selection_params.rng_fast);
  }

  // Coin Selection attempts to select inputs from a pool of eligible UTXOs to
  // fund the transaction at a target feerate. If an attempt fails, more
  // attempts may be made using a more permissive CoinEligibilityFilter.
  util::Result<SelectionResult> res = [&] {
    // Place coins eligibility filters on a scope increasing order.
    std::vector<SelectionFilter> ordered_filters{
        // If possible, fund the transaction with confirmed UTXOs only. Prefer
        // at least six
        // confirmations on outputs received from other wallets and only spend
        // confirmed change.
        {CoinEligibilityFilter(1, 6, 0), /*allow_mixed_output_types=*/false},
        {CoinEligibilityFilter(1, 1, 0)},
    };
    // Fall back to using zero confirmation change (but with as few ancestors in
    // the mempool as possible) if we cannot fund the transaction otherwise.
    if (wallet.m_spend_zero_conf_change) {
      ordered_filters.push_back({CoinEligibilityFilter(0, 1, 2)});
      ordered_filters.push_back(
          {CoinEligibilityFilter(0, 1, std::min(size_t{4}, max_ancestors / 3),
                                 std::min(size_t{4}, max_descendants / 3))});
      ordered_filters.push_back({CoinEligibilityFilter(0, 1, max_ancestors / 2,
                                                       max_descendants / 2)});
      // If partial groups are allowed, relax the requirement of spending
      // OutputGroups (groups of UTXOs sent to the same address, which are
      // obviously controlled by a single wallet) in their entirety.
      ordered_filters.push_back(
          {CoinEligibilityFilter(0, 1, max_ancestors - 1, max_descendants - 1,
                                 /*include_partial=*/true)});
      // Try with unsafe inputs if they are allowed. This may spend unconfirmed
      // outputs received from other wallets.
      if (coin_selection_params.m_include_unsafe_inputs) {
        ordered_filters.push_back({CoinEligibilityFilter(
            /*conf_mine=*/0, /*conf_theirs*/ 0, max_ancestors - 1,
            max_descendants - 1, /*include_partial=*/true)});
      }
      // Try with unlimited ancestors/descendants. The transaction will still
      // need to meet mempool ancestor/descendant policy to be accepted to
      // mempool and broadcasted, but OutputGroups use heuristics that may
      // overestimate ancestor/descendant counts.
      if (!fRejectLongChains) {
        ordered_filters.push_back(
            {CoinEligibilityFilter(0, 1, std::numeric_limits<uint64_t>::max(),
                                   std::numeric_limits<uint64_t>::max(),
                                   /*include_partial=*/true)});
      }
    }

    // Group outputs and map them by coin eligibility filter
    std::vector<OutputGroup> discarded_groups;
    FilteredOutputGroups filtered_groups =
        GroupOutputs(wallet, available_coins, coin_selection_params,
                     ordered_filters, discarded_groups);

    // Check if we still have enough balance after applying filters (some coins
    // might be discarded)
    CAmount total_discarded = 0;
    CAmount total_unconf_long_chain = 0;
    for (const auto& group : discarded_groups) {
      total_discarded += group.GetSelectionAmount();
      if (group.m_ancestors >= max_ancestors ||
          group.m_descendants >= max_descendants)
        total_unconf_long_chain += group.GetSelectionAmount();
    }

    if (CAmount total_amount =
            available_coins.GetTotalAmount() - total_discarded <
            value_to_select) {
      // Special case, too-long-mempool cluster.
      if (total_amount + total_unconf_long_chain > value_to_select) {
        return util::Result<SelectionResult>(
            {_("Unconfirmed UTXOs are available, but spending them creates a "
               "chain of transactions that will be rejected by the mempool")});
      }
      return util::Result<SelectionResult>(
          util::Error());  // General "Insufficient Funds"
    }

    // Walk-through the filters until the solution gets found.
    // If no solution is found, return the first detailed error (if any).
    // future: add "error level" so the worst one can be picked instead.
    std::vector<util::Result<SelectionResult>> res_detailed_errors;
    for (const auto& select_filter : ordered_filters) {
      auto it = filtered_groups.find(select_filter.filter);
      if (it == filtered_groups.end()) continue;
      if (auto res{AttemptSelection(wallet.chain(), value_to_select, it->second,
                                    coin_selection_params,
                                    select_filter.allow_mixed_output_types)}) {
        return res;  // result found
      } else {
        // If any specific error message appears here, then something
        // particularly wrong might have happened. Save the error and continue
        // the selection process. So if no solutions gets found, we can return
        // the detailed error to the upper layers.
        if (HasErrorMsg(res)) res_detailed_errors.emplace_back(res);
      }
    }

    // Return right away if we have a detailed error
    if (!res_detailed_errors.empty()) return res_detailed_errors.front();

    // General "Insufficient Funds"
    return util::Result<SelectionResult>(util::Error());
  }();

  return res;
}

}  // namespace wallet