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

#include "coinselector.h"

#include <key_io.h>
#include <policy/policy.h>

#include <tuple>
#include <vector>
#include <iostream>
#include <signingprovider.h>

namespace nunchuk {

// copy from validation.h
/** Default for -limitancestorcount, max number of in-mempool ancestors */
static const unsigned int DEFAULT_ANCESTOR_LIMIT = 25;
/** Default for -limitdescendantcount, max number of in-mempool descendants */
static const unsigned int DEFAULT_DESCENDANT_LIMIT = 25;

// copy from wallet/wallet.h
//! Default for -spendzeroconfchange
static const bool DEFAULT_SPEND_ZEROCONF_CHANGE = true;
//! Default for -walletrejectlongchains
static const bool DEFAULT_WALLET_REJECT_LONG_CHAINS = false;

std::map<std::string, CScript> CoinSelector::scriptsig_cache_;
std::map<std::string, CScriptWitness> CoinSelector::scriptwitness_cache_;

CoinSelector::CoinSelector(const std::string& descriptors,
                           const std::string& example_address) {
  if (scriptsig_cache_.find(descriptors) == scriptsig_cache_.end() ||
      scriptwitness_cache_.find(descriptors) == scriptwitness_cache_.end()) {
    FlatSigningProvider provider =
        SigningProviderCache::getInstance().GetProvider(descriptors);

    CScript spk = GetScriptForDestination(DecodeDestination(example_address));
    SignatureData sigdata;
    if (!ProduceSignature(provider, DUMMY_MAXIMUM_SIGNATURE_CREATOR, spk,
                          sigdata)) {
      throw NunchukException(NunchukException::CREATE_DUMMY_SIGNATURE_ERROR,
                             "Create dummy signature error");
    }
    scriptsig_cache_[descriptors] = sigdata.scriptSig;
    scriptwitness_cache_[descriptors] = sigdata.scriptWitness;
  }
  dummy_scriptsig_ = scriptsig_cache_.at(descriptors);
  dummy_scriptwitness_ = scriptwitness_cache_.at(descriptors);
}

CoinSelector::CoinSelector(CFeeRate fee_rate, CFeeRate discard_rate,
                           CScriptWitness dummy_scriptwitness)
    : fee_rate_(std::move(fee_rate)),
      discard_rate_(std::move(discard_rate)),
      dummy_scriptwitness_(std::move(dummy_scriptwitness)) {}

void CoinSelector::set_fee_rate(CFeeRate value) {
  // Note (Nunchuk): set rate to the one returned from blockchain-service
  fee_rate_ = value;
}

void CoinSelector::set_discard_rate(CFeeRate value) {
  // Note (Nunchuk): calculate from estimateSmartFee and estimateMaxBlocks
  // returned from blockchain-service
  // Original:
  // https://github.com/bitcoin/bitcoin/blob/2f71a1ea35667b3873197201531e7ae198ec5bf4/src/wallet/fees.cpp#L83
  discard_rate_ = value;
}

std::vector<OutputGroup> GroupOutputs(const std::vector<UnspentOutput>& outputs,
                                      const size_t max_ancestors) {
  std::vector<OutputGroup> groups;

  for (const auto& output : outputs) {
    CMutableTransaction cmt{};
    cmt.vout.push_back(CTxOut{output.get_amount(), CScript()});
    CTransactionRef ctr = MakeTransactionRef(cmt);
    CInputCoin input_coin{ctr, 0};
    input_coin.outpoint =
        COutPoint(uint256S(output.get_txid()), output.get_vout());

    size_t ancestors = 0, descendants = 0;

    // Make an OutputGroup containing just this output
    OutputGroup group{};
    group.Insert(input_coin, output.get_height(), true, ancestors, descendants,
                 true);
    groups.push_back(group);
  }
  return groups;
}

bool CoinSelector::SelectCoinsMinConf(
    const CAmount& nTargetValue,
    const CoinEligibilityFilter& eligibility_filter,
    std::vector<OutputGroup> groups, std::set<CInputCoin>& setCoinsRet,
    CAmount& nValueRet, const CoinSelectionParams& coin_selection_params,
    bool& bnb_used) {
  setCoinsRet.clear();
  nValueRet = 0;

  std::vector<OutputGroup> utxo_pool;
  if (coin_selection_params.use_bnb) {
    // Note (Nunchuk): using passed in fee_rate
    // Original:
    // https://github.com/bitcoin/bitcoin/blob/2f71a1ea35667b3873197201531e7ae198ec5bf4/src/wallet/wallet.cpp#L2311
    CFeeRate long_term_feerate = fee_rate_;

    // Calculate cost of change
    CAmount cost_of_change =
        discard_rate_.GetFee(coin_selection_params.change_spend_size) +
        coin_selection_params.effective_fee.GetFee(
            coin_selection_params.change_output_size);

    // Filter by the min conf specs and add to utxo_pool and calculate effective
    // value
    for (OutputGroup& group : groups) {
      if (!group.EligibleForSpending(eligibility_filter)) continue;

      group.fee = 0;
      group.long_term_fee = 0;
      group.effective_value = 0;
      for (auto it = group.m_outputs.begin(); it != group.m_outputs.end();) {
        const CInputCoin& coin = *it;
        CAmount effective_value =
            coin.txout.nValue -
            (coin.m_input_bytes < 0
                 ? 0
                 : coin_selection_params.effective_fee.GetFee(
                       coin.m_input_bytes));
        // Only include outputs that are positive effective value (i.e. not
        // dust)
        if (effective_value > 0) {
          group.fee += coin.m_input_bytes < 0
                           ? 0
                           : coin_selection_params.effective_fee.GetFee(
                                 coin.m_input_bytes);
          group.long_term_fee +=
              coin.m_input_bytes < 0
                  ? 0
                  : long_term_feerate.GetFee(coin.m_input_bytes);
          if (coin_selection_params.m_subtract_fee_outputs) {
            group.effective_value += coin.txout.nValue;
          } else {
            group.effective_value += effective_value;
          }
          ++it;
        } else {
          // Critical
          // it = group.Discard(coin);
        }
      }
      if (group.effective_value > 0) utxo_pool.push_back(group);
    }
    bnb_used = true;
    return SelectCoinsBnB(utxo_pool, nTargetValue, cost_of_change, setCoinsRet,
                          nValueRet);
  } else {
    // Filter by the min conf specs and add to utxo_pool
    for (const OutputGroup& group : groups) {
      if (!group.EligibleForSpending(eligibility_filter)) continue;
      utxo_pool.push_back(group);
    }
    bnb_used = false;
    return KnapsackSolver(nTargetValue, utxo_pool, setCoinsRet, nValueRet);
  }
}

bool CoinSelector::SelectCoins(
    const std::vector<UnspentOutput>& vAvailableCoins,
    const std::vector<UnspentOutput>& presetInputs, const CAmount& nTargetValue,
    std::set<CInputCoin>& setCoinsRet, CAmount& nValueRet,
    CoinSelectionParams& coin_selection_params, bool& bnb_used) {
  std::vector<UnspentOutput> vCoins(vAvailableCoins);
  CAmount value_to_select = nTargetValue;

  // Default to bnb was not used. If we use it, we set it later
  bnb_used = false;

  // Note (Nunchuk): use default value
  // Original:
  // https://github.com/bitcoin/bitcoin/blob/2f71a1ea35667b3873197201531e7ae198ec5bf4/src/wallet/wallet.cpp#L2427
  size_t max_ancestors = DEFAULT_ANCESTOR_LIMIT;
  size_t max_descendants = DEFAULT_DESCENDANT_LIMIT;
  bool fRejectLongChains = DEFAULT_WALLET_REJECT_LONG_CHAINS;
  // Original:
  // https://github.com/bitcoin/bitcoin/blob/2f71a1ea35667b3873197201531e7ae198ec5bf4/src/wallet/wallet.h#L1000
  bool m_spend_zero_conf_change = DEFAULT_SPEND_ZEROCONF_CHANGE;

  // Support preset inputs for manual coin select
  // If preset inputs are used, additional inputs are not allowed.
  if (!presetInputs.empty()) {
    for (const UnspentOutput& output : presetInputs) {
      CMutableTransaction cmt{};
      cmt.vout.push_back(CTxOut{output.get_amount(), CScript()});
      CTransactionRef ctr = MakeTransactionRef(cmt);
      CInputCoin input_coin{ctr, 0};
      input_coin.outpoint =
          COutPoint(uint256S(output.get_txid()), output.get_vout());

      setCoinsRet.insert(input_coin);
      nValueRet += output.get_amount();
    }
    return (nValueRet >= nTargetValue);
  }

  // Original:
  // https://github.com/bitcoin/bitcoin/blob/2f71a1ea35667b3873197201531e7ae198ec5bf4/src/wallet/wallet.cpp#L2369
  std::vector<OutputGroup> groups = GroupOutputs(vCoins, max_ancestors);

  bool res =
      value_to_select <= 0 ||
      SelectCoinsMinConf(value_to_select, CoinEligibilityFilter(1, 6, 0),
                         groups, setCoinsRet, nValueRet, coin_selection_params,
                         bnb_used) ||
      SelectCoinsMinConf(value_to_select, CoinEligibilityFilter(1, 1, 0),
                         groups, setCoinsRet, nValueRet, coin_selection_params,
                         bnb_used) ||
      (m_spend_zero_conf_change &&
       SelectCoinsMinConf(value_to_select, CoinEligibilityFilter(0, 1, 2),
                          groups, setCoinsRet, nValueRet, coin_selection_params,
                          bnb_used)) ||
      (m_spend_zero_conf_change &&
       SelectCoinsMinConf(
           value_to_select,
           CoinEligibilityFilter(0, 1, std::min((size_t)4, max_ancestors / 3),
                                 std::min((size_t)4, max_descendants / 3)),
           groups, setCoinsRet, nValueRet, coin_selection_params, bnb_used)) ||
      (m_spend_zero_conf_change &&
       SelectCoinsMinConf(
           value_to_select,
           CoinEligibilityFilter(0, 1, max_ancestors / 2, max_descendants / 2),
           groups, setCoinsRet, nValueRet, coin_selection_params, bnb_used)) ||
      (m_spend_zero_conf_change &&
       SelectCoinsMinConf(
           value_to_select,
           CoinEligibilityFilter(0, 1, max_ancestors - 1, max_descendants - 1),
           groups, setCoinsRet, nValueRet, coin_selection_params, bnb_used)) ||
      (m_spend_zero_conf_change && !fRejectLongChains &&
       SelectCoinsMinConf(
           value_to_select,
           CoinEligibilityFilter(0, 1, std::numeric_limits<uint64_t>::max()),
           groups, setCoinsRet, nValueRet, coin_selection_params, bnb_used));

  return res;
}

// 25% of the secp256k1 ECDSA signatures have 73 bytes, 50% of them have 72
// bytes and 25% of them have 71 bytes.
// However, Bitcoin standardness rules only accept low-S signatures on the P2P
// network, so we assume 73-byte signatures are not possible (although miners
// can bypass standardness rules). Low-S low-R signature is also possible,
// which is 71 bytes, but since we don't know whether the external signers
// know how to produce low-S low-R signatures, it's safer to lean on the
// conservative side. So we use low-S signature to calculate max signature
// size, which is 72 bytes. Core's corresponding DummySigner for this is
// DUMMY_MAXIMUM_SIGNATURE_CREATOR.
int64_t CoinSelector::CalculateMaximumSignedTxSize(const CTransaction& tx) {
  CMutableTransaction txNew(tx);
  for (auto&& input : txNew.vin) {
    input.scriptSig = dummy_scriptsig_;
    input.scriptWitness = dummy_scriptwitness_;
  }
  return GetVirtualTransactionSize(CTransaction(txNew));
}

bool CoinSelector::Select(const std::vector<UnspentOutput>& vAvailableCoins,
                          const std::vector<UnspentOutput>& presetInputs,
                          const std::string& changeAddress,
                          bool subtractFeeFromAmount,
                          std::vector<TxOutput>& vecSend,
                          std::vector<TxInput>& vecInput, CAmount& nFeeRet,
                          int& signedVSize, std::string& error,
                          int& nChangePosInOut) {
  CAmount nValue = 0;
  int nChangePosRequest = nChangePosInOut;
  unsigned int nSubtractFeeFromAmount =
      subtractFeeFromAmount ? vecSend.size() : 0;
  for (const auto& recipient : vecSend) {
    if (nValue < 0 || recipient.second < 0) {
      error = "Transaction amounts must not be negative";
      return false;
    }
    nValue += recipient.second;
  }
  if (vecSend.empty()) {
    error = "Transaction must have at least one recipient";
    return false;
  }

  CMutableTransaction txNew;
  CAmount nFeeNeeded;
  std::set<CInputCoin> setCoins;

  CoinSelectionParams
      coin_selection_params;  // Parameters for coin selection, init with dummy

  CScript scriptChange =
      GetScriptForDestination(DecodeDestination(changeAddress));
  CTxOut change_prototype_txout(0, scriptChange);

  coin_selection_params.change_output_size =
      GetSerializeSize(change_prototype_txout);

  CFeeRate discard_rate = discard_rate_;

  // Get the fee rate to use effective values in coin selection
  CFeeRate nFeeRateNeeded = fee_rate_;

  nFeeRet = 0;
  bool pick_new_inputs = true;
  CAmount nValueIn = 0;

  // BnB selector is the only selector used when this is true.
  // That should only happen on the first pass through the loop.
  coin_selection_params.use_bnb = true;
  coin_selection_params.m_subtract_fee_outputs =
      nSubtractFeeFromAmount != 0;  // If we are doing subtract fee from
                                    // recipient, don't use effective values
  // Start with no fee and loop until there is enough fee
  std::vector<TxOutput> vout{};
  while (true) {
    nChangePosInOut = nChangePosRequest;
    vout.clear();
    txNew.vin.clear();
    txNew.vout.clear();
    bool fFirst = true;

    CAmount nValueToSelect = nValue;
    if (nSubtractFeeFromAmount == 0) nValueToSelect += nFeeRet;

    // vouts to the payees
    if (!coin_selection_params.m_subtract_fee_outputs) {
      coin_selection_params.tx_noinputs_size =
          11;  // Static vsize overhead + outputs vsize. 4 nVersion, 4
               // nLocktime, 1 input count, 1 output count, 1 witness overhead
               // (dummy, flag, stack size)
    }
    for (const auto& recipient : vecSend) {
      CScript destScript =
          GetScriptForDestination(DecodeDestination(std::get<0>(recipient)));
      CTxOut txout(recipient.second, destScript);

      if (subtractFeeFromAmount) {
        // Subtract fee equally from each selected recipient
        txout.nValue -= nFeeRet / nSubtractFeeFromAmount;
        // first receiver pays the remainder not divisible by output count
        if (fFirst) {
          fFirst = false;
          txout.nValue -= nFeeRet % nSubtractFeeFromAmount;
        }
      }

      // Include the fee cost for outputs. Note this is only used for BnB right
      // now
      if (!coin_selection_params.m_subtract_fee_outputs) {
        coin_selection_params.tx_noinputs_size +=
            GetSerializeSize(txout, PROTOCOL_VERSION);
      }

      if (IsDust(txout, discard_rate_)) {
        if (subtractFeeFromAmount && nFeeRet > 0) {
          if (txout.nValue < 0)
            error = "The transaction amount is too small to pay the fee";
          else
            error =
                "The transaction amount is too small to send after the fee has "
                "been deducted";
        } else
          error = "Transaction amount too small";
        return false;
      }
      vout.push_back({recipient.first, txout.nValue});
      txNew.vout.push_back(txout);
    }

    // Choose coins to use
    bool bnb_used = false;
    if (pick_new_inputs) {
      nValueIn = 0;
      setCoins.clear();
      // If the wallet doesn't know how to sign change output, assume
      // p2sh-p2wpkh as lower-bound to allow BnB to do it's thing
      coin_selection_params.change_spend_size = 91;
      coin_selection_params.effective_fee = nFeeRateNeeded;
      if (!SelectCoins(vAvailableCoins, presetInputs, nValueToSelect, setCoins,
                       nValueIn, coin_selection_params, bnb_used)) {
        // If BnB was used, it was the first pass. No longer the first pass and
        // continue loop with knapsack.
        if (bnb_used) {
          coin_selection_params.use_bnb = false;
          continue;
        } else {
          error = "Insufficient funds";
          return false;
        }
      }
    } else {
      bnb_used = false;
    }

    const CAmount nChange = nValueIn - nValueToSelect;
    if (nChange > 0) {
      // Fill a vout to ourself
      TxOutput newTxOut(changeAddress, nChange);
      // Never create dust outputs; if we would, just
      // add the dust to the fee.
      // The nChange when BnB is used is always going to go to fees.
      if (IsDust({nChange, scriptChange}, discard_rate) || bnb_used) {
        nChangePosInOut = -1;
        nFeeRet += nChange;
      } else {
        nChangePosInOut = vout.size();
        std::vector<TxOutput>::iterator position =
            vout.begin() + nChangePosInOut;
        vout.insert(position, newTxOut);
        std::vector<CTxOut>::iterator txvoutpos =
            txNew.vout.begin() + nChangePosInOut;
        txNew.vout.insert(txvoutpos, {nChange, scriptChange});
      }
    } else {
      nChangePosInOut = -1;
    }

    // Dummy fill vin for maximum size estimation
    for (const auto& coin : setCoins) {
      txNew.vin.push_back(CTxIn(coin.outpoint, CScript()));
    }

    signedVSize = CalculateMaximumSignedTxSize(CTransaction(txNew));
    if (signedVSize < 0) {
      error = "Signing transaction failed";
      return false;
    }

    nFeeNeeded = fee_rate_.GetFee(signedVSize);
    if (nFeeRet >= nFeeNeeded) {
      // Reduce fee to only the needed amount if possible. This
      // prevents potential overpayment in fees if the coins
      // selected to meet nFeeNeeded result in a transaction that
      // requires less fee than the prior iteration.

      // If we have no change and a big enough excess fee, then
      // try to construct transaction again only without picking
      // new inputs. We now know we only need the smaller fee
      // (because of reduced tx size) and so we should add a
      // change output. Only try this once.
      if (nChangePosInOut == -1 && nSubtractFeeFromAmount == 0 &&
          pick_new_inputs) {
        unsigned int tx_size_with_change =
            signedVSize + coin_selection_params.change_output_size +
            2;  // Add 2 as a buffer in case increasing # of outputs changes
                // compact size
        CAmount fee_needed_with_change = fee_rate_.GetFee(tx_size_with_change);
        // A typical spendable segwit txout is 31 bytes big, and will
        // need a CTxIn of at least 67 bytes to spend:
        // so dust is a spendable txout less than
        // 98*dustRelayFee/1000 (in satoshis).
        // 294 satoshis at the default rate of 3000 sat/kB.
        CAmount minimum_value_for_change = 294;
        if (nFeeRet >= fee_needed_with_change + minimum_value_for_change) {
          pick_new_inputs = false;
          nFeeRet = fee_needed_with_change;
          continue;
        }
      }

      // If we have change output already, just increase it
      if (nFeeRet > nFeeNeeded && nChangePosInOut != -1 &&
          nSubtractFeeFromAmount == 0) {
        CAmount extraFeePaid = nFeeRet - nFeeNeeded;
        vout.back().second = vout.back().second + extraFeePaid;
        nFeeRet -= extraFeePaid;
      }
      break;  // Done, enough fee included.
    } else if (!pick_new_inputs) {
      // This shouldn't happen, we should have had enough excess
      // fee to pay for the new output and still meet nFeeNeeded
      // Or we should have just subtracted fee from recipients and
      // nFeeNeeded should not have changed
      error = "Transaction fee and change calculation failed";
      return false;
    }

    // Try to reduce change to include necessary fee
    if (nChangePosInOut != -1 && nSubtractFeeFromAmount == 0) {
      CAmount additionalFeeNeeded = nFeeNeeded - nFeeRet;
      // Only reduce change if remaining amount is still a large enough output.
      if (vout.back().second >= 500000LL + additionalFeeNeeded) {
        vout.back().second = vout.back().second - additionalFeeNeeded;
        nFeeRet += additionalFeeNeeded;
        break;  // Done, able to increase fee from change
      }
    }

    // If subtracting fee from recipients, we now know what fee we
    // need to subtract, we have no reason to reselect inputs
    if (nSubtractFeeFromAmount > 0) {
      pick_new_inputs = false;
    }

    // Include more fee and try again.
    nFeeRet = nFeeNeeded;
    coin_selection_params.use_bnb = false;
    continue;
  }

  std::vector<CInputCoin> selected_coins(setCoins.begin(), setCoins.end());
  for (const auto& coin : selected_coins) {
    vecInput.push_back(TxInput(coin.outpoint.hash.GetHex(), coin.outpoint.n));
  }
  vecSend.clear();
  for (const auto& out : vout) {
    vecSend.push_back(out);
  }
  return true;
}

}  // namespace nunchuk
