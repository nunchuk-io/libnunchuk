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

#ifndef NUNCHUK_LEDGER_CONTINUATION_H
#define NUNCHUK_LEDGER_CONTINUATION_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nunchuk::ledger {

struct LedgerMerkleLeaf {
  std::vector<unsigned char> value;
  std::vector<unsigned char> hash;
  std::vector<std::vector<unsigned char>> proof;
};

struct LedgerMerkleTree {
  std::vector<unsigned char> root;
  std::vector<LedgerMerkleLeaf> leaves;
};

std::vector<unsigned char> Sha256(std::span<const unsigned char> data);
std::vector<unsigned char> Sha256(const std::string& data);
std::vector<unsigned char> EncodeLedgerVarint(uint64_t value);
uint64_t ReadLedgerVarint(const std::vector<unsigned char>& data,
                          size_t& offset,
                          std::string_view context = "Ledger varint");
LedgerMerkleTree BuildLedgerMerkleTree(
    const std::vector<std::vector<unsigned char>>& leaves);
LedgerMerkleTree BuildLedgerMerkleTree(const std::vector<std::string>& leaves);
LedgerMerkleTree BuildLedgerMerkleTree(const std::string& data,
                                       size_t chunk_size);

class LedgerContinuationContext {
 public:
  void reset();
  void addPreimage(const std::vector<unsigned char>& hash,
                   const std::vector<unsigned char>& preimage);
  void addPreimage(const std::vector<unsigned char>& hash,
                   const std::string& preimage);
  void addMerkleTree(const LedgerMerkleTree& tree);
  std::vector<unsigned char> resolve(
      const std::vector<unsigned char>& request);

  const std::vector<std::vector<unsigned char>>& yieldedResults() const;

 private:
  std::map<std::string, std::vector<unsigned char>> preimages_;
  std::map<std::string, LedgerMerkleTree> merkle_trees_;
  std::deque<std::vector<unsigned char>> queue_;
  std::vector<std::vector<unsigned char>> yielded_results_;
};

}  // namespace nunchuk::ledger

#endif  // NUNCHUK_LEDGER_CONTINUATION_H
