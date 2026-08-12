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

#include "utils/ledger/continuation.hpp"

#include <algorithm>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>
#include <tinyformat.h>
#include <util/strencodings.h>

namespace nunchuk::ledger {
namespace {

constexpr size_t SHA256_LENGTH = 32;
constexpr size_t APDU_MAX_PAYLOAD = 255;
constexpr unsigned char CLIENT_COMMAND_YIELD = 0x10;
constexpr unsigned char CLIENT_COMMAND_GET_PREIMAGE = 0x40;
constexpr unsigned char CLIENT_COMMAND_GET_MERKLE_LEAF_PROOF = 0x41;
constexpr unsigned char CLIENT_COMMAND_GET_MERKLE_LEAF_INDEX = 0x42;
constexpr unsigned char CLIENT_COMMAND_GET_MORE_ELEMENTS = 0xa0;

size_t HighestPowerOfTwoLessThan(size_t value) {
  if (value < 2) {
    throw std::runtime_error("Merkle tree split requires at least 2 leaves");
  }
  if ((value & (value - 1)) == 0) {
    return value / 2;
  }
  size_t result = 1;
  while ((result << 1) < value) {
    result <<= 1;
  }
  return result;
}

std::vector<unsigned char> BuildMerkleNode(std::vector<LedgerMerkleLeaf>& leaves,
                                           size_t begin, size_t end) {
  const auto count = end - begin;
  if (count == 1) {
    return leaves[begin].hash;
  }

  const auto left_count = HighestPowerOfTwoLessThan(count);
  const auto middle = begin + left_count;
  const auto left_hash = BuildMerkleNode(leaves, begin, middle);
  const auto right_hash = BuildMerkleNode(leaves, middle, end);

  for (auto i = begin; i < middle; ++i) {
    leaves[i].proof.push_back(right_hash);
  }
  for (auto i = middle; i < end; ++i) {
    leaves[i].proof.push_back(left_hash);
  }

  std::vector<unsigned char> node;
  node.reserve(1 + SHA256_LENGTH + SHA256_LENGTH);
  node.push_back(0x01);
  node.insert(node.end(), left_hash.begin(), left_hash.end());
  node.insert(node.end(), right_hash.begin(), right_hash.end());
  return Sha256(node);
}

template <typename Leaves>
LedgerMerkleTree BuildLedgerMerkleTreeImpl(const Leaves& leaves) {
  LedgerMerkleTree tree;
  if (leaves.empty()) {
    tree.root.assign(SHA256_LENGTH, 0);
    return tree;
  }

  tree.leaves.reserve(leaves.size());
  for (const auto& raw_leaf : leaves) {
    LedgerMerkleLeaf leaf;
    leaf.value.reserve(1 + raw_leaf.size());
    leaf.value.push_back(0x00);
    leaf.value.insert(leaf.value.end(), raw_leaf.begin(), raw_leaf.end());
    leaf.hash = Sha256(leaf.value);
    tree.leaves.push_back(std::move(leaf));
  }
  tree.root = BuildMerkleNode(tree.leaves, 0, tree.leaves.size());
  return tree;
}

}  // namespace

std::vector<unsigned char> Sha256(std::span<const unsigned char> data) {
  std::vector<unsigned char> hash(SHA256_LENGTH);
  CSHA256().Write(data.data(), data.size()).Finalize(hash.data());
  return hash;
}

std::vector<unsigned char> Sha256(const std::string& data) {
  return Sha256(std::span<const unsigned char>{
      reinterpret_cast<const unsigned char*>(data.data()), data.size()});
}

std::vector<unsigned char> EncodeLedgerVarint(uint64_t value) {
  std::vector<unsigned char> result;
  if (value <= 0xfc) {
    result.push_back(static_cast<unsigned char>(value));
  } else if (value <= std::numeric_limits<uint16_t>::max()) {
    result.push_back(0xfd);
    const auto offset = result.size();
    result.resize(offset + sizeof(uint16_t));
    WriteLE16(result.data() + offset, static_cast<uint16_t>(value));
  } else if (value <= std::numeric_limits<uint32_t>::max()) {
    result.push_back(0xfe);
    const auto offset = result.size();
    result.resize(offset + sizeof(uint32_t));
    WriteLE32(result.data() + offset, static_cast<uint32_t>(value));
  } else {
    result.push_back(0xff);
    const auto offset = result.size();
    result.resize(offset + sizeof(uint64_t));
    WriteLE64(result.data() + offset, value);
  }
  return result;
}

uint64_t ReadLedgerVarint(const std::vector<unsigned char>& data,
                          size_t& offset, std::string_view context) {
  if (offset >= data.size()) {
    throw std::runtime_error(
        strprintf("%s is missing a varint", std::string(context)));
  }
  const auto prefix = data[offset++];
  if (prefix <= 0xfc) {
    return prefix;
  }
  if (prefix == 0xfd) {
    if (offset + sizeof(uint16_t) > data.size()) {
      throw std::runtime_error(
          strprintf("%s has a truncated varint", std::string(context)));
    }
    const auto value = ReadLE16(data.data() + offset);
    offset += sizeof(uint16_t);
    return value;
  }
  if (prefix == 0xfe) {
    if (offset + sizeof(uint32_t) > data.size()) {
      throw std::runtime_error(
          strprintf("%s has a truncated varint", std::string(context)));
    }
    const auto value = ReadLE32(data.data() + offset);
    offset += sizeof(uint32_t);
    return value;
  }
  if (offset + sizeof(uint64_t) > data.size()) {
    throw std::runtime_error(
        strprintf("%s has a truncated varint", std::string(context)));
  }
  const auto value = ReadLE64(data.data() + offset);
  offset += sizeof(uint64_t);
  return value;
}

LedgerMerkleTree BuildLedgerMerkleTree(
    const std::vector<std::vector<unsigned char>>& leaves) {
  return BuildLedgerMerkleTreeImpl(leaves);
}

LedgerMerkleTree BuildLedgerMerkleTree(const std::vector<std::string>& leaves) {
  return BuildLedgerMerkleTreeImpl(leaves);
}

LedgerMerkleTree BuildLedgerMerkleTree(const std::string& data,
                                       size_t chunk_size) {
  if (chunk_size == 0) {
    throw std::invalid_argument("Ledger merkle tree chunk size is zero");
  }

  std::vector<std::string_view> leaves;
  leaves.reserve((data.size() + chunk_size - 1) / chunk_size);
  for (size_t offset = 0; offset < data.size(); offset += chunk_size) {
    const auto size = std::min(chunk_size, data.size() - offset);
    leaves.emplace_back(data.data() + offset, size);
  }
  return BuildLedgerMerkleTreeImpl(leaves);
}

void LedgerContinuationContext::reset() {
  preimages_.clear();
  merkle_trees_.clear();
  queue_.clear();
  yielded_results_.clear();
}

void LedgerContinuationContext::addPreimage(
    const std::vector<unsigned char>& hash,
    const std::vector<unsigned char>& preimage) {
  preimages_[HexStr(hash)] = preimage;
}

void LedgerContinuationContext::addPreimage(
    const std::vector<unsigned char>& hash, const std::string& preimage) {
  preimages_[HexStr(hash)] =
      std::vector<unsigned char>(preimage.begin(), preimage.end());
}

void LedgerContinuationContext::addMerkleTree(
    const LedgerMerkleTree& tree) {
  for (const auto& leaf : tree.leaves) {
    addPreimage(leaf.hash, leaf.value);
  }
  merkle_trees_[HexStr(tree.root)] = tree;
}

std::vector<unsigned char> LedgerContinuationContext::resolve(
    const std::vector<unsigned char>& request) {
  if (request.empty()) {
    throw std::runtime_error("Ledger client command is empty");
  }

  switch (request[0]) {
    case CLIENT_COMMAND_YIELD:
      yielded_results_.emplace_back(request.begin() + 1, request.end());
      return {};

    case CLIENT_COMMAND_GET_PREIMAGE: {
      if (request.size() < 34) {
        throw std::runtime_error("Ledger preimage command is truncated");
      }
      const auto hash =
          std::span<const unsigned char>{request}.subspan(2, SHA256_LENGTH);
      const auto it = preimages_.find(HexStr(hash));
      if (it == preimages_.end()) {
        throw std::runtime_error("Ledger requested an unknown preimage");
      }

      const auto& preimage = it->second;
      const auto length = EncodeLedgerVarint(preimage.size());
      const auto max_payload = APDU_MAX_PAYLOAD - length.size() - 1;
      const auto included = std::min(max_payload, preimage.size());

      std::vector<unsigned char> payload;
      payload.reserve(length.size() + 1 + included);
      payload.insert(payload.end(), length.begin(), length.end());
      payload.push_back(static_cast<unsigned char>(included));
      payload.insert(payload.end(), preimage.begin(), preimage.begin() + included);

      for (size_t i = included; i < preimage.size(); ++i) {
        queue_.push_back({preimage[i]});
      }
      return payload;
    }

    case CLIENT_COMMAND_GET_MERKLE_LEAF_PROOF: {
      if (request.size() < 33) {
        throw std::runtime_error("Ledger merkle proof command is truncated");
      }
      const auto root =
          std::span<const unsigned char>{request}.subspan(1, SHA256_LENGTH);
      size_t offset = 33;
      (void)ReadLedgerVarint(request, offset, "Ledger client command");
      const auto proof_index =
          ReadLedgerVarint(request, offset, "Ledger client command");
      const auto tree_it = merkle_trees_.find(HexStr(root));
      if (tree_it == merkle_trees_.end() ||
          proof_index >= tree_it->second.leaves.size()) {
        throw std::runtime_error("Ledger requested an unknown merkle proof");
      }

      const auto& leaf = tree_it->second.leaves[proof_index];
      const auto& proof = leaf.proof;
      if (proof.size() > 0xff) {
        throw std::runtime_error("Ledger merkle proof is too large");
      }

      const auto max_elements =
          (APDU_MAX_PAYLOAD - SHA256_LENGTH - 1 - 1) / SHA256_LENGTH;
      const auto included = std::min(max_elements, proof.size());
      std::vector<unsigned char> payload;
      payload.reserve(SHA256_LENGTH + 2 + included * SHA256_LENGTH);
      payload.insert(payload.end(), leaf.hash.begin(), leaf.hash.end());
      payload.push_back(static_cast<unsigned char>(proof.size()));
      payload.push_back(static_cast<unsigned char>(included));
      for (size_t i = 0; i < included; ++i) {
        payload.insert(payload.end(), proof[i].begin(), proof[i].end());
      }
      for (size_t i = included; i < proof.size(); ++i) {
        queue_.push_back(proof[i]);
      }
      return payload;
    }

    case CLIENT_COMMAND_GET_MERKLE_LEAF_INDEX: {
      if (request.size() < 65) {
        throw std::runtime_error("Ledger merkle index command is truncated");
      }
      const auto root =
          std::span<const unsigned char>{request}.subspan(1, SHA256_LENGTH);
      const auto leaf_hash =
          std::span<const unsigned char>{request}.subspan(33, SHA256_LENGTH);
      const auto tree_it = merkle_trees_.find(HexStr(root));
      if (tree_it == merkle_trees_.end()) {
        return {0x00};
      }

      const auto& leaves = tree_it->second.leaves;
      for (size_t i = 0; i < leaves.size(); ++i) {
        if (std::equal(leaves[i].hash.begin(), leaves[i].hash.end(),
                       leaf_hash.begin(), leaf_hash.end())) {
          auto encoded_index = EncodeLedgerVarint(i);
          std::vector<unsigned char> payload;
          payload.reserve(1 + encoded_index.size());
          payload.push_back(0x01);
          payload.insert(payload.end(), encoded_index.begin(), encoded_index.end());
          return payload;
        }
      }
      return {0x00};
    }

    case CLIENT_COMMAND_GET_MORE_ELEMENTS: {
      if (queue_.empty()) {
        throw std::runtime_error(
            "Ledger requested more elements from an empty queue");
      }
      const auto element_size = queue_.front().size();
      if (element_size == 0 || element_size > 0xff) {
        throw std::runtime_error("Ledger queue element size is invalid");
      }
      for (const auto& element : queue_) {
        if (element.size() != element_size) {
          throw std::runtime_error("Ledger queue elements have different sizes");
        }
      }

      const auto max_elements = (APDU_MAX_PAYLOAD - 2) / element_size;
      const auto included = std::min(max_elements, queue_.size());
      std::vector<unsigned char> payload;
      payload.reserve(2 + included * element_size);
      payload.push_back(static_cast<unsigned char>(included));
      payload.push_back(static_cast<unsigned char>(element_size));
      for (size_t i = 0; i < included; ++i) {
        const auto& element = queue_.front();
        payload.insert(payload.end(), element.begin(), element.end());
        queue_.pop_front();
      }
      return payload;
    }

    default:
      throw std::runtime_error("Ledger requested an unknown client command");
  }
}

const std::vector<std::vector<unsigned char>>&
LedgerContinuationContext::yieldedResults() const {
  return yielded_results_;
}

}  // namespace nunchuk::ledger
