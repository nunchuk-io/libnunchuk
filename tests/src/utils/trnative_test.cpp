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

#include <nunchuk.h>
#include <miniscript/compiler.h>
#include <util/translation.h>

#include <algorithm>
#include <optional>
#include <set>
#include <string>

#include <doctest.h>

// Bitcoin Core leaves G_TRANSLATION_FUN to be defined by the final binary
// (see bitcoind.cpp / test setup_common.cpp); provide it for this test binary.
const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
std::set<std::string> LeafSet(const TrNativeResult& r) {
  return std::set<std::string>(r.subscripts.begin(), r.subscripts.end());
}
}  // namespace

// Port of rust-miniscript Policy::compile_tr_native (rust-bitcoin/
// rust-miniscript#906). These cases mirror the upstream PR's test vectors;
// the expected internal key, leaf count, leaf set and error categories are
// taken from the reference Rust implementation.
TEST_CASE("testing CompileTrNative") {
  const std::optional<std::string> unspend{"UNSPEND"};

  SUBCASE("simple or: one key becomes internal key, other is single leaf") {
    auto r = CompileTrNative("or(pk(A),pk(B))", unspend, 128);
    CHECK(r.ok);
    CHECK(r.internal_key == "B");
    CHECK(r.subscripts == std::vector<std::string>{"pk(A)"});
    CHECK(r.depths == std::vector<int>{0});
  }

  SUBCASE("and over or decomposes into two IF-free leaves") {
    auto r = CompileTrNative("and(or(pk(A),pk(B)),pk(C))", unspend, 128);
    CHECK(r.ok);
    CHECK(r.internal_key == "UNSPEND");
    CHECK(r.subscripts.size() == 2);
    CHECK(LeafSet(r) == std::set<std::string>{"and_v(v:pk(A),pk(C))",
                                              "and_v(v:pk(B),pk(C))"});
  }

  SUBCASE("or of ands: two leaves") {
    auto r = CompileTrNative("or(and(pk(A),pk(B)),and(pk(C),pk(D)))", unspend, 128);
    CHECK(r.ok);
    CHECK(r.subscripts.size() == 2);
    CHECK(LeafSet(r) == std::set<std::string>{"and_v(v:pk(A),pk(B))",
                                              "and_v(v:pk(C),pk(D))"});
  }

  SUBCASE("thresh expands to all pair leaves") {
    auto r = CompileTrNative("thresh(2,pk(A),pk(B),pk(C),pk(D),pk(E))", unspend, 1024);
    CHECK(r.ok);
    CHECK(r.subscripts.size() == 10);
  }

  SUBCASE("thresh capped below expansion falls back to a single multi_a leaf") {
    auto r = CompileTrNative("thresh(2,pk(A),pk(B),pk(C),pk(D),pk(E))", unspend, 2);
    CHECK(r.ok);
    CHECK(r.subscripts == std::vector<std::string>{"multi_a(2,A,B,C,D,E)"});
  }

  SUBCASE("and of ors fully decomposes with enough leaves") {
    auto r = CompileTrNative("and(or(pk(A),pk(B)),or(pk(C),pk(D)))", unspend, 128);
    CHECK(r.ok);
    CHECK(r.subscripts.size() == 4);
    CHECK(LeafSet(r) == std::set<std::string>{
                            "and_v(v:pk(A),pk(C))", "and_v(v:pk(A),pk(D))",
                            "and_v(v:pk(B),pk(C))", "and_v(v:pk(B),pk(D))"});
  }

  SUBCASE("and of ors capped too low leaves a branching fragment") {
    auto r = CompileTrNative("and(or(pk(A),pk(B)),or(pk(C),pk(D)))", unspend, 2);
    CHECK_FALSE(r.ok);
    CHECK(r.error == TrNativeError::IF_FRAGMENT_IN_NATIVE_LEAF);
  }

  SUBCASE("max_leaves of zero is an error") {
    auto r = CompileTrNative("or(pk(A),pk(B))", unspend, 0);
    CHECK_FALSE(r.ok);
    CHECK(r.error == TrNativeError::TOO_MANY_TAPLEAVES);
  }
}
