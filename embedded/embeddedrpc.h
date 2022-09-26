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

#ifndef NUNCHUK_EMBEDDEDRPC_H
#define NUNCHUK_EMBEDDEDRPC_H
#define HAVE_CONFIG_H

// Bitcoin cannot be compiled without assertions
#undef NDEBUG

#include <rpc/register.h>
#include <rpc/server.h>
#include <util/translation.h>

#include <string>

//! Interface for handling RPC call using embedded bitcoin library
class EmbeddedRpc {
 public:
  /**
   * Initialize EmbeddedRpc.
   * Call this before any other methods.
   */
  void Init(const std::string &chain = "test");

  /**
   * Switch chain
   */
  void SetChain(const std::string &chain);

  /**
   * Get current chain
   */
  const std::string &GetChain() const;

  /**
   * Execute a rpc method.
   * @param body The rpc request in JSON to execute
   * @returns Result of the call in JSON.
   */
  std::string SendRequest(const std::string &body) const;

  static EmbeddedRpc &getInstance();
  EmbeddedRpc(EmbeddedRpc const &) = delete;
  void operator=(EmbeddedRpc const &) = delete;

 private:
  EmbeddedRpc();
  ~EmbeddedRpc();

  bool initialized_;
  std::string chain_;
  CRPCTable table_;
};

#endif  // NUNCHUK_EMBEDDEDRPC_H
