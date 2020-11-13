// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_EMBEDDEDRPC_H
#define NUNCHUK_EMBEDDEDRPC_H
#define HAVE_CONFIG_H

// Bitcoin cannot be compiled without assertions
#undef NDEBUG

#include <node/context.h>
#include <rpc/register.h>
#include <rpc/server.h>
#include <util/ref.h>
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

  bool initialized_;
  std::string chain_;
  CRPCTable table_;
  NodeContext node_context_;
  util::Ref context_ref_{node_context_};
};

#endif  // NUNCHUK_EMBEDDEDRPC_H
