/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * Portions of the HTTP implementation are adapted from Blockstream GDK.
 * See LICENSE-GDK in this directory.
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */

#ifndef NUNCHUK_JADE_HTTP_CLIENT_H
#define NUNCHUK_JADE_HTTP_CLIENT_H

#include <optional>
#include <string>
#include <vector>

#include "utils/jade/types.hpp"
#include "utils/json.hpp"

namespace nunchuk::jade {

struct JadeHttpRequest {
  std::vector<std::string> urls;
  std::string method;
  std::string accept;
  std::optional<nlohmann::json> data;
  std::vector<std::string> root_certificates;
  std::string on_reply;
};

struct JadeHttpResult {
  nlohmann::json body;
  std::optional<CustomPinServerInfo> custom_server;
};

JadeHttpResult PerformHttpRequest(const JadeHttpRequest& request,
                                  const std::string& certificate_file,
                                  bool custom_servers_only = false);

JadeHttpRequest ParseHttpRequest(const nlohmann::json& result);
nlohmann::json BuildHttpReplyParams(const JadeHttpRequest& request,
                                    const nlohmann::json& body);

}  // namespace nunchuk::jade

#endif  // NUNCHUK_JADE_HTTP_CLIENT_H
