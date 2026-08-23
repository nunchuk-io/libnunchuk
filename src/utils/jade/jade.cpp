/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */

#include "utils/jade/jade.hpp"

#include <boost/algorithm/string/case_conv.hpp>
#include <cstdint>
#include <stdexcept>

#include <nunchuk.h>
#include <ur-decoder.hpp>
#include <ur-encoder.hpp>
#include <ur.h>

#include "utils/json.hpp"

namespace nunchuk::jade {

std::string HandlePinQr(const std::vector<std::string>& qr_data,
                        const std::string& certificate_file,
                        bool allow_custom_server) {
  ur::URDecoder decoder;
  for (const auto& part : qr_data) decoder.receive_part(part);
  if (!decoder.is_complete() || !decoder.is_success()) {
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid BC-UR2 input");
  }

  const auto& decoded = decoder.result_ur();
  if (decoded.type() != "jade-pin") {
    throw JadeException(JadeException::INVALID_PARAMETER,
                        "Invalid BC-UR2 input");
  }

  try {
    const auto data = nlohmann::json::from_cbor(decoded.cbor(), true, true);
    if (!data.is_object() || data.value("id", std::string{}) != "qrauth") {
      throw JadeException(JadeException::INVALID_PARAMETER,
                          "[Jade] Invalid auth request id");
    }
    const auto request = ParseHttpRequest(data.at("result"));
    const auto perform = [&](bool custom_servers_only) {
      try {
        return PerformHttpRequest(request, certificate_file,
                                  custom_servers_only);
      } catch (const std::exception& e) {
        throw JadeException(JadeException::SERVER_REQUEST_ERROR,
                            "[Jade] " + std::string(e.what()));
      }
    };
    auto response = perform(false);

    if (response.custom_server.has_value()) {
      if (!allow_custom_server) {
        std::string error = "Custom Jade pinserver requires approval";
        if (!response.custom_server->host.empty()) {
          error += ": " + response.custom_server->host;
        }
        throw JadeException(JadeException::CUSTOM_SERVER_REQUIRES_APPROVAL,
                            "[Jade] " + error);
      }
      response = perform(true);
    }
    return response.body.dump();
  } catch (const JadeException&) {
    throw;
  } catch (const nlohmann::json::exception& e) {
    throw JadeException(JadeException::INVALID_PARAMETER,
                        "[Jade] Invalid data: " + std::string(e.what()));
  } catch (const std::exception& e) {
    throw JadeException(
        JadeException::INVALID_PARAMETER,
        "[Jade] Invalid auth request: " + std::string(e.what()));
  }
}

std::vector<std::string> ExportPinQr(const std::string& pin, int fragment_len) {
  const nlohmann::json pin_rpc = {
      {"id", "0"},
      {"method", "pin"},
      {"params", nlohmann::json::parse(pin)},
  };

  const std::vector<uint8_t> cbor = nlohmann::json::to_cbor(pin_rpc);
  ur::UREncoder encoder(ur::UR("jade-pin", cbor), fragment_len);
  std::vector<std::string> parts;
  do {
    parts.push_back(boost::algorithm::to_upper_copy(encoder.next_part()));
  } while (encoder.seq_num() <= 2 * encoder.seq_len());
  return parts;
}

}  // namespace nunchuk::jade
