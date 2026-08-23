/*
 * This file is part of libnunchuk (https://github.com/nunchuk-io/libnunchuk).
 * Copyright (C) 2026 Nunchuk
 *
 * Portions of this implementation are adapted from Blockstream GDK's
 * http_client, parse_url, and select_url implementations.
 * See LICENSE-GDK in this directory.
 *
 * libnunchuk is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */

#include "utils/jade/http_client.hpp"

#include <algorithm>
#include <boost/algorithm/string/case_conv.hpp>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <limits>
#include <openssl/ssl.h>
#include <stdexcept>
#include <string_view>
#include <utility>

#include "certs/sslcerts.h"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "utils/httplib.h"

namespace nunchuk::jade {
namespace {

using namespace std::chrono_literals;

constexpr auto HTTP_TIMEOUT = 30s;
constexpr size_t MAX_HTTP_RESPONSE_SIZE = 1024U * 1024U;
constexpr int MAX_REDIRECTS = 5;
constexpr int HTTP_ATTEMPTS = 3;

constexpr std::string_view OFFICIAL_CLEARNET_HOSTS[] = {
    "j8d.io", "jadepin.blockstream.com"};
constexpr std::string_view OFFICIAL_ONION_HOST =
    "mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion";

struct ParsedUrl {
  std::string original;
  std::string scheme;
  std::string host;
  std::string port;
  std::string target;
  bool secure = false;
};

struct HttpResponse {
  unsigned int status = 0;
  std::string body;
  std::string location;
};

ParsedUrl ParseUrl(const std::string& value) {
  const auto separator = value.find("://");
  if (separator == std::string::npos) {
    throw std::invalid_argument("Jade pinserver URL has no scheme");
  }

  ParsedUrl result;
  result.original = value;
  result.scheme = boost::algorithm::to_lower_copy(value.substr(0, separator));
  if (result.scheme != "http" && result.scheme != "https") {
    throw std::invalid_argument("Unsupported Jade pinserver URL scheme");
  }
  result.secure = result.scheme == "https";

  const size_t authority_begin = separator + 3;
  const size_t target_begin = value.find_first_of("/?#", authority_begin);
  const std::string authority =
      value.substr(authority_begin, target_begin - authority_begin);
  if (authority.empty() || authority.find('@') != std::string::npos) {
    throw std::invalid_argument("Invalid Jade pinserver URL authority");
  }

  if (authority.front() == '[') {
    const auto close = authority.find(']');
    if (close == std::string::npos) {
      throw std::invalid_argument("Invalid Jade pinserver IPv6 URL");
    }
    result.host =
        boost::algorithm::to_lower_copy(authority.substr(1, close - 1));
    if (close + 1 < authority.size()) {
      if (authority[close + 1] != ':') {
        throw std::invalid_argument("Invalid Jade pinserver URL port");
      }
      result.port = authority.substr(close + 2);
      if (result.port.empty()) {
        throw std::invalid_argument("Invalid Jade pinserver URL port");
      }
    }
  } else {
    const auto colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(':') == colon) {
      result.host = boost::algorithm::to_lower_copy(authority.substr(0, colon));
      result.port = authority.substr(colon + 1);
      if (result.port.empty()) {
        throw std::invalid_argument("Invalid Jade pinserver URL port");
      }
    } else {
      result.host = boost::algorithm::to_lower_copy(authority);
    }
  }
  if (result.host.empty()) {
    throw std::invalid_argument("Jade pinserver URL has no host");
  }
  if (result.port.empty()) result.port = result.secure ? "443" : "80";
  size_t parsed_port_length = 0;
  const int port = std::stoi(result.port, &parsed_port_length);
  if (parsed_port_length != result.port.size()) {
    throw std::invalid_argument("Invalid Jade pinserver URL port");
  }
  if (port <= 0 || port > std::numeric_limits<uint16_t>::max()) {
    throw std::invalid_argument("Invalid Jade pinserver URL port");
  }

  result.target =
      target_begin == std::string::npos ? "/" : value.substr(target_begin);
  if (result.target.empty() || result.target.front() != '/') {
    result.target.insert(result.target.begin(), '/');
  }
  return result;
}

bool IsDefaultPort(const ParsedUrl& url) {
  return (url.secure && url.port == "443") || (!url.secure && url.port == "80");
}

bool IsOfficial(const ParsedUrl& url) {
  if (!IsDefaultPort(url)) return false;
  if (url.host.ends_with(".onion")) {
    return !url.secure && url.host == OFFICIAL_ONION_HOST;
  }
  if (!url.secure) return false;
  return std::any_of(std::begin(OFFICIAL_CLEARNET_HOSTS),
                     std::end(OFFICIAL_CLEARNET_HOSTS),
                     [&](std::string_view host) { return url.host == host; });
}

std::optional<ParsedUrl> SelectUrl(const std::vector<ParsedUrl>& urls,
                                   bool custom_only) {
  auto allowed = [&](const ParsedUrl& url) {
    return !custom_only || !IsOfficial(url);
  };
  const auto secure = std::find_if(
      urls.begin(), urls.end(),
      [&](const ParsedUrl& url) { return allowed(url) && url.secure; });
  if (secure != urls.end()) return *secure;
  const auto insecure = std::find_if(
      urls.begin(), urls.end(),
      [&](const ParsedUrl& url) { return allowed(url) && !url.secure; });
  if (insecure != urls.end()) return *insecure;
  return std::nullopt;
}

httplib::Request MakeRequest(const JadeHttpRequest& request,
                             const ParsedUrl& url) {
  if (request.method != "GET" && request.method != "POST") {
    throw std::invalid_argument("Unsupported Jade pinserver HTTP method");
  }
  if (request.method == "GET" && request.data.has_value()) {
    throw std::invalid_argument("Jade pinserver GET request contains a body");
  }
  httplib::Request output;
  output.method = request.method;
  output.path = url.target;
  output.headers.emplace("User-Agent", "libnunchuk-jade");
  if (request.accept == "json" || request.accept == "application/json") {
    output.headers.emplace("Accept", "application/json");
  } else if (!request.accept.empty()) {
    throw std::invalid_argument("Unsupported Jade pinserver response type");
  }
  if (request.data.has_value()) {
    output.headers.emplace("Content-Type", "application/json");
    output.body = request.data->dump();
  }
  return output;
}

HttpResponse ExecuteRequestOnce(const JadeHttpRequest& request,
                                const std::string& certificate_file,
                                const ParsedUrl& url) {
  const std::string host =
      url.host.find(':') == std::string::npos ? url.host : "[" + url.host + "]";
  const std::string base_url = url.scheme + "://" + host + ":" + url.port;
  httplib::Client client(base_url.c_str());
  if (!client.is_valid()) {
    throw std::runtime_error("Unable to create Jade HTTP client");
  }
  client.set_connection_timeout(HTTP_TIMEOUT);
  client.set_read_timeout(HTTP_TIMEOUT);
  client.set_write_timeout(HTTP_TIMEOUT);
  client.set_keep_alive(false);
  client.set_follow_location(false);
  client.set_url_encode(false);
  client.set_decompress(false);
  if (url.secure) {
    if (SSL_CTX_set_min_proto_version(client.ssl_context(), TLS1_2_VERSION) !=
        1) {
      throw std::runtime_error("Unable to configure Jade TLS client");
    }
    client.set_ca_cert_store(
        CreateCaCertStore(certificate_file, request.root_certificates));
    client.enable_server_certificate_verification(true);
  }

  auto wire_request = MakeRequest(request, url);
  std::string response_body;
  bool response_too_large = false;
  wire_request.content_receiver = [&](const char* data, size_t size, uint64_t,
                                      uint64_t total_size) {
    if (total_size > MAX_HTTP_RESPONSE_SIZE ||
        size > MAX_HTTP_RESPONSE_SIZE - response_body.size()) {
      response_too_large = true;
      return false;
    }
    response_body.append(data, size);
    return true;
  };

  const auto response = client.send(wire_request);
  if (!response) {
    if (response_too_large) {
      throw std::runtime_error("Jade pinserver response exceeds size limit");
    }
    throw std::runtime_error(
        "Jade pinserver request failed: " +
        std::to_string(static_cast<int>(response.error())));
  }
  return {static_cast<unsigned int>(response->status), std::move(response_body),
          response->get_header_value("Location")};
}

HttpResponse ExecuteRequest(const JadeHttpRequest& request,
                            const std::string& certificate_file,
                            const ParsedUrl& url) {
  for (int attempt = 1; attempt <= HTTP_ATTEMPTS; ++attempt) {
    try {
      auto response = ExecuteRequestOnce(request, certificate_file, url);
      if (attempt < HTTP_ATTEMPTS &&
          (response.status == 429 || response.status >= 500)) {
        continue;
      }
      return response;
    } catch (...) {
      if (attempt == HTTP_ATTEMPTS) throw;
    }
  }
  throw std::runtime_error("Jade pinserver request failed");
}

nlohmann::json DecodeResponse(const JadeHttpRequest& request,
                              const HttpResponse& response) {
  if (response.status < 200 || response.status >= 300) {
    throw std::runtime_error("Jade pinserver returned HTTP status " +
                             std::to_string(response.status));
  }
  if (response.body.empty()) return nlohmann::json::object();
  if (request.accept != "json" && request.accept != "application/json") {
    throw std::runtime_error("Jade pinserver response is not JSON");
  }
  return nlohmann::json::parse(response.body);
}

nlohmann::json PerformWithRedirects(const JadeHttpRequest& request,
                                    const std::string& certificate_file,
                                    ParsedUrl url, bool custom_request) {
  const std::string approved_scheme = url.scheme;
  const std::string approved_host = url.host;
  const std::string approved_port = url.port;
  for (int redirects = 0; redirects <= MAX_REDIRECTS; ++redirects) {
    const auto response = ExecuteRequest(request, certificate_file, url);
    if (response.status >= 300 && response.status < 400 &&
        !response.location.empty()) {
      if (redirects == MAX_REDIRECTS) {
        throw std::runtime_error("Jade pinserver redirect limit exceeded");
      }
      auto redirected = ParseUrl(response.location);
      if ((custom_request && (redirected.scheme != approved_scheme ||
                              redirected.host != approved_host ||
                              redirected.port != approved_port)) ||
          (!custom_request && !IsOfficial(redirected))) {
        throw std::runtime_error(
            "Jade pinserver redirected to an unapproved host");
      }
      url = std::move(redirected);
      continue;
    }
    return DecodeResponse(request, response);
  }
  throw std::runtime_error("Jade pinserver redirect limit exceeded");
}

}  // namespace

JadeHttpResult PerformHttpRequest(const JadeHttpRequest& request,
                                  const std::string& certificate_file,
                                  bool custom_servers_only) {
  std::vector<ParsedUrl> urls;
  urls.reserve(request.urls.size());
  for (const auto& value : request.urls) urls.push_back(ParseUrl(value));

  const auto selected = SelectUrl(urls, custom_servers_only);
  if (!selected.has_value()) {
    throw std::runtime_error("No usable Jade pinserver URL is available");
  }

  const bool custom_request = !IsOfficial(*selected);
  if (!custom_servers_only && custom_request) {
    CustomPinServerInfo info;
    info.method = request.method;
    info.host = selected->host.find(':') == std::string::npos
                    ? selected->host
                    : "[" + selected->host + "]";
    if (!IsDefaultPort(*selected)) info.host += ":" + selected->port;
    for (const auto& url : urls) {
      if (!IsOfficial(url)) info.urls.push_back(url.original);
    }
    return {{}, std::move(info)};
  }

  return {PerformWithRedirects(request, certificate_file, *selected,
                               custom_request),
          std::nullopt};
}

JadeHttpRequest ParseHttpRequest(const nlohmann::json& result) {
  if (!result.is_object() || !result.contains("http_request") ||
      !result.at("http_request").is_object()) {
    throw std::runtime_error("Invalid Jade HTTP request response");
  }
  const auto& wrapper = result.at("http_request");
  const auto& params = wrapper.at("params");
  if (!params.is_object() || !params.contains("urls") ||
      !params.at("urls").is_array()) {
    throw std::runtime_error("Invalid Jade pinserver request parameters");
  }

  JadeHttpRequest request;
  request.method = params.value("method", std::string{});
  request.accept = params.value("accept", std::string{});
  request.on_reply = wrapper.value("on-reply", std::string{});
  for (const auto& url : params.at("urls")) {
    request.urls.push_back(url.get<std::string>());
  }
  if (params.contains("data")) request.data = params.at("data");
  if (params.contains("root_certificates")) {
    for (const auto& root : params.at("root_certificates")) {
      request.root_certificates.push_back(root.get<std::string>());
    }
  }
  if (request.urls.empty() || request.method.empty() ||
      request.on_reply.empty()) {
    throw std::runtime_error("Incomplete Jade pinserver request");
  }
  if (request.on_reply != "pin" && request.on_reply != "handshake_init" &&
      request.on_reply != "handshake_complete") {
    throw std::runtime_error("Unsupported Jade pinserver continuation");
  }
  return request;
}

nlohmann::json BuildHttpReplyParams(const JadeHttpRequest& request,
                                    const nlohmann::json& body) {
  if (!body.is_object()) {
    throw std::runtime_error("Jade pinserver returned a non-object response");
  }
  if (request.on_reply == "pin") {
    return {{"data", body.at("data")}};
  }
  if (request.on_reply == "handshake_init") {
    return {{"sig", body.at("sig")}, {"ske", body.at("ske")}};
  }
  if (request.on_reply == "handshake_complete") {
    return {{"encrypted_key", body.at("encrypted_key")},
            {"hmac", body.at("hmac")}};
  }
  throw std::runtime_error("Unsupported Jade pinserver continuation");
}

}  // namespace nunchuk::jade
