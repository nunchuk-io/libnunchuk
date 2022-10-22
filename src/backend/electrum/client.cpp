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

#include <backend/electrum/client.h>
#include <iterator>
#include <utils/loguru.hpp>
#include <utils/errorutils.hpp>
#include <boost/tokenizer.hpp>
#include <boost/algorithm/string.hpp>

using namespace boost::asio;

namespace nunchuk {

static const std::string DEFAULT_SERVER = "127.0.0.1:50001";

static const std::string NETWORK_REJECTED_PREFIX =
    "the transaction was rejected by network rules.";

static std::string GetServerAddress(const AppSettings& appsettings) {
  auto getFirstElementOrDefault = [](const std::vector<std::string>& elements,
                                     const std::string& def) {
    if (elements.empty()) {
      return def;
    }
    return elements.front();
  };

  switch (appsettings.get_chain()) {
    case Chain::TESTNET:
      return getFirstElementOrDefault(appsettings.get_testnet_servers(),
                                      DEFAULT_SERVER);
    case Chain::MAIN:
      return getFirstElementOrDefault(appsettings.get_mainnet_servers(),
                                      DEFAULT_SERVER);
    case Chain::SIGNET:
      return getFirstElementOrDefault(appsettings.get_signet_servers(),
                                      DEFAULT_SERVER);

    default:
      throw NunchukException(NunchukException::INVALID_CHAIN,
                             "Chain not supported");
  }
}

static NunchukException MakeElectrumException(const std::string& error) {
  if (!boost::istarts_with(error, NETWORK_REJECTED_PREFIX)) {
    return NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                            NormalizeErrorMessage(error));
  }

  boost::char_separator<char> sep("\n");
  boost::tokenizer<boost::char_separator<char>> tokens(error, sep);

  if (tokens.begin() != tokens.end() &&
      std::next(tokens.begin()) != tokens.end()) {
    return NunchukException(NunchukException::NETWORK_REJECTED,
                            NormalizeErrorMessage(*std::next(tokens.begin())));
  }

  return NunchukException(NunchukException::NETWORK_REJECTED,
                          NormalizeErrorMessage(error));
}

ElectrumClient::ElectrumClient(const AppSettings& appsettings,
                               const std::function<void()> on_disconnect)
    : io_thread_(),
      signal_thread_(),
      signal_worker_(make_work_guard(signal_service_)),
      interval_(60),
      timer_(io_service_, interval_) {
  disconnect_signal_.connect(on_disconnect);
  std::string server_url = GetServerAddress(appsettings);

  size_t colonDoubleSlash = server_url.find("://");
  if (colonDoubleSlash != std::string::npos) {
    protocol_ = server_url.substr(0, colonDoubleSlash);
    server_url = server_url.substr(colonDoubleSlash + 3);
  }
  size_t colon = server_url.find(":");
  if (colon != std::string::npos) {
    host_ = server_url.substr(0, colon);
    std::string portStr = server_url.substr(colon + 1);
    port_ = portStr.empty() ? 50001 : std::stoi(portStr);
    if (port_ < 0 || port_ > 65353) port_ = 50001;
  } else {
    host_ = server_url;
  }
  use_proxy_ = appsettings.use_proxy();
  if (use_proxy_) {
    proxy_host_ = appsettings.get_proxy_host();
    proxy_port_ = appsettings.get_proxy_port();
    proxy_username_ = appsettings.get_proxy_username();
    proxy_password_ = appsettings.get_proxy_password();
  }

  is_secure_ = boost::iequals(protocol_, "ssl");
  if (is_secure_) {
    ssl::context ctx(ssl::context::tls);
    if (!appsettings.get_certificate_file().empty()) {
      ctx.set_verify_mode(ssl::verify_peer);
      ctx.load_verify_file(appsettings.get_certificate_file());
    } else {
      ctx.set_verify_mode(ssl::verify_none);
    }
    secure_socket_ = std::unique_ptr<ssl::stream<ip::tcp::socket>>(
        new ssl::stream<ip::tcp::socket>(io_service_, ctx));
  } else {
    socket_ =
        std::unique_ptr<ip::tcp::socket>(new ip::tcp::socket(io_service_));
  }
  socket_connect();
  start();
}

ElectrumClient::~ElectrumClient() {
  try {
    stop();
  } catch (...) {
    LOG_F(ERROR, "ElectrumClient::~ElectrumClient");
  }
}

void ElectrumClient::handle_error(const std::string& where,
                                  const std::string& message) {
  LOG_F(ERROR, "%s: %s", where.c_str(), message.c_str());
  stopped_ = true;
  for (auto &&it = callback_.begin(), next = it; it != callback_.end();
       it = next) {
    ++next;
    it->second.set_value(
        {{"error", {{"code", 1}, {"message", "Disconnected"}}}});
  }
  disconnect_signal_();
}

void ElectrumClient::subscribe(const std::string& method,
                               const NotifySignal::slot_type& lis) {
  sigmap_[method].connect(lis);
}

void ElectrumClient::scripthash_add_listener(
    const NotifySignal::slot_type& lis) {
  subscribe("blockchain.scripthash.subscribe", lis);
}

json ElectrumClient::call_method(const std::string& method,
                                 const json& params) {
  if (stopped_) {
    throw NunchukException(NunchukException::SERVER_REQUEST_ERROR,
                           "Disconnected");
  }

  int id = id_++;
  json req = {{"jsonrpc", "2.0"}, {"method", method}, {"id", id}};
  if (params != nullptr) req["params"] = params;

  callback_[id] =
      std::promise<json>(std::allocator_arg, std::allocator<json>());
  enqueue_message(req.dump());
  json resp = callback_[id].get_future().get();
  callback_.erase(id);
  if (resp.contains("error")) {
    throw MakeElectrumException(resp["error"]["message"]);
  }
  return resp["result"];
}

json ElectrumClient::blockchain_headers_subscribe(
    const NotifySignal::slot_type& lis) {
  subscribe("blockchain.headers.subscribe", lis);
  return call_method("blockchain.headers.subscribe");
}

json ElectrumClient::blockchain_scripthash_subscribe(
    const std::string& scripthash) {
  return call_method("blockchain.scripthash.subscribe", {scripthash});
}

json ElectrumClient::blockchain_scripthash_listunspent(
    const std::string& scripthash) {
  return call_method("blockchain.scripthash.listunspent", {scripthash});
}

json ElectrumClient::blockchain_scripthash_get_history(
    const std::string& scripthash) {
  return call_method("blockchain.scripthash.get_history", {scripthash});
}

json ElectrumClient::blockchain_scripthash_get_mempool(
    const std::string& scripthash) {
  return call_method("blockchain.scripthash.get_mempool", {scripthash});
}

json ElectrumClient::blockchain_scripthash_get_balance(
    const std::string& scripthash) {
  return call_method("blockchain.scripthash.get_balance", {scripthash});
}

json ElectrumClient::blockchain_estimatefee(int number) {
  return call_method("blockchain.estimatefee", {number});
}

json ElectrumClient::blockchain_relayfee() {
  return call_method("blockchain.relayfee");
}

json ElectrumClient::blockchain_transaction_broadcast(
    const std::string& raw_tx) {
  return call_method("blockchain.transaction.broadcast", {raw_tx});
}

json ElectrumClient::blockchain_transaction_get(const std::string& tx_hash,
                                                bool verbose) {
  return call_method("blockchain.transaction.get", {tx_hash, verbose});
}

void ElectrumClient::start() {
  io_thread_ = std::thread([&]() {
    try {
      io_service_.run();
    } catch (std::exception& e) {
      LOG_F(ERROR, "ElectrumClient::io_thread_ %s", e.what());
    }
  });
  signal_thread_ = std::thread([&]() {
    try {
      signal_service_.run();
    } catch (std::exception& e) {
      LOG_F(ERROR, "ElectrumClient::signal_thread_ %s", e.what());
    }
  });
}

void ElectrumClient::stop() {
  stopped_ = true;
  signal_worker_.reset();
  io_service_.stop();
  signal_thread_.join();
  io_thread_.join();
  request_queue_.clear();
}

void ElectrumClient::enqueue_message(const std::string& jsonrpc_request) {
  bool write_in_progress = !request_queue_.empty();
  request_queue_.push_back(jsonrpc_request);
  if (!write_in_progress) {
    socket_write();
  }
}

void ElectrumClient::socket_connect() {
  std::string h = use_proxy_ ? proxy_host_ : host_;
  int p = use_proxy_ ? proxy_port_ : port_;
  ip::tcp::resolver::query resolver_query(h, std::to_string(p));
  ip::tcp::resolver resolver(io_service_);
  boost::system::error_code error;
  auto resolve_rs = resolver.resolve(resolver_query, error);
  if (error.value() != 0) {
    return handle_error("socket_connect", "can not resolve host");
  }
  async_connect(
      is_secure_ ? secure_socket_->next_layer() : socket_->lowest_layer(),
      resolve_rs,
      boost::bind(&ElectrumClient::handle_connect, this, placeholders::error));
}

void ElectrumClient::socket_read() {
  if (is_secure_) {
    async_read_until(
        *secure_socket_, receive_buffer_, "\n",
        boost::bind(&ElectrumClient::handle_read, this, placeholders::error));
  } else {
    async_read_until(
        *socket_, receive_buffer_, "\n",
        boost::bind(&ElectrumClient::handle_read, this, placeholders::error));
  }
}

void ElectrumClient::socket_write() {
  if (request_queue_.empty() || !connected_ || stopped_) {
    return;
  }

  std::ostream request(&request_buffer_);
  request << request_queue_.front() << "\n";

  if (is_secure_) {
    async_write(
        *secure_socket_, request_buffer_,
        boost::bind(&ElectrumClient::handle_write, this, placeholders::error));
  } else {
    async_write(
        *socket_, request_buffer_,
        boost::bind(&ElectrumClient::handle_write, this, placeholders::error));
  }
}

void ElectrumClient::ping(const boost::system::error_code& error) {
  json req = {{"jsonrpc", "2.0"}, {"method", "server.ping"}, {"id", id_++}};
  enqueue_message(req.dump());
  timer_.expires_at(timer_.expires_at() + interval_);
  timer_.async_wait(
      boost::bind(&ElectrumClient::ping, this, placeholders::error));
}

void ElectrumClient::handle_connect(const boost::system::error_code& error) {
  if (error) {
    return handle_error("handle_connect", error.message());
  }
  if (!handle_socks5()) {
    return handle_error("handle_connect", "handle socks5 error");
  }

  if (is_secure_) {
    secure_socket_->lowest_layer().set_option(ip::tcp::no_delay(true));
    secure_socket_->set_verify_callback(
        [](bool preverified, ssl::verify_context& ctx) {
          char subject_name[256];
          X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
          X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
          LOG_F(INFO, "Verifying %s", subject_name);
          return preverified;
        });
    secure_socket_->handshake(ssl::stream_base::client);
  }

  connected_ = true;
  socket_read();
  socket_write();
  timer_.async_wait(
      boost::bind(&ElectrumClient::ping, this, placeholders::error));
}

void ElectrumClient::handle_read(const boost::system::error_code& error) {
  if (error) {
    return handle_error("handle_read", error.message());
  }
  std::stringstream ss;
  ss << buffer_cast<const char*>(receive_buffer_.data());
  std::string message;
  std::getline(ss, message);
  if (!message.empty()) {
    DLOG_F(INFO, "Read message: %s", message.c_str());
    json response = json::parse(message);
    if (response["method"] != nullptr) {
      signal_service_.post([this, response]() {
        sigmap_.at(response["method"])(response["params"]);
      });
    } else {
      int id = response["id"];
      auto cb = callback_.find(id);
      if (cb != callback_.end()) {
        cb->second.set_value(response);
      }
    }
  }
  receive_buffer_.consume(message.size() + 1);
  socket_read();
}

void ElectrumClient::handle_write(const boost::system::error_code& error) {
  if (error) {
    return handle_error("handle_write", error.message());
  }
  DLOG_F(INFO, "Write message: %s", request_queue_.front().c_str());
  request_buffer_.consume(request_queue_.front().size());
  request_queue_.pop_front();
  socket_write();
}

// Reference: https://tools.ietf.org/html/rfc1928
bool ElectrumClient::handle_socks5() {
  if (!use_proxy_) return true;
  bool auth = !proxy_username_.empty() && !proxy_password_.empty();

  auto my_write = [&](const std::vector<uint8_t>& req) {
    write(is_secure_ ? secure_socket_->next_layer() : *socket_, buffer(req));
  };
  auto my_read = [&](uint8_t* res, int i) {
    read(is_secure_ ? secure_socket_->next_layer() : *socket_, buffer(res, i));
  };

  std::vector<uint8_t> auth_req{0x05};
  if (auth) {
    auth_req.push_back(0x02);
    auth_req.push_back(0x00);
    auth_req.push_back(0x02);
  } else {
    auth_req.push_back(0x01);
    auth_req.push_back(0x00);
  }
  my_write(auth_req);
  uint8_t authen_reply[2];
  my_read(authen_reply, 2);
  if (authen_reply[0] != 0x05) {
    LOG_F(ERROR, "Proxy failed to initialize");
    return false;
  }

  if (auth && authen_reply[1] == 0x02) {
    // Reference: https://tools.ietf.org/html/rfc1929
    std::vector<uint8_t> up_req{0x01};
    up_req.push_back(proxy_username_.length());
    up_req.insert(up_req.end(), proxy_username_.begin(), proxy_username_.end());
    up_req.push_back(proxy_password_.length());
    up_req.insert(up_req.end(), proxy_password_.begin(), proxy_password_.end());
    my_write(up_req);
    uint8_t up_reply[2];
    my_read(up_reply, 2);
    if (up_reply[0] != 0x01 || up_reply[1] != 0x00) {
      LOG_F(ERROR, "Authentication unsuccessful");
      return false;
    }
  } else if (authen_reply[1] != 0x00) {
    LOG_F(ERROR, "Authentication wrong method: %02x", authen_reply[1]);
    return false;
  }

  std::vector<uint8_t> connect_req{0x05, 0x01, 0x00, 0x03};
  connect_req.push_back(host_.length());
  connect_req.insert(connect_req.end(), host_.begin(), host_.end());
  connect_req.push_back((port_ >> 8) & 0xff);
  connect_req.push_back(port_ & 0xff);
  my_write(connect_req);
  uint8_t connect_reply[4];
  my_read(connect_reply, 4);
  if (connect_reply[0] != 0x05 || connect_reply[1] != 0x00 ||
      connect_reply[2] != 0x00) {
    LOG_F(ERROR, "Connect socks5 failed: %02x", connect_reply[1]);
    return false;
  }

  uint8_t resp[256];
  switch (connect_reply[3]) {
    case 0x01:  // IP V4
      my_read(resp, 4);
      break;
    case 0x04:  // IP V6
      my_read(resp, 16);
      break;
    case 0x03:  // DOMAINNAME
      my_read(resp, 1);
      my_read(resp, resp[0]);
      break;
    default:
      LOG_F(ERROR, "Error: malformed proxy response");
      return false;
  }
  my_read(resp, 2);
  return true;
}

}  // namespace nunchuk
