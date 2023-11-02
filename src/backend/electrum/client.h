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

#ifndef NUNCHUK_ELECTRUM_CLIENT_H
#define NUNCHUK_ELECTRUM_CLIENT_H

#include <nunchuk.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/signals2.hpp>
#include <utils/json.hpp>

#include <iostream>
#include <future>
#include <memory>
#include <map>
#include <deque>

using json = nlohmann::json;

typedef boost::signals2::signal<void(json)> NotifySignal;

namespace nunchuk {
class ElectrumClient {
 public:
  ElectrumClient(const nunchuk::AppSettings& appsettings,
                 const std::function<void()> on_disconnect);
  ~ElectrumClient();

  void subscribe(const std::string& method, const NotifySignal::slot_type& lis);
  void scripthash_add_listener(const NotifySignal::slot_type& lis);
  json call_method(const std::string& method, const json& params = nullptr);

  json blockchain_headers_subscribe(const NotifySignal::slot_type& lis);
  json blockchain_scripthash_subscribe(const std::string& scripthash);
  json blockchain_scripthash_listunspent(const std::string& scripthash);
  json blockchain_scripthash_get_history(const std::string& scripthash);
  json blockchain_scripthash_get_mempool(const std::string& scripthash);
  json blockchain_scripthash_get_balance(const std::string& scripthash);
  json blockchain_estimatefee(int number);
  json blockchain_relayfee();
  json blockchain_transaction_broadcast(const std::string& raw_tx);
  json blockchain_transaction_get(const std::string& tx_hash);
  json blockchain_block_header(int height);

  json server_version();
  bool support_batch_requests();
  std::vector<json> call_batch(const std::vector<std::string>& methods,
                               const std::vector<json>& params);
  std::map<std::string, std::string> get_multi_rawtx(
      const std::vector<std::string>& txs_hash);
  std::map<std::string, json> get_multi_history(
      const std::vector<std::string>& scripthashes);
  std::map<int, std::string> get_multi_rawheader(
      const std::vector<int>& heights);
  std::map<std::string, std::string> subscribe_multi_scripthash(
      const std::vector<std::string>& scripthashes);

 private:
  void start();
  void stop();
  void enqueue_message(const std::string& jsonrpc_request);
  void socket_connect();
  void socket_read();
  void socket_write();
  void ping(const boost::system::error_code& error);
  void handle_connect(const boost::system::error_code& error);
  void handle_read(const boost::system::error_code& error);
  void handle_write(const boost::system::error_code& error);
  bool handle_socks5();
  void handle_error(const std::string& where, const std::string& message);

  std::string protocol_ = "tcp";
  std::string host_;
  int port_ = 50001;
  bool is_secure_;
  bool use_proxy_;
  std::string proxy_host_ = "";
  int proxy_port_ = -1;
  std::string proxy_username_ = "";
  std::string proxy_password_ = "";
  std::thread io_thread_;
  boost::asio::io_service io_service_;
  std::thread signal_thread_;
  boost::asio::io_service signal_service_;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type>
      signal_worker_;
  std::unique_ptr<boost::asio::ip::tcp::socket> socket_;
  std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>
      secure_socket_;
  std::atomic<bool> connected_{false};
  std::atomic<bool> stopped_{false};
  std::atomic<int> id_{0};
  boost::asio::streambuf receive_buffer_;
  boost::asio::streambuf request_buffer_;
  std::deque<std::string> request_queue_;
  std::map<std::string, NotifySignal> sigmap_;
  std::map<int, std::promise<json>> callback_;
  std::map<std::string, std::promise<json>> batch_callback_;
  boost::signals2::signal<void()> disconnect_signal_;
  boost::posix_time::seconds interval_;
  boost::asio::deadline_timer timer_;
  bool support_batch_request_ = false;
  time_t last_read_ = std::time(0);
};

}  // namespace nunchuk

#endif  // NUNCHUK_ELECTRUM_CLIENT_H
