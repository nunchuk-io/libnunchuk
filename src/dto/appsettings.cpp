// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <nunchuk.h>

namespace nunchuk {

AppSettings::AppSettings() {}

Chain AppSettings::get_chain() const { return chain_; }
BackendType AppSettings::get_backend_type() const { return backend_type_; }
std::vector<std::string> AppSettings::get_mainnet_servers() const {
  return mainnet_servers_;
}
std::vector<std::string> AppSettings::get_testnet_servers() const {
  return testnet_servers_;
}
std::string AppSettings::get_hwi_path() const { return hwi_path_; }
std::string AppSettings::get_storage_path() const { return storage_path_; }
bool AppSettings::use_proxy() const { return enable_proxy_; }
std::string AppSettings::get_proxy_host() const { return proxy_host_; }
int AppSettings::get_proxy_port() const { return proxy_port_; }
std::string AppSettings::get_proxy_username() const { return proxy_username_; }
std::string AppSettings::get_proxy_password() const { return proxy_password_; }
std::string AppSettings::get_certificate_file() const {
  return certificate_file_;
}
std::string AppSettings::get_corerpc_host() const { return corerpc_host_; }
int AppSettings::get_corerpc_port() const { return corerpc_port_; }
std::string AppSettings::get_corerpc_username() const {
  return corerpc_username_;
}
std::string AppSettings::get_corerpc_password() const {
  return corerpc_password_;
}

void AppSettings::set_chain(Chain value) { chain_ = value; }
void AppSettings::set_backend_type(BackendType value) { backend_type_ = value; }
void AppSettings::set_mainnet_servers(const std::vector<std::string>& value) {
  mainnet_servers_ = value;
}
void AppSettings::set_testnet_servers(const std::vector<std::string>& value) {
  testnet_servers_ = value;
}
void AppSettings::set_hwi_path(const std::string& value) { hwi_path_ = value; }
void AppSettings::set_storage_path(const std::string& value) {
  storage_path_ = value;
}
void AppSettings::enable_proxy(bool value) { enable_proxy_ = value; }
void AppSettings::set_proxy_host(const std::string& value) {
  proxy_host_ = value;
}
void AppSettings::set_proxy_port(int value) { proxy_port_ = value; }
void AppSettings::set_proxy_username(const std::string& value) {
  proxy_username_ = value;
}
void AppSettings::set_proxy_password(const std::string& value) {
  proxy_password_ = value;
}
void AppSettings::set_certificate_file(const std::string& value) {
  certificate_file_ = value;
}
void AppSettings::set_corerpc_host(const std::string& value) {
  corerpc_host_ = value;
}
void AppSettings::set_corerpc_port(int value) { corerpc_port_ = value; }
void AppSettings::set_corerpc_username(const std::string& value) {
  corerpc_username_ = value;
}
void AppSettings::set_corerpc_password(const std::string& value) {
  corerpc_password_ = value;
}

}  // namespace nunchuk