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

#include "hwiservice.h"

#include <base58.h>

#include <boost/algorithm/string/trim.hpp>
#if __has_include(<boost/process/v1.hpp>)
#include <boost/process/v1.hpp>
#ifdef _WIN32
#include <boost/process/v1/windows.hpp>
#endif
namespace bp = boost::process::v1;
#else
#include <boost/process.hpp>
#ifdef _WIN32
#include <boost/process/windows.hpp>
#endif
namespace bp = boost::process;
#endif
#include <charconv>
#include <regex>
#include "utils/quote.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <pthread.h>
#include <signal.h>
#endif

#include <utils/json.hpp>
#include <utils/loguru.hpp>
#include <utils/errorutils.hpp>

using json = nlohmann::json;

namespace nunchuk {
namespace {
std::string HwiCommand(const std::string& hwi,
                       const std::vector<std::string>& args) {
  std::stringstream command;
  command << hwi;
  for (const auto& arg : args) command << " " << arg;
  return command.str();
}

template <typename... Redirects>
bp::child LaunchHwi(const std::string& command, Redirects&&... redirects) {
#ifdef _WIN32
  return bp::child(command.c_str(), std::forward<Redirects>(redirects)...,
                   bp::windows::hide);
#else
  return bp::child(command.c_str(), std::forward<Redirects>(redirects)...);
#endif
}

// Prevent a disconnected child from delivering SIGPIPE to the host process.
// The underlying pipe is closed before its stream buffer is destroyed.
class PipeWriteGuard {
 public:
  PipeWriteGuard() {
#ifndef _WIN32
    sigemptyset(&set_);
    sigaddset(&set_, SIGPIPE);
    sigset_t pending;
    sigpending(&pending);
    pending_ = sigismember(&pending, SIGPIPE);
    blocked_ = pthread_sigmask(SIG_BLOCK, &set_, &previous_) == 0;
#endif
  }
  ~PipeWriteGuard() {
#ifndef _WIN32
    if (blocked_) {
      sigset_t pending;
      sigpending(&pending);
      if (!pending_ && sigismember(&pending, SIGPIPE)) {
        int signal;
        sigwait(&set_, &signal);
      }
      pthread_sigmask(SIG_SETMASK, &previous_, nullptr);
    }
#endif
  }

 private:
#ifndef _WIN32
  sigset_t set_, previous_;
  bool pending_ = false, blocked_ = false;
#endif
};

}  // namespace

struct HWIService::HwiChildHandle {
  bp::child proc;
  explicit HwiChildHandle(bp::child&& c) : proc(std::move(c)) {}
};

HWIService::~HWIService() = default;

static void ValidateDevice(const Device &device) {
  if (device.get_master_fingerprint().empty() &&
      (device.get_type().empty() || device.get_path().empty())) {
    throw HWIException(HWIException::MISSING_ARGUMENTS,
                       "Device type or fingerprint must be specified");
  }
}

static json ParseResponse(const std::string &resp) {
  json rs = json::parse(resp);
  if (rs["error"] != nullptr) {
    throw HWIException(rs["code"].get<int>() - 4000,
                       NormalizeErrorMessage(rs["error"]));
  }
  return rs;
}

static std::vector<std::string> PrependDeviceID(
    std::vector<std::string> cmd_args, const Device &device) {
  if (!device.get_master_fingerprint().empty()) {
    cmd_args.insert(cmd_args.begin(), device.get_master_fingerprint());
    cmd_args.insert(cmd_args.begin(), "-f");
  } else {
    // No fingerprint, try to use device type+path instead
    cmd_args.insert(cmd_args.begin(), device.get_path());
    cmd_args.insert(cmd_args.begin(), "-d");
    cmd_args.insert(cmd_args.begin(), device.get_type());
    cmd_args.insert(cmd_args.begin(), "-t");
  }
  return cmd_args;
}

static bool NeedsWalletRegistration(const Wallet& wallet, const Device& device) {
  const auto& type = device.get_type();
  return wallet.get_wallet_type() == WalletType::MINISCRIPT &&
         (type == "ledger" || type == "bitbox02" || type == "jade" ||
          type == "coldcard");
}

HWIService::HWIService(std::string path, Chain chain)
    : hwi_(path), chain_(chain) {
  CheckVersion();
}

void HWIService::SetPath(const std::string &path) {
  hwi_ = path;
  CheckVersion();
}

void HWIService::SetChain(Chain chain) { chain_ = chain; }

std::string HWIService::RunWalletCommand(
    const Wallet& wallet, const Device& device,
    const std::vector<std::string>& args) const {
  if (!NeedsWalletRegistration(wallet, device)) {
    return RunCmd(PrependDeviceID(args, device));
  }

  auto result = ParseResponse(RunCmd(PrependDeviceID(
      {"registerdescriptor", quoted_copy(boost::trim_copy(wallet.get_name())),
       quoted_copy(wallet.get_descriptor(DescriptorPath::EXTERNAL_INTERNAL))},
      device)));
  auto command = args;
  command.insert(command.end(),
                 {"--registration",
                  quoted_copy(result["registration"].get<std::string>())});
  return RunCmd(PrependDeviceID(command, device));
}

void HWIService::CheckVersion() {
  try {
    auto version = RunCmd({"--version"});
    if (std::string_view hwi = "hwi "; version.size() > hwi.size())
      version = version.substr(hwi.size());
    if (auto dot = version.find_first_of("."); dot != std::string::npos)
      std::from_chars(version.data(), version.data() + dot, version_);
  } catch (...) {
  }
}

std::string HWIService::RunCmd(const std::vector<std::string> &cmd_args) const {
  std::vector<std::string> args(cmd_args);

  if (chain_ == Chain::TESTNET) {
    if (version_ == 1)
      args.insert(args.begin(), "--testnet");
    else
      args.insert(args.begin(), "--chain test");
  } else if (chain_ == Chain::SIGNET) {
    if (version_ == 1)
      args.insert(args.begin(), "--signet");
    else
      args.insert(args.begin(), "--chain signet");
  }

  int exitcode = -1;
  std::string result;
  const std::string cmd_str = HwiCommand(hwi_, args);
  HwiChildHandle* child = nullptr;
  auto release_child = [&]() {
    if (!child) return;
    std::lock_guard<std::mutex> lock(hwi_child_mutex_);
    auto it = std::find_if(
        active_hwi_children_.begin(), active_hwi_children_.end(),
        [child](const std::unique_ptr<HwiChildHandle>& handle) {
          return handle.get() == child;
        });
    if (it != active_hwi_children_.end()) active_hwi_children_.erase(it);
    child = nullptr;
  };
  try {
    bp::ipstream out;
#ifdef _WIN32
    bp::ipstream err;
    auto c = LaunchHwi(cmd_str, bp::std_out > out, bp::std_err > err);
#else
    auto c = LaunchHwi(cmd_str, bp::std_out > out);
#endif
    {
      std::lock_guard<std::mutex> lock(hwi_child_mutex_);
      active_hwi_children_.push_back(
          std::make_unique<HwiChildHandle>(std::move(c)));
      child = active_hwi_children_.back().get();
    }
    std::getline(out, result);
    child->proc.wait();
    exitcode = child->proc.exit_code();
  } catch (const bp::process_error& pe) {
    release_child();
    throw HWIException(HWIException::RUN_ERROR,
                       NormalizeErrorMessage(pe.what()));
  } catch (...) {
    release_child();
    throw;
  }
  release_child();

  if (exitcode != 0) {
    LOG_F(ERROR, "Run hwi command '%s' exit code: %d", cmd_str.c_str(),
          exitcode);
    throw HWIException(HWIException::RUN_ERROR, "Run command exit error!");
  }

  LOG_F(INFO, "Run hwi command '%s' result: %s", cmd_str.c_str(),
        result.c_str());
  return result;
}

void HWIService::KillHwiProcess() const {
  std::lock_guard<std::mutex> lock(hwi_child_mutex_);
  for (auto& child : active_hwi_children_) {
    if (!child) continue;
    try {
      child->proc.terminate();
    } catch (const std::exception& e) {
      LOG_F(WARNING, "KillHwiProcess terminate: %s", e.what());
    }
  }
}

std::vector<Device> HWIService::Enumerate() const {
  json enumerate = json::parse(RunCmd({"enumerate"}));
  if (!enumerate.is_array()) {
    throw HWIException(HWIException::INVALID_RESULT, "Enumerate is not array!");
  }

  std::vector<Device> rs{};
  for (auto &el : enumerate.items()) {
    if (el.value()["error"] != nullptr &&
        el.value()["code"] != -18 &&  // device not initialized
        el.value()["code"] != -12 &&  // device not ready
        el.value()["code"] != -20     // pairing required
    ) {
      continue;
    }
    auto fingerprint = el.value()["fingerprint"];
    Device device{el.value()["type"],
                  el.value()["path"],
                  el.value()["model"],
                  fingerprint == nullptr ? "" : fingerprint,
                  el.value()["needs_passphrase_sent"],
                  el.value()["needs_pin_sent"],
                  el.value()["code"] != -18};
    device.set_needs_pairing(el.value()["code"] == -20 ||
                            el.value().value("needs_pairing", false));
    rs.push_back(device);
  }
  return rs;
}

std::string HWIService::GetXpubAtPath(const Device &device,
                                      const std::string derivation_path) const {
  ValidateDevice(device);
  auto cmd_args = PrependDeviceID({"getxpub", derivation_path}, device);
  json rs = ParseResponse(RunCmd(cmd_args));
  return rs["xpub"];
}

std::string HWIService::GetMasterFingerprint(const Device &device) const {
  ValidateDevice(device);
  std::string masterPubkey = GetXpubAtPath(device, "m/48h");
  std::vector<unsigned char> origin;
  if (!DecodeBase58(masterPubkey.c_str(), origin, 100)) {
    throw HWIException(HWIException::INVALID_RESULT, "Can't decode pubkey!");
  }

  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (int i = 5; i < 9; ++i) {
    ss << std::setw(2) << static_cast<unsigned>(origin[i]);
  }
  return ss.str();
}

std::string HWIService::SignTx(const Device &device,
                               const std::string &base64_psbt) const {
  ValidateDevice(device);
  std::vector<std::string> cmd_args =
      PrependDeviceID({"signtx", base64_psbt}, device);
  json rs = ParseResponse(RunCmd(cmd_args));
  return rs["psbt"];
}

std::string HWIService::SignTx(const Wallet &wallet, const Device &device,
                               const std::string &base64_psbt) const {
  ValidateDevice(device);
  json rs = ParseResponse(
      RunWalletCommand(wallet, device, {"signtx", base64_psbt}));
  return rs["psbt"];
}

std::string HWIService::SignMessage(const Device &device,
                                    const std::string &message,
                                    const std::string &derivation_path) const {
  ValidateDevice(device);
  std::string quoted_message = "\"" + message + "\"";
  std::vector<std::string> cmd_args =
      PrependDeviceID({"signmessage", quoted_message, derivation_path}, device);
  json rs = ParseResponse(RunCmd(cmd_args));
  return rs["signature"];
}

std::string HWIService::DisplayAddress(const Device &device,
                                       const std::string &desc) const {
  ValidateDevice(device);
  std::string quoted_desc = "\"" + desc + "\"";
  std::vector<std::string> cmd_args =
      PrependDeviceID({"displayaddress", "--desc", quoted_desc}, device);
  json rs = ParseResponse(RunCmd(cmd_args));
  return rs["address"];
}

std::string HWIService::DisplayAddress(const Wallet &wallet,
                                       const Device &device,
                                       const std::string &desc,
                                       int index,
                                       bool internal) const {
  if (!NeedsWalletRegistration(wallet, device)) {
    return DisplayAddress(device, desc);
  }

  ValidateDevice(device);
  json rs = ParseResponse(RunWalletCommand(
      wallet, device,
      {"displayaddress", "--multipath-index", internal ? "1" : "0",
       "--index", std::to_string(index)}));
  return rs["address"];
}

void HWIService::PromptPin(const Device &device) const {
  ValidateDevice(device);
  std::vector<std::string> cmd_args = {"-t", device.get_type(), "-d",
                                       device.get_path(), "promptpin"};
  ParseResponse(RunCmd(cmd_args));
}

void HWIService::SendPin(const Device &device, const std::string &pin) const {
  ValidateDevice(device);
  std::string quoted_pin = "\"" + pin + "\"";
  std::vector<std::string> cmd_args = {
      "-t", device.get_type(), "-d", device.get_path(), "sendpin", quoted_pin};
  ParseResponse(RunCmd(cmd_args));
}

void HWIService::SendPassphrase(const Device &device,
                                const std::string &passphrase) const {
  ValidateDevice(device);
  std::string password = "\"" + passphrase + "\"";
  std::vector<std::string> cmd_args = {
      "-t",     device.get_type(), "-d", device.get_path(), "--password",
      password, "togglepassphrase"};
  ParseResponse(RunCmd(cmd_args));
}

struct DevicePairingSession::Impl {
  enum class Phase { NEW, WAITING, FINISHED };
  std::string hwi;
  Device device;
  bp::opstream input;
  bp::ipstream output;
  bp::child child;
  std::mutex child_mutex;
  std::atomic_bool canceled{false};
  Phase phase = Phase::NEW;
  DevicePairingMethod method = DevicePairingMethod::ENTER_CODE;

  Impl(const std::string& path, const Device& dev)
      : hwi(path), device(dev) {}
  ~Impl() { Close(); }

  void CheckCanceled() const {
    if (canceled)
      throw HWIException(HWIException::ACTION_CANCELED, "Pairing canceled");
  }

  void Cancel() noexcept {
    canceled = true;
    std::lock_guard lock(child_mutex);
    std::error_code ec;
    if (child.valid() && child.running(ec)) child.terminate(ec);
  }

  void Close() noexcept {
    // Closing the pipe directly prevents retrying buffered data after failure.
    input.pipe().close();
    std::lock_guard lock(child_mutex);
    std::error_code ec;
    if (child.valid()) {
      if (child.running(ec)) child.terminate(ec);
      child.wait(ec);
    }
    phase = Phase::FINISHED;
  }

  json Read() {
    std::string line;
    if (!std::getline(output, line)) {
      CheckCanceled();
      throw HWIException(HWIException::DEVICE_CONN_ERROR,
                         "Pairing process closed without a result");
    }
    CheckCanceled();
    auto message = json::parse(line);
    if (!message.is_object())
      throw HWIException(HWIException::INVALID_RESULT,
                         "Invalid pairing result");
    if (message.contains("error")) {
      throw HWIException(
          message.at("code").get<int>() - 4000,
          NormalizeErrorMessage(message.at("error").get<std::string>()));
    }
    return message;
  }

  void Finish(const json& result) {
    if (result.contains("event") || !result.value("success", false)) {
      throw HWIException(HWIException::INVALID_RESULT,
                         "Invalid pairing result");
    }
    // Poll on the calling thread without holding the mutex during the wait,
    // so Cancel can terminate a child even after its final JSON.
    for (;;) {
      CheckCanceled();
      {
        std::lock_guard lock(child_mutex);
        if (!child.running()) {
          child.wait();
          CheckCanceled();
          if (child.exit_code() != 0)
            throw HWIException(HWIException::RUN_ERROR,
                               "Pairing process failed");
          break;
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    CheckCanceled();
    Close();
  }
};

DevicePairingSession::DevicePairingSession(const std::string& hwi_path,
                                           const Device& device)
    : impl_(std::make_unique<Impl>(hwi_path, device)) {}
DevicePairingSession::~DevicePairingSession() = default;

std::optional<DevicePairingRequest> DevicePairingSession::Start() {
  auto& session = *impl_;
  if (session.phase != Impl::Phase::NEW)
    throw HWIException(HWIException::BAD_ARGUMENT,
                       "Pairing has already started");
  try {
    {
      std::lock_guard lock(session.child_mutex);
      session.CheckCanceled();
      if (session.device.get_type().empty() ||
          session.device.get_path().empty()) {
        throw HWIException(HWIException::MISSING_ARGUMENTS,
                           "Pairing requires a device type and path");
      }
      // Preserve Windows HID backslashes while keeping a spaced device path
      // together, using the same command-line convention as RunCmd.
      const auto command = HwiCommand(
          session.hwi, {"-t", session.device.get_type(), "-d",
                        "\"" + session.device.get_path() + "\"", "pair"});
      session.child = LaunchHwi(command, bp::std_in < session.input,
                                bp::std_out > session.output,
                                bp::std_err > bp::null);
    }
    auto message = session.Read();
    if (!message.contains("event")) {
      session.Finish(message);
      return std::nullopt;
    }
    DevicePairingRequest request;
    if (message.value("event", "") != "pairing_required") {
      throw HWIException(HWIException::INVALID_RESULT,
                         "Unsupported pairing event");
    }
    const auto method = message.value("method", "");
    if (method == "enter_code") {
      request.method = DevicePairingMethod::ENTER_CODE;
    } else if (method == "confirm_code" && message.contains("code") &&
               message["code"].is_string()) {
      request.method = DevicePairingMethod::CONFIRM_CODE;
      request.code = message["code"].get<std::string>();
    } else {
      throw HWIException(HWIException::INVALID_RESULT,
                         "Unsupported pairing request");
    }
    session.method = request.method;
    session.phase = Impl::Phase::WAITING;
    return request;
  } catch (const HWIException&) {
    session.Close();
    throw;
  } catch (const std::exception& e) {
    session.Close();
    throw HWIException(HWIException::RUN_ERROR,
                       NormalizeErrorMessage(e.what()));
  }
}

void DevicePairingSession::Confirm(const DevicePairingResponse& response) {
  auto& session = *impl_;
  if (session.phase != Impl::Phase::WAITING)
    throw HWIException(HWIException::BAD_ARGUMENT,
                       "No pairing response is pending");
  try {
    session.CheckCanceled();
    json reply{{"accept", response.accept}, {"code", nullptr}};
    if (session.method == DevicePairingMethod::ENTER_CODE && response.accept)
      reply["code"] = response.code;
    {
      PipeWriteGuard guard;
      session.input << reply.dump() << std::endl;
      session.input.pipe().close();
    }
    if (!session.input)
      throw HWIException(HWIException::DEVICE_CONN_ERROR,
                         "Pairing connection closed");
    session.Finish(session.Read());
  } catch (const HWIException&) {
    session.Close();
    throw;
  } catch (const std::exception& e) {
    session.Close();
    throw HWIException(HWIException::RUN_ERROR,
                       NormalizeErrorMessage(e.what()));
  }
}

void DevicePairingSession::Cancel() noexcept { impl_->Cancel(); }
}  // namespace nunchuk
