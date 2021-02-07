// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hwiservice.h"

#include <base58.h>

#include <array>
#include <boost/process.hpp>
#ifdef _WIN32
#include <boost/process/windows.hpp>
#endif
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <utils/json.hpp>
#include <utils/loguru.hpp>

using json = nlohmann::json;
namespace bp = boost::process;

namespace nunchuk {

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
                       rs["error"].get<std::string>());
  }
  return rs;
}

HWIService::HWIService(std::string path, Chain chain)
    : hwi_(path), testnet_(chain == Chain::TESTNET) {}

void HWIService::SetPath(const std::string &path) { hwi_ = path; }
void HWIService::SetChain(Chain chain) { testnet_ = chain == Chain::TESTNET; }

std::string HWIService::RunCmd(const std::vector<std::string> &args) const {
  // build command string
  std::stringstream cmd;
  cmd << hwi_;
  const int v_size = args.size();
  for (size_t i = 0; i < v_size; ++i) {
    cmd << " " << args[i];
  }

  // run command and get output
  int exitcode;
  std::string result;
  try {
    bp::ipstream out;
#ifdef _WIN32
    bp::child c(cmd.str().c_str(), bp::std_out > out, bp::windows::hide);
#else
    bp::child c(cmd.str().c_str(), bp::std_out > out);
#endif
    std::getline(out, result);
    c.wait();
    exitcode = c.exit_code();
  } catch (bp::process_error &pe) {
    throw HWIException(HWIException::RUN_ERROR, pe.what());
  }

  if (exitcode != 0) {
    LOG_F(ERROR, "Run hwi command '%s' exit code: %d", cmd.str().c_str(),
          exitcode);
    throw HWIException(HWIException::RUN_ERROR, "run command exit error!");
  }

  LOG_F(INFO, "Run hwi command '%s' result: %s", cmd.str().c_str(),
        result.c_str());
  return result;
}

std::vector<Device> HWIService::Enumerate() const {
  json enumerate = json::parse(RunCmd({"enumerate"}));
  if (!enumerate.is_array()) {
    throw HWIException(HWIException::INVALID_RESULT, "enumerate is not array!");
  }

  std::vector<Device> rs{};
  for (auto &el : enumerate.items()) {
    if (el.value()["error"] != nullptr &&
        el.value()["code"] != -18 &&  // device not initialized
        el.value()["code"] != -12     // device not ready
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
    rs.push_back(device);
  }
  return rs;
}

std::string HWIService::GetXpubAtPath(const Device &device,
                                      const std::string derivation_path) const {
  ValidateDevice(device);
  std::vector<std::string> cmd_args = {"-f", device.get_master_fingerprint(),
                                       "getxpub", derivation_path};
  if (testnet_) {
    cmd_args.insert(cmd_args.begin(), "--testnet");
  }
  json rs = ParseResponse(RunCmd(cmd_args));
  return rs["xpub"];
}

std::string HWIService::GetMasterFingerprint(const Device &device) const {
  ValidateDevice(device);
  std::string masterPubkey = GetXpubAtPath(device, "m/48h");
  std::vector<unsigned char> origin;
  if (!DecodeBase58(masterPubkey.c_str(), origin, 100)) {
    throw HWIException(HWIException::INVALID_RESULT, "can't decode pubkey!");
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
  std::vector<std::string> cmd_args = {"signtx", base64_psbt};
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
  if (testnet_) {
    cmd_args.insert(cmd_args.begin(), "--testnet");
  }
  json rs = ParseResponse(RunCmd(cmd_args));
  return rs["psbt"];
}

std::string HWIService::SignMessage(const Device &device,
                                    const std::string &message,
                                    const std::string &derivation_path) const {
  ValidateDevice(device);
  std::string quoted_message = "\"" + message + "\"";
  std::vector<std::string> cmd_args = {"signmessage", quoted_message,
                                       derivation_path};
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
  if (testnet_) {
    cmd_args.insert(cmd_args.begin(), "--testnet");
  }
  json rs = ParseResponse(RunCmd(cmd_args));
  return rs["signature"];
}

std::string HWIService::DisplayAddress(const Device &device,
                                       const std::string &desc) const {
  ValidateDevice(device);
  std::string quoted_desc = "\"" + desc + "\"";
  std::vector<std::string> cmd_args = {"displayaddress", "--desc", quoted_desc};
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
  if (testnet_) {
    cmd_args.insert(cmd_args.begin(), "--testnet");
  }
  json rs = ParseResponse(RunCmd(cmd_args));
  return rs["address"];
}

void HWIService::PromptPin(const Device &device) const {
  ValidateDevice(device);
  std::vector<std::string> cmd_args = {"-t", device.get_type(), "-d",
                                       device.get_path(), "promptpin"};
  if (testnet_) {
    cmd_args.insert(cmd_args.begin(), "--testnet");
  }
  ParseResponse(RunCmd(cmd_args));
}

void HWIService::SendPin(const Device &device, const std::string &pin) const {
  ValidateDevice(device);
  std::vector<std::string> cmd_args = {
      "-t", device.get_type(), "-d", device.get_path(), "sendpin", pin};
  if (testnet_) {
    cmd_args.insert(cmd_args.begin(), "--testnet");
  }
  ParseResponse(RunCmd(cmd_args));
}

}  // namespace nunchuk
