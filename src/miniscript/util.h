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

#ifndef NUNCHUK_MINISCRIPT_UTIL_H
#define NUNCHUK_MINISCRIPT_UTIL_H

#include <nunchuk.h>
#include <miniscript/compiler.h>
#include <vector>
#include <stdexcept>
#include <optional>

namespace nunchuk {

struct ParseContext {
  typedef std::string Key;

  miniscript::MiniscriptContext ms_context;

  ParseContext(miniscript::MiniscriptContext ms_context_)
      : ms_context(ms_context_) {}

  template <typename I>
  std::optional<Key> FromString(I first, I last) const {
    if (std::distance(first, last) == 0 || std::distance(first, last) > 200)
      return {};
    return std::string(first, last);
  }

  bool KeyCompare(const Key& a, const Key& b) const { return a < b; }

  miniscript::MiniscriptContext MsContext() const { return ms_context; }
};

std::string PolicyToString(const Policy& node);
std::string PolicyToMiniscript(const Policy& policy,
                               const std::map<std::string, std::string>& config,
                               AddressType address_type);
miniscript::NodeRef<std::string> ParseMiniscript(const std::string& script,
                                                 AddressType address_type);
std::string MiniscriptToString(const miniscript::NodeRef<std::string>& node);
ScriptNode MiniscriptToScriptNode(const miniscript::NodeRef<std::string>& node);
std::string ScriptNodeToString(const ScriptNode& node);
bool ParseTapscriptTemplate(const std::string& tapscript_template,
                            std::string& keypath,
                            std::vector<std::string>& subscripts,
                            std::vector<int>& depths, std::string& error);
bool SubScriptsToString(const std::vector<std::string>& subscripts,
                        const std::vector<int>& depths, std::string& ret);
ScriptNode SubScriptsToScriptNode(const std::vector<std::string>& subscripts,
                                  const std::vector<int>& depths);
std::vector<SigningPath> GetAllSigningPaths(const ScriptNode& node);
bool IsValidMusigTemplate(const std::string& musig_template);
std::string GetMusigScript(const std::string& musig_template,
                           const std::map<std::string, SingleSigner>& signers);

}  // namespace nunchuk

#endif  // NUNCHUK_MINISCRIPT_UTIL_H