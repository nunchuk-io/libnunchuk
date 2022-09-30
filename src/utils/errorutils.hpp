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

#ifndef NUNCHUK_ERRORUTILS_H
#define NUNCHUK_ERRORUTILS_H

#include <exception>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <functional>

namespace nunchuk {

inline std::string NormalizeErrorMessage(std::string message) {
  if (!message.empty()) {
    message[0] = std::toupper(message[0]);
  }
  return message;
}

template <typename Function>
auto RunThrowOne(Function &&func) {
  return func();
}
template <typename Function, typename... Functions>
auto RunThrowOne(Function &&func, Functions &&...funcs) {
  try {
    return func();
  } catch (const std::exception &e) {
    return RunThrowOne(std::forward<Functions>(funcs)...);
  }
}

}  // namespace nunchuk

#endif
