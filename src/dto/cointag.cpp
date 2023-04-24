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

#include <nunchuk.h>
#include <vector>

namespace nunchuk {

CoinTag::CoinTag(int id, const std::string& name, const std::string& color)
    : id_(id), name_(name), color_(color) {}

int CoinTag::get_id() const { return id_; }
std::string CoinTag::get_name() const { return name_; }
std::string CoinTag::get_color() const { return color_; }

}  // namespace nunchuk