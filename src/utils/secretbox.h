/*
 * This file is part of the Nunchuk software (https://nunchuk.io/)
 * Copyright (C) 2022, 2023 Nunchuk
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NUNCHUK_CRYPTO_SECRETBOX_H
#define NUNCHUK_CRYPTO_SECRETBOX_H

#include <string>
#include <vector>

namespace nunchuk {

class Secretbox {
 public:
  Secretbox(const std::vector<unsigned char> &key);
  std::string Box(const std::string &plain);
  std::string Open(const std::string &box);

 private:
  std::vector<unsigned char> key_;
};

class Publicbox {
 public:
  static std::pair<std::string, std::string> GenerateKeyPair();
  Publicbox(const std::string &pkey, const std::string &skey);
  std::string Box(const std::string &plain, const std::string &receiver_pkey);
  std::string Open(const std::string &box);

 private:
  std::vector<unsigned char> skey_;
  std::vector<unsigned char> pkey_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_CRYPTO_SECRETBOX_H
