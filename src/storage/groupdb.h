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

#ifndef NUNCHUK_STORAGE_GROUPDB_H
#define NUNCHUK_STORAGE_GROUPDB_H

#include "common.h"
#include "db.h"
#include <nunchuk.h>
#include <vector>
#include <string>

namespace nunchuk {

class NunchukGroupDb : public NunchukDb {
 public:
  using NunchukDb::NunchukDb;
  void Init();

  void SetDeviceToken(const std::string& value);
  void SetEphemeralKey(const std::string& pub, const std::string& priv);

  std::string GetDeviceToken() const;
  std::pair<std::string, std::string> GetEphemeralKey() const;

 private:
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_GROUPDB_H
