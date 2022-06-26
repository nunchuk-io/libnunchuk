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

#ifndef NUNCHUK_STORAGE_PRIMARYDB_H
#define NUNCHUK_STORAGE_PRIMARYDB_H

#include "common.h"
#include "db.h"
#include <nunchuk.h>
#include <vector>
#include <string>

namespace nunchuk {

class NunchukPrimaryDb : public NunchukDb {
 public:
  using NunchukDb::NunchukDb;
  void Init();
  bool AddPrimaryKey(const PrimaryKey &key);
  bool RemovePrimaryKey(const std::string& account);
  std::vector<PrimaryKey> GetPrimaryKeys() const;

 private:
  friend class NunchukStorage;
};

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_PRIMARYDB_H
