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

#ifndef NUNCHUK_STORAGE_COMMON_H
#define NUNCHUK_STORAGE_COMMON_H

#define SQLITE_HAS_CODEC
#define STORAGE_VER 4
#define HAVE_CONFIG_H
#ifdef NDEBUG
#undef NDEBUG
#endif

#include <sqlcipher/sqlite3.h>
#include <nunchuk.h>

#define SQLCHECK(x)                                                         \
  do {                                                                      \
    int rc = (x);                                                           \
    if (rc != SQLITE_OK) {                                                  \
      throw nunchuk::StorageException(nunchuk::StorageException::SQL_ERROR, \
                                      sqlite3_errmsg(db_));                 \
    }                                                                       \
  } while (0)

namespace nunchuk {

namespace DbKeys {
const int ID = 0;
const int IMMUTABLE_DATA = 1;
const int NAME = 2;
const int FINGERPRINT = 3;
const int ESCROW_INDEX = 5;
const int LAST_HEALTH_CHECK = 6;
const int VERSION = 7;
const int DESCRIPTION = 8;
const int CHAIN_TIP = 9;
const int SELECTED_WALLET = 10;
const int SIGNER_DEVICE_TYPE = 11;
const int SIGNER_DEVICE_MODEL = 12;
const int MNEMONIC = 13;
const int SYNC_TS = 14;
const int SYNC_ROOM_ID = 15;
const int EXPORT_TS = 16;
const int DELETED_SIGNERS = 17;
const int DELETED_WALLETS = 18;
const int DELETED_TRANSACTIONS = 19;
const int MASTER_XPRV = 20;
const int SIGNER_TYPE = 21;
const int LAST_USED = 22;
const int SIGNER_TAGS = 23;
const int GAP_LIMIT = 24;
}  // namespace DbKeys

}  // namespace nunchuk

#endif  // NUNCHUK_STORAGE_COMMON_H
