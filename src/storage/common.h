// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_STORAGE_COMMON_H
#define NUNCHUK_STORAGE_COMMON_H

#define SQLITE_HAS_CODEC
#define STORAGE_VER 3
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
}  // namespace DbKeys

}

#endif  // NUNCHUK_STORAGE_COMMON_H
