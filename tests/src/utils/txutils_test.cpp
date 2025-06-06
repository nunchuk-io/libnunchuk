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
#include <utils/txutils.hpp>

#include <doctest.h>

TEST_CASE("testing transaction utils") {
  nunchuk::Utils::SetChain(nunchuk::Chain::TESTNET);

  std::string raw_tx =
      "0200000000010137485dfcc52de6fd1775d7cafddd7b05681d7bfdea4c198fbccbb0d2c9"
      "f3d3dd01000000232200205bcbd70d352b4e481b2611cd61de7c51c98386d785f8b79fb3"
      "a1f64e303c17c8fdffffff01940c030000000000160014216eb46badfcf5f5dd10734aa6"
      "8950c7cec5db2f0400473044022073760eff0dae634e7d0752ed8e832ee1f908e1d1dbc1"
      "3d983c4553a408f5851a02204f7ef21ed5eef95ff0c1c43768f76411ff91c20c66bd7539"
      "6307efa6ccc0a8af01483045022100e3be7b281fbcdbd151bfe35185768c793794fc9ebd"
      "b45ef6e167886e6150cd24022014048a771a9809b57728adbd0f3804d3339b776333be23"
      "f3494b03835397fe2d014752210256f86e73a3e209551c5bd9e08585580967af1c2fd783"
      "31365b5b32da3be61a6121029b5b93270321264110e8893c49458a21b666644bcb1eafa4"
      "dc01ef405f8d0ea452ae00000000";
  CMutableTransaction mtx = DecodeRawTransaction(raw_tx);
  nunchuk::Transaction tx = GetTransactionFromCMutableTransaction(mtx, 0);
  CHECK(tx.get_txid() ==
        "27574e539fdf228179d53dd34ee1f68818bfbf4e6ea25871a9cc381710ac53b9");
  CHECK(tx.get_status() == nunchuk::TransactionStatus::PENDING_CONFIRMATION);
  CHECK(tx.get_height() == 0);
  CHECK(tx.get_inputs().size() == 1);
  CHECK(tx.get_inputs()[0] ==
        nunchuk::TxInput{
            "ddd3f3c9d2b0cbbc8f194ceafd7b1d68057bddfdcad77517fde62dc5fc5d4837",
            1});
  CHECK(tx.get_outputs().size() == 1);
  CHECK(
      tx.get_outputs()[0] ==
      nunchuk::TxOutput{"tb1qy9htg6adln6lthgswd92dz2scl8vtke05jtvcj", 199828});
}
