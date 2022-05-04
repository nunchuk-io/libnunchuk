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

#ifndef NUNCHUK_NUNCHUKMATRIXIMPL_H
#define NUNCHUK_NUNCHUKMATRIXIMPL_H
#define NUNCHUK_EVENT_VER 1

#include <nunchukmatrix.h>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <future>
#include <storage/roomdb.h>
#include <storage/storage.h>
#include <shared_mutex>

namespace nunchuk {

class NunchukMatrixImpl : public NunchukMatrix {
 public:
  NunchukMatrixImpl(const AppSettings& appsettings,
                    const std::string& access_token, const std::string& account,
                    SendEventFunc sendfunc);
  NunchukMatrixImpl(const NunchukMatrixImpl&) = delete;
  NunchukMatrixImpl& operator=(const NunchukMatrixImpl&) = delete;
  ~NunchukMatrixImpl() override;

  NunchukMatrixEvent SendErrorEvent(const std::string& room_id,
                                    const std::string& platform,
                                    const std::string& code,
                                    const std::string& message) override;

  NunchukMatrixEvent InitWallet(const std::string& room_id,
                                const std::string& name, int m, int n,
                                AddressType address_type, bool is_escrow,
                                const std::string& description = {}) override;
  NunchukMatrixEvent JoinWallet(const std::string& room_id,
                                const SingleSigner& signer) override;
  NunchukMatrixEvent LeaveWallet(const std::string& room_id,
                                 const std::string& join_event_id,
                                 const std::string& reason = {}) override;
  NunchukMatrixEvent CancelWallet(const std::string& room_id,
                                  const std::string& reason = {}) override;
  NunchukMatrixEvent CreateWallet(const std::unique_ptr<Nunchuk>& nu,
                                  const std::string& room_id) override;
  NunchukMatrixEvent DeleteWallet(const std::unique_ptr<Nunchuk>& nu,
                                  const std::string& room_id) override;

  NunchukMatrixEvent InitTransaction(
      const std::unique_ptr<Nunchuk>& nu, const std::string& room_id,
      const std::map<std::string, Amount> outputs, const std::string& memo = {},
      const std::vector<UnspentOutput> inputs = {}, Amount fee_rate = -1,
      bool subtract_fee_from_amount = false) override;
  NunchukMatrixEvent SignTransaction(const std::unique_ptr<Nunchuk>& nu,
                                     const std::string& init_event_id,
                                     const Device& device) override;
  NunchukMatrixEvent RejectTransaction(const std::string& init_event_id,
                                       const std::string& reason = {}) override;
  NunchukMatrixEvent CancelTransaction(const std::string& init_event_id,
                                       const std::string& reason = {}) override;
  NunchukMatrixEvent BroadcastTransaction(
      const std::unique_ptr<Nunchuk>& nu,
      const std::string& init_event_id) override;

  void EnableAutoBackup(const std::unique_ptr<Nunchuk>& nu,
                        const std::string& sync_room_id,
                        const std::string& access_token) override;
  void EnableGenerateReceiveEvent(const std::unique_ptr<Nunchuk>& nu) override;

  void RegisterFileFunc(UploadFileFunc upload,
                        DownloadFileFunc download) override;
  NunchukMatrixEvent UploadFileCallback(const std::string& json_info,
                                        const std::string& file_url) override;
  void DownloadFileCallback(
      const std::unique_ptr<Nunchuk>& nu, const std::string& json_info,
      const std::vector<unsigned char>& file_data,
      std::function<bool /* stop */ (int /* percent */)> progress) override;
  void WriteFileCallback(
      const std::unique_ptr<Nunchuk>& nu, const std::string& json_info,
      const std::string& file_path,
      std::function<bool /* stop */ (int /* percent */)> progress) override;

  std::vector<RoomWallet> GetAllRoomWallets() override;
  bool HasRoomWallet(const std::string& room_id) override;
  RoomWallet GetRoomWallet(const std::string& room_id) override;
  std::vector<RoomTransaction> GetPendingTransactions(
      const std::string& room_id) override;
  RoomTransaction GetRoomTransaction(const std::string& init_event_id) override;
  NunchukMatrixEvent GetEvent(const std::string& event_id) override;
  std::string GetTransactionId(const std::string& event_id) override;

  void ConsumeEvent(const std::unique_ptr<Nunchuk>& nu,
                    const NunchukMatrixEvent& event) override;
  void ConsumeSyncEvent(
      const std::unique_ptr<Nunchuk>& nu, const NunchukMatrixEvent& event,
      std::function<bool /* stop */ (int /* percent */)> progress) override;

 private:
  NunchukMatrixEvent NewEvent(const std::string& room_id,
                              const std::string& event_type,
                              const std::string& content,
                              bool ignore_error = false);
  void SendReceiveTransaction(const std::string& room_id,
                              const std::string& tx_id);
  void SendWalletReady(const std::string& room_id);
  void SendTransactionReady(const std::string& room_id,
                            const std::string& init_event_id);
  void RandomDelay(std::function<void()> func);
  void AsyncBackup(const std::unique_ptr<Nunchuk>& nu, int delay_sec = 0);
  NunchukMatrixEvent Backup(const std::unique_ptr<Nunchuk>& nu);
  void SyncWithBackup(const std::string& dataStr);
  std::string ExportBackup();

  NunchukStorage storage_;
  std::string sync_room_id_;
  std::string access_token_;
  std::string sender_;
  bool stopped = false;
  Chain chain_;
  SendEventFunc sendfunc_;
  UploadFileFunc uploadfunc_;
  DownloadFileFunc downloadfunc_;
  std::shared_mutex access_;
  std::map<std::string, std::string> wallet2room_;
  std::vector<std::future<void>> delay_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_NUNCHUKMATRIXIMPL_H
