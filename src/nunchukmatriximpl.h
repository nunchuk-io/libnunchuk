// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_NUNCHUKMATRIXIMPL_H
#define NUNCHUK_NUNCHUKMATRIXIMPL_H

#include <nunchukmatrix.h>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <storage/roomdb.h>
#include <storage/storage.h>

namespace nunchuk {

class NunchukMatrixImpl : public NunchukMatrix {
 public:
  NunchukMatrixImpl(const AppSettings& appsettings,
                    const std::string& access_token, const std::string& account,
                    SendEventFunc sendfunc);
  NunchukMatrixImpl(const NunchukMatrixImpl&) = delete;
  NunchukMatrixImpl& operator=(const NunchukMatrixImpl&) = delete;
  ~NunchukMatrixImpl() override;

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

  NunchukMatrixEvent Backup(const std::unique_ptr<Nunchuk>& nu,
                            const std::string& sync_room_id,
                            const std::string& access_token = {}) override;

  std::vector<RoomWallet> GetAllRoomWallets() override;
  RoomWallet GetRoomWallet(const std::string& room_id) override;
  std::vector<RoomTransaction> GetPendingTransactions(
      const std::string& room_id) override;
  NunchukMatrixEvent GetEvent(const std::string& event_id) override;

  void ConsumeEvent(const std::unique_ptr<Nunchuk>& nu,
                    const NunchukMatrixEvent& event) override;

 private:
  NunchukMatrixEvent NewEvent(const std::string& room_id,
                              const std::string& event_type,
                              const std::string& content);
  void SendWalletReady(const std::string& room_id);
  void SendTransactionReady(const std::string& room_id,
                            const std::string& init_event_id);

  NunchukStorage storage_;
  std::string access_token_;
  std::string sender_;
  Chain chain_;
  SendEventFunc sendfunc_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_NUNCHUKMATRIXIMPL_H
