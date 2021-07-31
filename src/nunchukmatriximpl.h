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
                    const std::string& passphrase, const std::string& account);
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
                                 const std::string& join_id,
                                 const std::string& reason = {}) override;
  NunchukMatrixEvent CancelWallet(const std::string& room_id,
                                  const std::string& reason = {}) override;
  NunchukMatrixEvent CreateWallet(const std::unique_ptr<Nunchuk>& nu,
                                  const std::string& room_id) override;

  NunchukMatrixEvent InitTransaction(const std::string& room_id,
                                     const Transaction& tx) override;
  NunchukMatrixEvent SignTransaction(const std::string& init_id,
                                     const Transaction& tx) override;
  NunchukMatrixEvent RejectTransaction(const std::string& init_id,
                                       const std::string& reason = {}) override;
  NunchukMatrixEvent CancelTransaction(const std::string& init_id,
                                       const std::string& reason = {}) override;
  NunchukMatrixEvent BroadcastTransaction(const std::string& init_id,
                                          const Transaction& tx) override;

  RoomWallet GetRoomWallet(const std::string& room_id) override;
  std::vector<RoomTransaction> GetPendingTransactions(
      const std::string& room_id) override;

  void ConsumeEvent(const std::unique_ptr<Nunchuk>& nu,
                    const NunchukMatrixEvent& event) override;

 private:
  NunchukMatrixEvent NewEvent(const std::string& room_id,
                              const std::string& event_type,
                              const std::string& content);
  NunchukStorage storage_;
  std::string sender_;
  Chain chain_;
};

}  // namespace nunchuk

#endif  // NUNCHUK_NUNCHUKMATRIXIMPL_H
