// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUKMATRIX_INCLUDE_H
#define NUNCHUKMATRIX_INCLUDE_H

#include <nunchuk.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace nunchuk {

class NUNCHUK_EXPORT NunchukMatrixException : public BaseException {
 public:
  static const int SHARED_WALLET_EXISTS = -5001;
  static const int SHARED_WALLET_NOT_FOUND = -5002;
  static const int EVENT_NOT_FOUND = -5003;
  static const int TRANSACTION_NOT_FOUND = -5004;

  using BaseException::BaseException;
};

class NUNCHUK_EXPORT NunchukMatrixEvent {
 public:
  NunchukMatrixEvent();

  std::string get_type() const;
  std::string get_content() const;
  std::string get_event_id() const;
  std::string get_room_id() const;
  std::string get_sender() const;
  time_t get_ts() const;

  void set_type(const std::string& value);
  void set_content(const std::string& value);
  void set_event_id(const std::string& value);
  void set_room_id(const std::string& value);
  void set_sender(const std::string& value);
  void set_ts(time_t value);

 private:
  std::string type_;
  std::string content_;
  std::string event_id_;
  std::string room_id_;
  std::string sender_;
  time_t ts_;
};

class NUNCHUK_EXPORT RoomSharedWallet {
 public:
  RoomSharedWallet();

  std::string get_wallet_id() const;
  std::string get_init_id() const;
  std::vector<std::string> get_join_ids() const;
  std::vector<std::string> get_leave_ids() const;
  std::string get_finalize_id() const;
  std::string get_cancel_id() const;
  std::string get_pin_data() const;

  void set_wallet_id(const std::string& value);
  void set_init_id(const std::string& value);
  void add_join_id(const std::string& value);
  void add_leave_id(const std::string& value);
  void set_finalize_id(const std::string& value);
  void set_cancel_id(const std::string& value);

 private:
  std::string wallet_id_;
  std::string init_id_;
  std::vector<std::string> join_ids_;
  std::vector<std::string> leave_ids_;
  std::string finalize_id_;
  std::string cancel_id_;
  std::string pin_data_;
};

class NUNCHUK_EXPORT RoomTransaction {
 public:
  RoomTransaction();

  std::string get_tx_id() const;
  std::string get_wallet_id() const;
  std::string get_init_id() const;
  std::vector<std::string> get_sign_ids() const;
  std::vector<std::string> get_reject_ids() const;
  std::string get_broadcast_id() const;
  std::string get_cancel_id() const;

  void set_tx_id(const std::string& value);
  void set_wallet_id(const std::string& value);
  void set_init_id(const std::string& value);
  void add_sign_id(const std::string& value);
  void add_reject_id(const std::string& value);
  void set_broadcast_id(const std::string& value);
  void set_cancel_id(const std::string& value);

 private:
  std::string tx_id_;
  std::string wallet_id_;
  std::string init_id_;
  std::vector<std::string> sign_ids_;
  std::vector<std::string> reject_ids_;
  std::string broadcast_id_;
  std::string cancel_id_;
};

class NUNCHUK_EXPORT NunchukMatrix {
 public:
  NunchukMatrix(const NunchukMatrix&) = delete;
  NunchukMatrix& operator=(const NunchukMatrix&) = delete;

  virtual ~NunchukMatrix();

  virtual NunchukMatrixEvent InitWallet(
      const std::string& room_id, const std::string& name, int m, int n,
      AddressType address_type, bool is_escrow,
      const std::string& description = {}) = 0;
  virtual NunchukMatrixEvent JoinWallet(const std::string& room_id,
                                        const SingleSigner& signer) = 0;
  virtual NunchukMatrixEvent LeaveWallet(const std::string& room_id,
                                         const std::string& join_id,
                                         const std::string& reason = {}) = 0;
  virtual NunchukMatrixEvent CancelWallet(const std::string& room_id,
                                          const std::string& reason = {}) = 0;
  virtual NunchukMatrixEvent CreateWallet(const std::unique_ptr<Nunchuk>& nu,
                                          const std::string& room_id) = 0;

  virtual NunchukMatrixEvent InitTransaction(const std::string& room_id,
                                             const Transaction& tx) = 0;
  virtual NunchukMatrixEvent SignTransaction(const std::string& init_id,
                                             const Transaction& tx) = 0;
  virtual NunchukMatrixEvent RejectTransaction(
      const std::string& init_id, const std::string& reason = {}) = 0;
  virtual NunchukMatrixEvent CancelTransaction(
      const std::string& init_id, const std::string& reason = {}) = 0;
  virtual NunchukMatrixEvent BroadcastTransaction(const std::string& init_id,
                                                  const Transaction& tx) = 0;

  virtual RoomSharedWallet GetRoomWallet(const std::string& room_id) = 0;
  virtual std::vector<RoomTransaction> GetPendingTransactions(
      const std::string& room_id) = 0;

  virtual void ConsumeEvent(const std::unique_ptr<Nunchuk>& nu,
                            const NunchukMatrixEvent& event) = 0;

 protected:
  NunchukMatrix() = default;
};

std::unique_ptr<NunchukMatrix> MakeNunchukMatrixForAccount(
    const AppSettings& appsettings, const std::string& passphrase,
    const std::string& account);

}  // namespace nunchuk

#endif  // NUNCHUKMATRIX_INCLUDE_H
