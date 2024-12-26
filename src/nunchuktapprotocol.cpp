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

#include <algorithm>
#include <memory>
#include <numeric>
#include <string>
#include <boost/algorithm/string.hpp>
#include <utils/loguru.hpp>
#include <tinyformat.h>
#include <tap_protocol/utils.h>
#include <utils/bip32.hpp>
#include <utils/txutils.hpp>
#include <spender.h>
#include <utils/chain.hpp>
#include "key_io.h"
#include "nunchuk.h"
#include "nunchukimpl.h"
#include "pubkey.h"
#include "span.h"
#include "util/strencodings.h"
#include "utils/stringutils.hpp"
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/tap_protocol.h"

using namespace boost::algorithm;

namespace nunchuk {
MasterSigner NunchukImpl::ImportTapsignerMasterSigner(
    const std::string& file_path, const std::string& backup_key,
    const std::string& raw_name, std::function<bool(int)> progress,
    bool is_primary) {
  const std::string data = storage_->LoadFile(file_path);
  return ImportTapsignerMasterSigner(
      std::vector<unsigned char>(std::begin(data), std::end(data)), backup_key,
      raw_name, progress, is_primary);
}

MasterSigner NunchukImpl::ImportTapsignerMasterSigner(
    const std::vector<unsigned char>& data, const std::string& backup_key,
    const std::string& raw_name, std::function<bool(int)> progress,
    bool is_primary) {
  try {
    const std::string decrypted =
        hwi_tapsigner_->DecryptBackup(data, backup_key);
    const std::vector<std::string> sp = split(decrypted, '\n');
    if (sp.empty()) {
      throw NunchukException(NunchukException::INVALID_FORMAT,
                             "Invalid backup data");
    }
    const std::string name = trim_copy(raw_name);
    const std::string& master_xprv = ConvertXprvChain(sp[0], chain_);
    SoftwareSigner signer{master_xprv};
    const std::string id = to_lower_copy(signer.GetMasterFingerprint());

    if (is_primary) {
      const std::string address = signer.GetAddressAtPath(LOGIN_SIGNING_PATH);
      PrimaryKey key{name, id, account_, address};
      if (!storage_->AddPrimaryKey(chain_, key)) {
        throw StorageException(StorageException::SQL_ERROR,
                               "Create primary key failed");
      }
    }

    Device device{"software", "nunchuk", id};
    storage_->CreateMasterSignerFromMasterXprv(chain_, name, device,
                                               master_xprv);
    storage_->CacheMasterSignerXPub(
        chain_, id,
        [&](std::string path) { return signer.GetXpubAtPath(path); }, progress,
        true);

    // Delete TAPSIGNER db if exists
    storage_->DeleteTapsigner(chain_, id);

    storage_listener_();
    MasterSigner mastersigner{id, device, std::time(0), SignerType::SOFTWARE};
    mastersigner.set_name(name);
    return mastersigner;
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

void NunchukImpl::VerifyTapsignerBackup(const std::string& file_path,
                                        const std::string& backup_key,
                                        const std::string& master_signer_id) {
  std::string data = storage_->LoadFile(file_path);
  VerifyTapsignerBackup(
      std::vector<unsigned char>(std::begin(data), std::end(data)), backup_key,
      master_signer_id);
}

void NunchukImpl::VerifyTapsignerBackup(const std::vector<unsigned char>& data,
                                        const std::string& backup_key,
                                        const std::string& master_signer_id) {
  try {
    const std::string decrypted =
        hwi_tapsigner_->DecryptBackup(data, backup_key);
    const std::vector<std::string> sp = split(decrypted, '\n');
    if (sp.empty()) {
      throw NunchukException(NunchukException::INVALID_FORMAT,
                             "Invalid backup data");
    }
    const std::string& master_xprv = ConvertXprvChain(sp[0], chain_);
    SoftwareSigner signer{master_xprv};
    const std::string id = to_lower_copy(signer.GetMasterFingerprint());
    if (!master_signer_id.empty() && id != master_signer_id) {
      throw NunchukException(TapProtocolException::INVALID_DEVICE,
                             strprintf("Invalid device: key fingerprint "
                                       "does not match. Expected '%s'",
                                       id));
    }
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

std::unique_ptr<tap_protocol::CKTapCard> NunchukImpl::CreateCKTapCard(
    std::unique_ptr<tap_protocol::Transport> transport) {
  try {
    auto card = std::make_unique<tap_protocol::CKTapCard>(std::move(transport));
    if (card->IsTampered()) {
      throw TapProtocolException(TapProtocolException::INVALID_STATE,
                                 "Card is tampered");
    }
    return card;
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

void NunchukImpl::WaitCKTapCard(tap_protocol::CKTapCard* card,
                                std::function<bool(int)> progress) {
  try {
    card->Status();
    int delay = card->GetAuthDelay();
    while (delay != 0) {
      for (int i = 1; i <= delay; ++i) {
        if (!progress(i * 1.0 / delay * 100)) {
          return;
        }
        auto wait = card->Wait();
        if (!wait.success) {
          throw TapProtocolException(TapProtocolException::TAP_PROTOCOL_ERROR,
                                     "Wait error");
        }
      }
      delay = card->Status().auth_delay;
      if (delay == 0) {
        progress(100);
        return;
      }
    };
    progress(100);
    return;
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

std::unique_ptr<tap_protocol::Tapsigner> NunchukImpl::CreateTapsigner(
    std::unique_ptr<tap_protocol::Transport> transport) {
  try {
    auto card = tap_protocol::CKTapCard(std::move(transport));
    if (card.IsTampered()) {
      throw TapProtocolException(TapProtocolException::INVALID_STATE,
                                 "Card is tampered");
    }
    if (!card.IsTapsigner()) {
      throw TapProtocolException(
          TapProtocolException::INVALID_DEVICE_TYPE,
          "Incorrect device type detected. Please try again.");
    }
    auto tapsigner = tap_protocol::ToTapsigner(std::move(card));
    tapsigner->CertificateCheck();
    return tapsigner;
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

static TapsignerStatus GetTapsignerStatus(tap_protocol::Tapsigner* tapsigner) {
  auto rs = TapsignerStatus(tapsigner->GetIdent(), tapsigner->GetBirthHeight(),
                            tapsigner->GetNumberOfBackups(),
                            tapsigner->GetAppletVersion(),
                            tapsigner->GetDerivationPath(),
                            tapsigner->IsTestnet(), tapsigner->GetAuthDelay());
  return rs;
}

TapsignerStatus NunchukImpl::GetTapsignerStatus(
    tap_protocol::Tapsigner* tapsigner) {
  try {
    tapsigner->CertificateCheck();
    tapsigner->Status();
    auto rs = nunchuk::GetTapsignerStatus(tapsigner);
    auto&& card_ident = rs.get_card_ident();
    if (rs.need_setup()) {
      return rs;
    }

    try {
      std::string id =
          storage_->GetTapsignerStatusFromCardIdent(chain_, card_ident)
              .get_master_signer_id();
      auto master_signer = storage_->GetMasterSigner(chain_, id);
      rs.set_master_signer_id(master_signer.get_id());
    } catch (StorageException& se) {
      if (se.code() != StorageException::MASTERSIGNER_NOT_FOUND) {
        throw;
      }
    }

    return rs;
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

void NunchukImpl::InitTapsigner(tap_protocol::Tapsigner* tapsigner,
                                const std::string& cvc,
                                const std::string& chain_code) {
  try {
    tapsigner->CertificateCheck();
    hwi_tapsigner_->SetDevice(tapsigner, cvc);

    auto use_chain_code =
        chain_code.empty() ? Utils::GenerateRandomChainCode() : chain_code;
    hwi_tapsigner_->SetupDevice(use_chain_code);

    auto device_master_chain_code = hwi_tapsigner_->GetChaincodeAtPath();
    if (use_chain_code != device_master_chain_code) {
      throw TapProtocolException(TapProtocolException::INVALID_STATE,
                                 "Device uses different chain code");
    }
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

TapsignerStatus NunchukImpl::SetupTapsigner(tap_protocol::Tapsigner* tapsigner,
                                            const std::string& cvc,
                                            const std::string& new_cvc,
                                            const std::string& derivation_path,
                                            const std::string& chain_code) {
  try {
    tapsigner->CertificateCheck();
    hwi_tapsigner_->SetDevice(tapsigner, cvc);

    auto use_chain_code =
        chain_code.empty() ? Utils::GenerateRandomChainCode() : chain_code;
    hwi_tapsigner_->SetupDevice(use_chain_code);

    auto device_master_chain_code = hwi_tapsigner_->GetChaincodeAtPath();

    if (use_chain_code != device_master_chain_code) {
      throw TapProtocolException(TapProtocolException::INVALID_STATE,
                                 "Device uses different chain code");
    }

    if (!derivation_path.empty() && derivation_path != "m/84h/0h/0h") {
      tapsigner->Derive(derivation_path, cvc);
    }

    auto rs = BackupTapsigner(tapsigner, cvc);
    if (!tapsigner->Change(new_cvc, cvc).success) {
      throw TapProtocolException(TapProtocolException::TAP_PROTOCOL_ERROR,
                                 "Change CVC failed");
    }
    return rs;
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

MasterSigner NunchukImpl::CreateTapsignerMasterSigner(
    tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
    const std::string& raw_name, std::function<bool(int)> progress,
    bool is_primary, bool replace) {
  std::string id;
  try {
    hwi_tapsigner_->SetDevice(tapsigner, cvc);
    std::string name = trim_copy(raw_name);
    id = hwi_tapsigner_->GetMasterFingerprint();

    if (!replace && storage_->HasSigner(chain_, id)) {
      throw StorageException(StorageException::SIGNER_EXISTS,
                             strprintf("Signer exists id = '%s'", id));
    }
    if (name.empty()) {
      name = id;
    }
    Device device("nfc", "tapsigner", id);

    id = storage_->CreateMasterSigner(chain_, name, device);

    storage_->CacheMasterSignerXPub(
        chain_, id,
        [&](std::string path) -> std::string {
          return hwi_tapsigner_->GetXpubAtPath(path);
        },
        progress, true);

    MasterSigner mastersigner{id, device, std::time(0), SignerType::NFC};
    TapsignerStatus status = nunchuk::GetTapsignerStatus(tapsigner);
    status.set_master_signer_id(id);
    if (!storage_->AddTapsigner(chain_, status)) {
      throw StorageException(StorageException::SQL_ERROR,
                             "Can't save TAPSIGNER data");
    }

    if (is_primary) {
      const auto xpub = hwi_tapsigner_->GetXpubAtPath(LOGIN_SIGNING_PATH);
      const auto epubkey = DecodeExtPubKey(xpub);
      const std::string address =
          EncodeDestination(PKHash(epubkey.pubkey.GetID()));
      PrimaryKey key{name, id, account_, address};
      if (!storage_->AddPrimaryKey(chain_, key)) {
        throw StorageException(StorageException::SQL_ERROR,
                               "Create primary key failed");
      }
    }
    mastersigner.set_name(name);
    return mastersigner;
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  } catch (TapProtocolException& te) {
    if (te.code() == TapProtocolException::TAG_LOST && !id.empty()) {
      storage_->DeleteMasterSigner(chain_, id);
    }
    throw;
  }
}

Transaction NunchukImpl::SignTapsignerTransaction(
    tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
    const std::string& wallet_id, const std::string& tx_id) {
  try {
    hwi_tapsigner_->SetDevice(tapsigner, cvc);
    std::string psbt = storage_->GetPsbt(chain_, wallet_id, tx_id);
    if (psbt.empty()) {
      throw StorageException(StorageException::TX_NOT_FOUND, "Tx not found!");
    }
    DLOG_F(INFO,
           "NunchukImpl::SignTapsignerTransaction()"
           ", psbt='%s'",
           psbt.c_str());
    auto master_signer_id = hwi_tapsigner_->GetMasterFingerprint();

    auto mastersigner = GetMasterSigner(master_signer_id);
    if (mastersigner.get_type() != SignerType::NFC) {
      throw NunchukException(NunchukException::INVALID_SIGNER_TYPE,
                             strprintf("Only for NFC wallet_id = '%s' tx_id = "
                                       "'%s' master_signer_id = '%s'",
                                       wallet_id, tx_id, master_signer_id));
    }
    std::string signed_psbt = hwi_tapsigner_->SignTx(psbt);

    DLOG_F(INFO,
           "NunchukImpl::SignTapsignerTransaction(), "
           "signed_psbt='%s'",
           signed_psbt.c_str());
    storage_->UpdatePsbt(chain_, wallet_id, signed_psbt);
    storage_listener_();
    return GetTransaction(wallet_id, tx_id);
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

std::string NunchukImpl::SignTapsignerMessage(
    tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
    const SingleSigner& signer, const std::string& message) {
  auto master_signer_id = signer.get_master_signer_id();
  auto st = storage_->GetTapsignerStatusFromMasterSigner(
      chain_, signer.get_master_signer_id());
  if (st.get_card_ident() != tapsigner->GetIdent()) {
    throw NunchukException(
        TapProtocolException::INVALID_DEVICE,
        strprintf(
            "Invalid device: key fingerprint does not match. Expected '%s'.",
            master_signer_id));
  }

  try {
    hwi_tapsigner_->SetDevice(tapsigner, cvc);
    return hwi_tapsigner_->SignMessage(message, signer.get_derivation_path());
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

bool NunchukImpl::ChangeTapsignerCVC(tap_protocol::Tapsigner* tapsigner,
                                     const std::string& cvc,
                                     const std::string& new_cvc,
                                     const std::string& master_signer_id) {
  try {
    if (!master_signer_id.empty()) {
      try {
        auto st = storage_->GetTapsignerStatusFromMasterSigner(
            chain_, master_signer_id);
        if (st.get_card_ident() != tapsigner->GetIdent()) {
          throw NunchukException(TapProtocolException::INVALID_DEVICE,
                                 strprintf("Invalid device: key fingerprint "
                                           "does not match. Expected '%s'.",
                                           master_signer_id));
        }
      } catch (StorageException& se) {
        if (se.code() == StorageException::MASTERSIGNER_NOT_FOUND) {
          throw NunchukException(TapProtocolException::INVALID_DEVICE,
                                 strprintf("Invalid device: key fingerprint "
                                           "does not match. Expected '%s'.",
                                           master_signer_id));
        }
        throw;
      }
    }
    hwi_tapsigner_->SetDevice(tapsigner, cvc);
    return tapsigner->Change(new_cvc, cvc).success;
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

TapsignerStatus NunchukImpl::BackupTapsigner(
    tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
    const std::string& master_signer_id) {
  try {
    if (!master_signer_id.empty()) {
      try {
        auto st = storage_->GetTapsignerStatusFromMasterSigner(
            chain_, master_signer_id);
        if (st.get_card_ident() != tapsigner->GetIdent()) {
          throw NunchukException(TapProtocolException::INVALID_DEVICE,
                                 strprintf("Invalid device: key fingerprint "
                                           "does not match. Expected '%s'.",
                                           master_signer_id));
        }
      } catch (StorageException& se) {
        if (se.code() == StorageException::MASTERSIGNER_NOT_FOUND) {
          throw NunchukException(TapProtocolException::INVALID_DEVICE,
                                 strprintf("Invalid device: key fingerprint "
                                           "does not match. Expected '%s'.",
                                           master_signer_id));
        }
        throw;
      }
    }
    hwi_tapsigner_->SetDevice(tapsigner, cvc);
    auto backup_data = hwi_tapsigner_->BackupDevice();
    auto rs = nunchuk::GetTapsignerStatus(tapsigner);
    rs.set_backup_data(backup_data);
    rs.set_master_signer_id(master_signer_id);
    return rs;
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

HealthStatus NunchukImpl::HealthCheckTapsignerMasterSigner(
    tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
    const std::string& master_signer_id, std::string& message,
    std::string& signature, std::string& path) {
  message = message.empty() ? Utils::GenerateHealthCheckMessage() : message;

  constexpr static int MESSAGE_MIN_LEN = 8;
  if (message.size() < MESSAGE_MIN_LEN) {
    throw NunchukException(NunchukException::MESSAGE_TOO_SHORT,
                           "Message too short!");
  }
  auto st =
      storage_->GetTapsignerStatusFromMasterSigner(chain_, master_signer_id);
  if (st.get_card_ident() != tapsigner->GetIdent()) {
    throw NunchukException(
        TapProtocolException::INVALID_DEVICE,
        strprintf(
            "Invalid device: key fingerprint does not match. Expected '%s'.",
            master_signer_id));
  }
  path = chain_ == Chain::MAIN ? MAINNET_HEALTH_CHECK_PATH
                               : TESTNET_HEALTH_CHECK_PATH;

  try {
    hwi_tapsigner_->SetDevice(tapsigner, cvc);

    std::string xpub = hwi_tapsigner_->GetXpubAtPath(path);
    std::string descriptor = GetPkhDescriptor(xpub);
    std::string address = CoreUtils::getInstance().DeriveAddress(descriptor);
    signature = hwi_tapsigner_->SignMessage(message, path);
    if (CoreUtils::getInstance().VerifyMessage(address, signature, message)) {
      storage_->SetHealthCheckSuccess(chain_, master_signer_id);
      return HealthStatus::SUCCESS;
    } else {
      return HealthStatus::SIGNATURE_INVALID;
    }
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

SingleSigner NunchukImpl::GetSignerFromTapsignerMasterSigner(
    tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
    const std::string& master_signer_id, const WalletType& wallet_type,
    const AddressType& address_type, int index) {
  std::string path = GetBip32Path(chain_, wallet_type, address_type, index);
  return GetSignerFromTapsignerMasterSigner(tapsigner, cvc, master_signer_id,
                                            path);
}

SingleSigner NunchukImpl::GetSignerFromTapsignerMasterSigner(
    tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
    const std::string& master_signer_id, const std::string& path) {
  if (!Utils::IsValidDerivationPath(path)) {
    throw NunchukException(NunchukException::INVALID_BIP32_PATH,
                           strprintf("Invalid derivation path [%s].", path));
  }
  auto st =
      storage_->GetTapsignerStatusFromMasterSigner(chain_, master_signer_id);
  if (st.get_card_ident() != tapsigner->GetIdent()) {
    throw NunchukException(
        TapProtocolException::INVALID_DEVICE,
        strprintf(
            "Invalid device: key fingerprint does not match. Expected '%s'.",
            master_signer_id));
  }

  try {
    auto signer =
        storage_->GetSignerFromMasterSigner(chain_, master_signer_id, path);
    return signer;
  } catch (nunchuk::BaseException& ex) {
    if (ex.code() != NunchukException::RUN_OUT_OF_CACHED_XPUB) {
      throw;
    }
  }

  try {
    hwi_tapsigner_->SetDevice(tapsigner, cvc);
    std::string xpub = hwi_tapsigner_->GetXpubAtPath(path);
    auto signer = storage_->AddSignerToMasterSigner(
        chain_, master_signer_id,
        Utils::SanitizeSingleSigner(SingleSigner(
            {}, xpub, {}, path, master_signer_id, std::time(nullptr))));
    return signer;
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

std::string NunchukImpl::SignHealthCheckMessage(
    tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
    const SingleSigner& signer, const std::string& message) {
  std::string id = signer.get_master_fingerprint();
  try {
    auto st = storage_->GetTapsignerStatusFromMasterSigner(chain_, id);
    if (st.get_card_ident() != tapsigner->GetIdent()) {
      throw NunchukException(
          TapProtocolException::INVALID_DEVICE,
          strprintf(
              "Invalid device: key fingerprint does not match. Expected '%s'.",
              id));
    }
  } catch (StorageException& se) {
    if (se.code() == StorageException::MASTERSIGNER_NOT_FOUND) {
      if (id.empty()) {
        throw NunchukException(TapProtocolException::INVALID_DEVICE,
                               strprintf("Invalid device: key fingerprint does "
                                         "not match. Expected '%s'.",
                                         id));
      }
    }
    throw;
  }

  bool isPsbt = message.size() != 64;
  try {
    hwi_tapsigner_->SetDevice(tapsigner, cvc);
    if (isPsbt) {
      return GetPartialSignature(hwi_tapsigner_->SignTx(message), id);
    }
    return hwi_tapsigner_->SignMessage(message, signer.get_derivation_path());
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

TapsignerStatus NunchukImpl::WaitTapsigner(tap_protocol::Tapsigner* tapsigner,
                                           std::function<bool(int)> progress) {
  try {
    hwi_tapsigner_->SetDevice(tapsigner);

    tapsigner->Status();
    int delay = tapsigner->GetAuthDelay();
    while (delay != 0) {
      for (int i = 1; i <= delay; ++i) {
        if (!progress(i * 1.0 / delay * 100)) {
          return nunchuk::GetTapsignerStatus(tapsigner);
        }
        auto wait = tapsigner->Wait();
        if (!wait.success) {
          throw TapProtocolException(TapProtocolException::TAP_PROTOCOL_ERROR,
                                     "Wait error");
        }
      }
      auto st = nunchuk::GetTapsignerStatus(tapsigner);
      delay = st.get_auth_delay();
      if (delay == 0) {
        progress(100);
        return st;
      }
    };
    progress(100);
    return nunchuk::GetTapsignerStatus(tapsigner);
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

void NunchukImpl::CacheTapsignerMasterSignerXPub(
    tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
    const std::string& master_signer_id,
    std::function<bool /* stop */ (int /* percent */)> progress) {
  try {
    hwi_tapsigner_->SetDevice(tapsigner, cvc);

    auto st =
        storage_->GetTapsignerStatusFromMasterSigner(chain_, master_signer_id);
    if (st.get_card_ident() != tapsigner->GetIdent()) {
      throw NunchukException(
          TapProtocolException::INVALID_DEVICE,
          strprintf(
              "Invalid device: key fingerprint does not match. Expected '%s'.",
              master_signer_id));
    }
    auto mastersigner = GetMasterSigner(master_signer_id);
    if (mastersigner.get_type() != SignerType::NFC) {
      throw NunchukException(
          NunchukException::INVALID_SIGNER_TYPE,
          strprintf("Only for NFC signer master_signer_id = '%s'",
                    master_signer_id));
    }

    if (storage_->CacheDefaultMasterSignerXpub(
            chain_, master_signer_id,
            [&](const std::string& path) {
              return hwi_tapsigner_->GetXpubAtPath(path);
            },
            progress)) {
      return;
    }

    storage_->CacheMasterSignerXPub(
        chain_, master_signer_id,
        [&](const std::string& path) {
          return hwi_tapsigner_->GetXpubAtPath(path);
        },
        progress, false);
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

void NunchukImpl::CacheDefaultTapsignerMasterSignerXPub(
    tap_protocol::Tapsigner* tapsigner, const std::string& cvc,
    const std::string& master_signer_id,
    std::function<bool /* stop */ (int /* percent */)> progress) {
  try {
    hwi_tapsigner_->SetDevice(tapsigner, cvc);

    auto st =
        storage_->GetTapsignerStatusFromMasterSigner(chain_, master_signer_id);
    if (st.get_card_ident() != tapsigner->GetIdent()) {
      throw NunchukException(
          TapProtocolException::INVALID_DEVICE,
          strprintf(
              "Invalid device: key fingerprint does not match. Expected '%s'.",
              master_signer_id));
    }
    auto mastersigner = GetMasterSigner(master_signer_id);
    if (mastersigner.get_type() != SignerType::NFC) {
      throw NunchukException(
          NunchukException::INVALID_SIGNER_TYPE,
          strprintf("Only for NFC signer master_signer_id = '%s'",
                    master_signer_id));
    }
    storage_->CacheDefaultMasterSignerXpub(
        chain_, master_signer_id,
        [&](const std::string& path) {
          return hwi_tapsigner_->GetXpubAtPath(path);
        },
        progress);
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

TapsignerStatus NunchukImpl::GetTapsignerStatusFromMasterSigner(
    const std::string& master_signer_id) {
  return storage_->GetTapsignerStatusFromMasterSigner(chain_, master_signer_id);
}

void NunchukImpl::AddTapsigner(const std::string& card_ident,
                               const std::string& xfp, const std::string& name,
                               const std::string& version, int birth_height,
                               bool is_testnet, bool replace) {
  bool exists = false;
  try {
    if (storage_->IsMasterSigner(chain_, xfp)) {
      exists = true;
    }
  } catch (StorageException& e) {
    if (e.code() != StorageException::MASTERSIGNER_NOT_FOUND) {
      throw;
    }
  }

  if (!exists || replace) {
    TapsignerStatus status(card_ident, birth_height, 0, version, std::nullopt,
                           is_testnet);
    Device device("nfc", "tapsigner", xfp);
    std::string id = storage_->CreateMasterSigner(chain_, name, device);
    status.set_master_signer_id(id);

    if (!storage_->AddTapsigner(chain_, status)) {
      throw StorageException(StorageException::SQL_ERROR,
                             "Can't save TAPSIGNER data");
    }
  }
}

// SATSCARD
std::unique_ptr<tap_protocol::Satscard> NunchukImpl::CreateSatscard(
    std::unique_ptr<tap_protocol::Transport> transport) {
  try {
    auto satscard =
        std::make_unique<tap_protocol::Satscard>(std::move(transport));

    if (satscard->IsTampered()) {
      throw TapProtocolException(TapProtocolException::INVALID_STATE,
                                 "Card is tampered");
    }
    if (satscard->IsTapsigner()) {
      throw TapProtocolException(
          TapProtocolException::INVALID_DEVICE_TYPE,
          "Incorrect device type detected. Please try again.");
    }
    satscard->CertificateCheck();
    return satscard;
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

static SatscardSlot::Status ConvertTapProtocolSatscardStatus(
    tap_protocol::Satscard::SlotStatus status) {
  switch (status) {
    case tap_protocol::Satscard::SlotStatus::UNUSED:
      return SatscardSlot::Status::UNUSED;
    case tap_protocol::Satscard::SlotStatus::SEALED:
      return SatscardSlot::Status::SEALED;
    case tap_protocol::Satscard::SlotStatus::UNSEALED:
      return SatscardSlot::Status::UNSEALED;
  }
  throw NunchukException(NunchukException::INVALID_PARAMETER,
                         "Invalid slot status");
}

static SatscardSlot ConvertTapProtocolSatscardSlot(
    const tap_protocol::Satscard::Slot& slot) {
  return SatscardSlot{
      slot.index,     ConvertTapProtocolSatscardStatus(slot.status),
      slot.address,   slot.privkey,
      slot.pubkey,    slot.chain_code,
      slot.master_pk,
  };
}

static SatscardSlot MergeSatscardSlot(const SatscardSlot& lhs,
                                      const SatscardSlot& rhs) {
  auto ret = SatscardSlot(
      std::max(lhs.get_index(), rhs.get_index()),
      std::max(lhs.get_status(), rhs.get_status()),
      std::max(lhs.get_address(), rhs.get_address()),
      std::max(lhs.get_privkey(), rhs.get_privkey()),
      std::max(lhs.get_pubkey(), rhs.get_pubkey()),
      std::max(lhs.get_chain_code(), rhs.get_chain_code()),
      std::max(lhs.get_master_privkey(), rhs.get_master_privkey()));
  ret.set_balance(std::max(lhs.get_balance(), rhs.get_balance()));
  ret.set_utxos(lhs.get_utxos().size() > rhs.get_utxos().size()
                    ? lhs.get_utxos()
                    : rhs.get_utxos());
  return ret;
}

static SatscardStatus GetSatscardstatus(tap_protocol::Satscard* satscard) {
  satscard->CertificateCheck();
  satscard->Status();
  const auto raw_slots = satscard->ListSlots();

  std::vector<SatscardSlot> slots;
  slots.reserve(satscard->GetNumSlots());

  std::transform(std::begin(raw_slots), std::end(raw_slots),
                 std::back_inserter(slots), ConvertTapProtocolSatscardSlot);

  return SatscardStatus{
      satscard->GetIdent(),         satscard->GetBirthHeight(),
      satscard->GetAppletVersion(), satscard->IsTestnet(),
      satscard->GetAuthDelay(),     satscard->GetActiveSlotIndex(),
      satscard->GetNumSlots(),      std::move(slots)};
}

static std::vector<std::string> GetSatscardSlotsDescriptor(
    const std::vector<SatscardSlot>& slots, bool use_privkey) {
  const auto get_slot_desc = [&](const SatscardSlot& slot) {
    if (use_privkey) {
      if (slot.get_privkey().empty()) {
        throw NunchukException(NunchukException::INVALID_PARAMETER,
                               "Slot must be unsealed");
      }
      CKey key;
      key.Set(std::begin(slot.get_privkey()), std::end(slot.get_privkey()),
              true);
      if (!key.IsValid()) {
        throw NunchukException(NunchukException::INVALID_PARAMETER,
                               "Invalid slot key");
      }

      const std::string wif = EncodeSecret(key);
      return AddChecksum("wpkh(" + wif + ")");
    }
    if (!slot.get_pubkey().empty()) {
      CPubKey pub(MakeUCharSpan(slot.get_pubkey()));
      if (!pub.IsValid()) {
        throw NunchukException(NunchukException::INVALID_PARAMETER,
                               "Invalid slot key");
      }

      return AddChecksum("wpkh(" + HexStr(slot.get_pubkey()) + ")");
    }
    return AddChecksum("addr(" + slot.get_address() + ")");
  };

  std::vector<std::string> ret(slots.size());
  std::transform(slots.begin(), slots.end(), ret.begin(), get_slot_desc);

  return ret;
}

static std::pair<Transaction, std::vector<std::string>>
CreateSatscardSlotsTransaction(const std::vector<SatscardSlot>& slots,
                               const std::string& address,
                               const Amount& fee_rate,
                               const Amount& discard_rate, bool use_privkey) {
  std::vector<UnspentOutput> utxos;
  std::string change_address;
  Amount total_balance = 0;

  for (auto&& slot : slots) {
    if (slot.get_balance() <= 0) {
      throw NunchukException(NunchukException::INVALID_AMOUNT,
                             "Invalid amount");
    }

    change_address = slot.get_address();

    for (auto&& utxo : slot.get_utxos()) {
      if (utxo.get_height() > 0) {
        utxos.emplace_back(utxo);
      }
    }

    total_balance += slot.get_balance();
  }

  std::vector<TxOutput> selector_outputs{TxOutput{address, total_balance}};
  std::vector<std::string> descs =
      nunchuk::GetSatscardSlotsDescriptor(slots, use_privkey);

  int vsize = 0;
  int change_pos = 0;
  auto res =
      wallet::CreateTransaction(utxos, utxos, selector_outputs, true, descs,
                                change_address, fee_rate, change_pos, vsize);
  if (!res) {
    std::string error = util::ErrorString(res).original;
    throw NunchukException(NunchukException::COIN_SELECTION_ERROR, error);
  }
  const auto& txr = *res;
  CTransactionRef tx_new = txr.tx;

  std::vector<TxInput> new_inputs;
  for (const CTxIn& txin : tx_new->vin) {
    new_inputs.push_back({txin.prevout.hash.GetHex(), txin.prevout.n});
  }
  std::vector<TxOutput> new_outputs;
  for (const CTxOut& txout : tx_new->vout) {
    CTxDestination address;
    ExtractDestination(txout.scriptPubKey, address);
    new_outputs.push_back({EncodeDestination(address), txout.nValue});
  }

  std::string base64_psbt =
      CoreUtils::getInstance().CreatePsbt(new_inputs, new_outputs);

  Wallet wallet{false};
  wallet.set_m(1);
  auto tx = GetTransactionFromPartiallySignedTransaction(
      DecodePsbt(base64_psbt), wallet);

  tx.set_fee(res->fee);
  tx.set_change_index(change_pos);
  tx.set_receive(false);
  tx.set_sub_amount(total_balance - res->fee);
  tx.set_fee_rate(fee_rate);
  tx.set_subtract_fee_from_amount(true);
  tx.set_psbt(base64_psbt);
  tx.set_vsize(vsize);
  return {std::move(tx), std::move(descs)};
}

SatscardStatus NunchukImpl::GetSatscardStatus(
    tap_protocol::Satscard* satscard) {
  try {
    Chain card_chain = satscard->IsTestnet() ? Chain::TESTNET : Chain::MAIN;
    if (card_chain != chain_) {
      throw NunchukException(NunchukException::INVALID_CHAIN, "Invalid chain");
    }
    return GetSatscardstatus(satscard);
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

SatscardStatus NunchukImpl::SetupSatscard(tap_protocol::Satscard* satscard,
                                          const std::string& cvc,
                                          const std::string& chain_code) {
  try {
    auto chain_code_bytes = ParseHex(
        chain_code.empty() ? Utils::GenerateRandomChainCode() : chain_code);
    if (chain_code_bytes.size() != 32) {
      throw TapProtocolException(TapProtocolException::BAD_ARGUMENT,
                                 "Invalid chain code");
    }

    satscard->CertificateCheck();
    satscard->New(chain_code_bytes, cvc);
    return GetSatscardstatus(satscard);
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

SatscardSlot NunchukImpl::UnsealSatscard(tap_protocol::Satscard* satscard,
                                         const std::string& cvc,
                                         const SatscardSlot& slot) {
  try {
    auto unsealed_slot = ConvertTapProtocolSatscardSlot(satscard->Unseal(cvc));
    return MergeSatscardSlot(unsealed_slot, slot);
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

SatscardSlot NunchukImpl::FetchSatscardSlotUTXOs(const SatscardSlot& slot) {
  auto utxos = synchronizer_->ListUnspent(slot.get_address());
  Amount balance = 0;
  bool unconfirmed = false;
  for (auto&& utxo : utxos) {
    if (utxo.get_height() == 0) {
      unconfirmed = true;
    } else {
      balance += utxo.get_amount();
    }
  }

  SatscardSlot ret = slot;
  ret.set_utxos(std::move(utxos));
  ret.set_balance(balance);
  ret.set_confirmed(!unconfirmed);
  return ret;
}

SatscardSlot NunchukImpl::GetSatscardSlotKey(tap_protocol::Satscard* satscard,
                                             const std::string& cvc,
                                             const SatscardSlot& slot) {
  try {
    auto slot_key = ConvertTapProtocolSatscardSlot(
        satscard->GetSlot(slot.get_index(), cvc));
    return MergeSatscardSlot(slot_key, slot);
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

Transaction NunchukImpl::CreateSatscardSlotsTransaction(
    const std::vector<SatscardSlot>& slots, const std::string& address,
    Amount fee_rate) {
  if (fee_rate <= 0) fee_rate = EstimateFee();
  auto discard_rate = synchronizer_->RelayFee();
  return nunchuk::CreateSatscardSlotsTransaction(slots, address, fee_rate,
                                                 discard_rate, false)
      .first;
};

Transaction NunchukImpl::SweepSatscardSlot(const SatscardSlot& slot,
                                           const std::string& address,
                                           Amount fee_rate) {
  return SweepSatscardSlots({slot}, address, fee_rate);
}

Transaction NunchukImpl::SweepSatscardSlots(
    const std::vector<SatscardSlot>& slots, const std::string& address,
    Amount fee_rate) {
  if (fee_rate <= 0) fee_rate = EstimateFee();
  auto discard_rate = synchronizer_->RelayFee();
  auto [tx, descs] = nunchuk::CreateSatscardSlotsTransaction(
      slots, address, fee_rate, discard_rate, true);

  auto psbt = DecodePsbt(tx.get_psbt());
  auto json_descs = json::array();
  for (auto&& desc : descs) {
    json_descs.push_back(desc);
  }
  auto provider =
      SigningProviderCache::getInstance().GetProvider(json_descs.dump());
  int nin = psbt.tx.value().vin.size();

  std::vector<std::string> tx_ids;
  for (int i = 0; i < nin; ++i) {
    tx_ids.push_back(psbt.tx.value().vin[i].prevout.hash.GetHex());
  }

  auto tx_map = synchronizer_->GetRawTxs(tx_ids);

  for (int i = 0; i < nin; ++i) {
    std::string tx_id = psbt.tx.value().vin[i].prevout.hash.GetHex();
    if (auto it = tx_map.find(tx_id); it != tx_map.end()) {
      psbt.inputs[i].non_witness_utxo =
          MakeTransactionRef(DecodeRawTransaction(it->second));
      psbt.inputs[i].witness_utxo.SetNull();
    } else {
      throw NunchukException(
          NunchukException::SERVER_REQUEST_ERROR,
          "Could not retrieve transaction. Please try again. txid = " + tx_id);
    }
  }

  const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);
  for (int i = 0; i < nin; i++) {
    SignPSBTInput(provider, psbt, i, &txdata, 1);
  }

  // Update script/keypath information using descriptor data.
  for (unsigned int i = 0; i < psbt.tx.value().vout.size(); ++i) {
    UpdatePSBTOutput(provider, psbt, i);
  }

  std::string raw_tx = CoreUtils::getInstance().FinalizePsbt(EncodePsbt(psbt));
  synchronizer_->Broadcast(raw_tx);
  tx.set_status(TransactionStatus::PENDING_CONFIRMATION);

  return tx;
};

SatscardStatus NunchukImpl::WaitSatscard(tap_protocol::Satscard* satscard,
                                         std::function<bool(int)> progress) {
  try {
    satscard->Status();
    int delay = satscard->GetAuthDelay();
    while (delay != 0) {
      for (int i = 1; i <= delay; ++i) {
        if (!progress(i * 1.0 / delay * 100)) {
          return GetSatscardstatus(satscard);
        }
        auto wait = satscard->Wait();
        if (!wait.success) {
          throw TapProtocolException(TapProtocolException::TAP_PROTOCOL_ERROR,
                                     "Wait error");
        }
      }
      auto st = GetSatscardstatus(satscard);
      delay = st.get_auth_delay();
      if (delay == 0) {
        progress(100);
        return st;
      }
    };
    progress(100);
    return GetSatscardstatus(satscard);
  } catch (tap_protocol::TapProtoException& te) {
    throw TapProtocolException(te);
  }
}

Transaction NunchukImpl::FetchTransaction(const std::string& tx_id) {
  return synchronizer_->GetTransaction(tx_id);
}

}  // namespace nunchuk
