// Copyright (c) 2020 Enigmo
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NUNCHUK_DESCRIPTOR_H
#define NUNCHUK_DESCRIPTOR_H

#include <nunchuk.h>
#include <script/descriptor.h>

#include <string>
#include <vector>

namespace nunchuk {

std::string AddChecksum(const std::string& str);

/**
 * @param external External descriptor to import
 * @param internal Internal descriptor to import
 * @param range The end or the range (in the form [begin,end]) to import
 * @param timestamp UNIX epoch time from which to start rescanning the
 * blockchain for this descriptor, use -1 for "now"
 */
std::string GetDescriptorsImportString(const std::string& external,
                                       const std::string& internal = {},
                                       int range = 1000,
                                       int64_t timestamp = -1);

std::string GetDescriptorForSigners(
    const std::vector<SingleSigner>& signers, int m, bool internal = false,
    AddressType address_type = AddressType::LEGACY,
    WalletType wallet_type = WalletType::MULTI_SIG);

// TODO (bakaoh): merge this method into GetDescriptorForSigners
std::string GetDescriptorForSignersAtIndex(
    const std::vector<SingleSigner>& signers, int m, bool internal,
    AddressType address_type, WalletType wallet_type, int index);

std::string GetPkhDescriptor(const std::string& address);

SingleSigner ParseSignerString(const std::string& signer_str);

bool ParseDescriptors(const std::string descs, AddressType& address_type,
                      WalletType& wallet_type, int& m, int& n,
                      std::vector<SingleSigner>& signers);

}  // namespace nunchuk

#endif  // NUNCHUK_DESCRIPTOR_H
