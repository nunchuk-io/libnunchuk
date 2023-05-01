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

#ifndef NUNCHUK_DESCRIPTOR_H
#define NUNCHUK_DESCRIPTOR_H

#include <nunchuk.h>
#include <script/descriptor.h>

#include <string>
#include <vector>

namespace nunchuk {

std::string AddChecksum(const std::string& str);

std::string FormalizePath(const std::string& path);

std::string GetDerivationPathView(std::string path);

std::string GetWalletId(const std::vector<SingleSigner>& signers, int m,
                        AddressType address_type, WalletType wallet_type);

/**
 * @param external External descriptor to import
 * @param internal Internal descriptor to import
 * @param range The end or the range (in the form [begin,end]) to import
 * @param timestamp UNIX epoch time from which to start rescanning the
 * blockchain for this descriptor, use -1 for "now"
 */
std::string GetDescriptorsImportString(const std::string& external,
                                       const std::string& internal = {},
                                       int range = 100, int64_t timestamp = -1);

std::string GetDescriptorsImportString(const Wallet& wallet);

std::string GetDescriptorForSigners(
    const std::vector<SingleSigner>& signers, int m,
    DescriptorPath path = DescriptorPath::EXTERNAL_ALL,
    AddressType address_type = AddressType::LEGACY,
    WalletType wallet_type = WalletType::MULTI_SIG, int index = -1,
    bool sorted = true);

std::string GetPkhDescriptor(const std::string& address);

std::string GetDescriptor(const SingleSigner& signer, AddressType address_type);

SingleSigner ParseSignerString(const std::string& signer_str);

bool ParseDescriptors(const std::string& descs, AddressType& address_type,
                      WalletType& wallet_type, int& m, int& n,
                      std::vector<SingleSigner>& signers);

bool ParseJSONDescriptors(const std::string& json_str, std::string& name,
                          AddressType& address_type, WalletType& wallet_type,
                          int& m, int& n, std::vector<SingleSigner>& signers);

std::string GetSignerNameFromDerivationPath(const std::string& derivation_path,
                                            const std::string& prefix = {});

}  // namespace nunchuk

#endif  // NUNCHUK_DESCRIPTOR_H
