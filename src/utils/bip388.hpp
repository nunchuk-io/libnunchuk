/*
 * This file is part of the Nunchuk software (https://nunchuk.io/)
 * Copyright (C) 2022, 2023, 2025 Nunchuk
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NUNCHUK_BIP388_H
#define NUNCHUK_BIP388_H

#include <nunchuk.h>
#include <string>
#include "descriptor.h"
#include "stringutils.hpp"

namespace nunchuk {

struct Bip388Policy {
  std::string descriptor_template;
  std::vector<std::string> keys_info;
};

inline Bip388Policy GetBip388Policy(const Wallet& wallet) {
  Bip388Policy policy;

  for (auto&& signer : wallet.get_signers()) {
    policy.keys_info.push_back(signer.get_descriptor());
  }

  std::string descriptor = wallet.get_descriptor(DescriptorPath::TEMPLATE);

  if (wallet.get_address_type() == AddressType::TAPROOT &&
      wallet.get_wallet_template() == WalletTemplate::DISABLE_KEY_PATH) {
    std::string xpub = GetUnspendableXpub(wallet.get_signers());
    policy.keys_info.insert(policy.keys_info.begin(), xpub);
  }
  std::sort(policy.keys_info.begin(), policy.keys_info.end(),
            [&](const std::string& lhs, const std::string rhs) {
              return descriptor.find(lhs) < descriptor.find(rhs);
            });

  for (size_t i = 0; i < policy.keys_info.size(); ++i) {
    descriptor = replaceAll(descriptor, policy.keys_info[i],
                            std::string("@") + std::to_string(i));
  }

  policy.descriptor_template = std::move(descriptor);
  return policy;
}

}  // namespace nunchuk

#endif
