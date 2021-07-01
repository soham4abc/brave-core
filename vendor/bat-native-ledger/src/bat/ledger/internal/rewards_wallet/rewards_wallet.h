/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_REWARDS_WALLET_REWARDS_WALLET_H_
#define BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_REWARDS_WALLET_REWARDS_WALLET_H_

#include <map>
#include <string>
#include <vector>

namespace ledger {

class RewardsWallet {
 public:
  RewardsWallet(const std::string& payment_id,
                const std::vector<uint8_t>& recovery_seed);

  RewardsWallet(const std::string& payment_id,
                const std::string& recovery_seed);

  RewardsWallet(const RewardsWallet& other);

  ~RewardsWallet();

  const std::string& payment_id() const { return payment_id_; }

  const std::vector<uint8_t>& recovery_seed() const { return recovery_seed_; }

  static RewardsWallet CreateWithEmptyPaymentId();

  struct KeyPair {
    KeyPair();
    KeyPair(const KeyPair& other);
    ~KeyPair();

    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
  };

  KeyPair GenerateKeyPair();

  std::string SignHeaders(const std::map<std::string, std::string>& headers,
                          const std::string& request_id);

  std::vector<std::string> GetRequestSigningHeaders(
      const std::string& method,
      const std::string& path,
      const std::string& body,
      const std::string& request_id);

  std::vector<std::string> GetRequestSigningHeaders(
      const std::string& method,
      const std::string& path,
      const std::string& body);

 private:
  RewardsWallet();

  std::string payment_id_;
  std::vector<uint8_t> recovery_seed_;
};

}  // namespace ledger

#endif
