/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ledger/internal/state/state_migration_v10.h"

#include <string>
#include <utility>

#include "base/base64.h"
#include "base/json/json_reader.h"
#include "bat/ledger/internal/core/user_encryption.h"
#include "bat/ledger/internal/ledger_impl.h"
#include "bat/ledger/internal/rewards_wallet/rewards_wallet_store.h"
#include "bat/ledger/internal/state/state_keys.h"

namespace ledger {

namespace state {

namespace {

mojom::RewardsWalletPtr ParseWalletJSON(const std::string& data) {
  auto root = base::JSONReader::Read(data);
  if (!root || !root->is_dict())
    return {};

  auto* payment_id = root->FindStringKey("payment_id");
  if (!payment_id)
    return {};

  auto* seed = root->FindStringKey("recovery_seed");
  if (!seed)
    return {};

  std::string decoded_seed;
  if (!base::Base64Decode(*seed, &decoded_seed))
    return {};

  auto wallet = mojom::RewardsWallet::New();
  wallet->payment_id = *payment_id;
  wallet->recovery_seed = std::move(decoded_seed);
  return wallet;
}

}  // namespace

StateMigrationV10::StateMigrationV10(LedgerImpl* ledger) : ledger_(ledger) {}

StateMigrationV10::~StateMigrationV10() = default;

void StateMigrationV10::Migrate(ledger::ResultCallback callback) {
  std::string pref_data =
      ledger_->ledger_client()->GetStringState(kWalletBrave);

  if (pref_data.empty()) {
    callback(type::Result::LEDGER_OK);
    return;
  }

  auto json =
      ledger_->context().Get<UserEncryption>().Base64DecryptString(pref_data);

  if (!json) {
    BLOG(0, "Rewards wallet data could not be decrypted from user preferences");
    callback(type::Result::LEDGER_OK);
    return;
  }

  auto result = ParseWalletJSON(*json);
  if (!result) {
    BLOG(0, "Rewards wallet could not be parsed from user preferences");
    callback(type::Result::LEDGER_OK);
    return;
  }

  auto on_saved = [](ledger::ResultCallback callback, bool success) {
    BLOG(0, "Error migrating Rewards wallet to database");
    callback(type::Result::LEDGER_OK);
  };

  ledger_->context()
      .Get<RewardsWalletStore>()
      .SaveNew(result->payment_id, result->recovery_seed)
      .Then(base::BindOnce(on_saved, callback));
}

}  // namespace state
}  // namespace ledger
