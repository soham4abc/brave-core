/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ledger/internal/rewards_wallet_store.h"

#include <utility>

#include "bat/ledger/internal/core/bat_ledger_job.h"
#include "bat/ledger/internal/core/sql_store.h"
#include "bat/ledger/internal/core/user_encryption.h"

namespace ledger {

namespace {

struct ReadJob : public BATLedgerJob<mojom::RewardsWalletPtr> {
  void Start() {
    context()
        .Get<SQLStore>()
        .Query("SELECT payment_id, recovery_seed FROM rewards_wallet LIMIT 1")
        .Then(ContinueWith(&ReadJob::OnReadComplete));
  }

  void OnReadComplete(mojom::DBCommandResponsePtr response) {
    SQLReader reader(response);
    if (!reader.Step()) {
      return Complete(nullptr);
    }

    std::string payment_id = reader.ColumnString(0);

    auto seed = context().Get<UserEncryption>().Base64DecryptString(
        reader.ColumnString(1));

    if (payment_id.empty() || !seed || (*seed).empty()) {
      // TODO: Wallet corruption - how should we recover?
      return Complete(nullptr);
    }

    auto wallet = mojom::RewardsWallet::New();
    wallet->payment_id = std::move(payment_id);
    wallet->recovery_seed = std::move(*seed);

    Complete(std::move(wallet));
  }
};

struct WriteJob : public BATLedgerJob<bool> {
  void Start(const std::string& payment_id, const std::string& encrypted_seed) {
    DCHECK(!payment_id.empty());
    DCHECK(!encrypted_seed.empty());

    context()
        .Get<SQLStore>()
        .Execute(
            "INSERT INTO rewards_wallet (payment_id, recovery_seed) "
            "VALUES (?, ?)",
            payment_id, encrypted_seed)
        .Then(ContinueWith(&WriteJob::OnInsertComplete));
  }

  void OnInsertComplete(mojom::DBCommandResponsePtr response) {
    // TODO(zenparsing): If it didn't succeed then we need to retry or something
    SQLReader reader(response);
    Complete(reader.Succeeded());
  }
};

}  // namespace

const size_t RewardsWalletStore::kComponentKey =
    BATLedgerContext::ReserveComponentKey();

Future<bool> RewardsWalletStore::Initialize() {
  Future<bool>::Resolver resolver;

  context().StartJob<ReadJob>().Then(
      callback_([this, resolver](mojom::RewardsWalletPtr wallet) mutable {
        if (wallet) {
          rewards_wallet_.payment_id = std::move(wallet->payment_id);
          rewards_wallet_.recovery_seed = std::move(wallet->recovery_seed);
        }

        resolver.Complete(true);
      }));

  return resolver.future();
}

Future<bool> RewardsWalletStore::SaveNew(const std::string& payment_id,
                                         const std::string& recovery_seed) {
  DCHECK(!payment_id.empty());

  Future<bool>::Resolver resolver;
  if (!rewards_wallet_.payment_id.empty()) {
    resolver.Complete(false);
    return resolver.future();
  }

  auto encrypted_seed =
      context().Get<UserEncryption>().Base64EncryptString(recovery_seed);

  if (!encrypted_seed) {
    resolver.Complete(false);
    return resolver.future();
  }

  rewards_wallet_.payment_id = payment_id;
  rewards_wallet_.recovery_seed = recovery_seed;

  return context().StartJob<WriteJob>(payment_id, *encrypted_seed);
}

}  // namespace ledger
