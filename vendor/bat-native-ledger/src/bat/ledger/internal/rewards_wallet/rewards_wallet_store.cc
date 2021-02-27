/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ledger/internal/rewards_wallet/rewards_wallet_store.h"

#include <utility>

#include "bat/ledger/internal/core/bat_ledger_job.h"
#include "bat/ledger/internal/core/sql_store.h"
#include "bat/ledger/internal/core/user_encryption.h"

namespace ledger {

namespace {

struct ReadResult {
  bool corrupted = false;
  optional<RewardsWallet> wallet;
};

struct ReadJob : public BATLedgerJob<ReadResult> {
  void Start() {
    context()
        .Get<SQLStore>()
        .Query("SELECT payment_id, recovery_seed FROM rewards_wallet LIMIT 1")
        .Then(ContinueWith(&ReadJob::OnReadComplete));
  }

  void OnReadComplete(mojom::DBCommandResponsePtr response) {
    SQLReader reader(response);
    if (!reader.Step())
      return Complete({corrupted = false, wallet = {}});

    std::string payment_id = reader.ColumnString(0);

    auto seed = context().Get<UserEncryption>().Base64DecryptString(
        reader.ColumnString(1));

    if (payment_id.empty() || !seed || (*seed).empty())
      return Complete({corrupted = true, wallet = {}})

    auto wallet = mojom::RewardsWallet::New();
    wallet->payment_id = std::move(payment_id);
    wallet->recovery_seed = std::move(*seed);

    Complete({corrupted = false, wallet = RewardsWallet(payment_id, *seed)});
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
      callback_([this, resolver](ReadResult result) mutable {
        if (result.wallet)
          rewards_wallet_ = std::move(result.wallet);

        resolver.Complete(!result.corrupted);
      }));

  return resolver.future();
}

Future<bool> RewardsWalletStore::SaveNew(const RewardsWallet& wallet) {
  DCHECK(!wallet.payment_id().empty());
  DCHECK(!wallet.recovery_seed().empty());

  if (rewards_wallet_)
    return Future<bool>::Completed(false);

  auto encrypted_seed = context().Get<UserEncryption>().Base64EncryptString(
      wallet.recovery_seed());

  if (!encrypted_seed)
    return Future<bool>::Completed(false);

  rewards_wallet_ = wallet;

  return context().StartJob<WriteJob>(wallet.payment_id(), *encrypted_seed);
}

}  // namespace ledger
