/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ledger/internal/core/bat_ledger_initializer.h"

#include <utility>

#include "bat/ledger/internal/core/bat_ledger_job.h"
#include "bat/ledger/internal/rewards_wallet/rewards_wallet_store.h"

namespace ledger {

namespace {

template <typename... Ts>
struct InitializeJob : public BATLedgerJob<bool> {
  void Start() { StartNext<Ts..., void>(true); }

  template <typename T, typename... Rest>
  void StartNext(bool success) {
    if (!success)
      return Complete(false);

    context().template Get<T>().Initialize().Then(
        ContinueWith(&InitializeJob::StartNext<Rest...>));
  }

  template <>
  void StartNext<void>(bool success) {
    Complete(success);
  }
};

using InitializeAllJob = InitializeJob<RewardsWalletStore>;

}  // namespace

const size_t BATLedgerInitializer::kComponentKey =
    BATLedgerContext::ReserveComponentKey();

Future<bool> BATLedgerInitializer::Initialize() {
  return context().StartJob<InitializeAllJob>();
}

}  // namespace ledger
