/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ledger/internal/uphold/uphold_wallet.h"

#include "bat/ledger/global_constants.h"
#include "bat/ledger/internal/common/random_util.h"
#include "bat/ledger/internal/ledger_impl.h"
#include "bat/ledger/internal/logging/event_log_keys.h"
#include "bat/ledger/internal/uphold/uphold_util.h"

using std::placeholders::_1;
using std::placeholders::_2;

namespace ledger {
namespace uphold {

namespace {
std::string GetNotificationForUserStatus(UserStatus status, bool verified) {
  switch (status) {
    case UserStatus::BLOCKED:
      return notifications::kBlockedUser;
    case UserStatus::OK:
      return !verified ? notifications::kUnverifiedUser : std::string{};
    case UserStatus::PENDING:
      return notifications::kPendingUser;
    case UserStatus::RESTRICTED:
      return notifications::kRestrictedUser;
    default:
      DCHECK(status == UserStatus::EMPTY);
      return {};
  }
}
}  // namespace

UpholdWallet::UpholdWallet(LedgerImpl* ledger)
    : ledger_{ledger},
      promotion_server_{std::make_unique<endpoint::PromotionServer>(ledger)} {}

UpholdWallet::~UpholdWallet() = default;

void UpholdWallet::Generate(ledger::ResultCallback callback) const {
  auto uphold_wallet = GetWallet(ledger_);
  if (!uphold_wallet) {
    uphold_wallet = type::ExternalWallet::New();
    uphold_wallet->type = constant::kWalletUphold;
    uphold_wallet->status = type::WalletStatus::NOT_CONNECTED;
    if (!ledger_->uphold()->SetWallet(uphold_wallet->Clone())) {
      BLOG(0, "Unable to set the Uphold wallet!");
      return callback(type::Result::LEDGER_ERROR);
    }

    ledger_->database()->SaveEventLog(
        log::kWalletStatusChange,
        "==> " + (std::ostringstream{} << uphold_wallet->status).str());
  }

  if (uphold_wallet->one_time_string.empty()) {
    uphold_wallet->one_time_string = util::GenerateRandomHexString();
  }
  uphold_wallet = GenerateLinks(std::move(uphold_wallet));

  const auto status = uphold_wallet->status;
  if (!ledger_->uphold()->SetWallet(std::move(uphold_wallet))) {
    BLOG(0, "Unable to set the Uphold wallet!");
    return callback(type::Result::LEDGER_ERROR);
  }

  if (status != type::WalletStatus::PENDING &&
      status != type::WalletStatus::VERIFIED) {
    return callback(type::Result::LEDGER_OK);
  }

  ledger_->uphold()->GetUser(
      std::bind(&UpholdWallet::OnGetUser, this, _1, _2, callback));
}

void UpholdWallet::OnGetUser(const type::Result result,
                             const User& user,
                             ledger::ResultCallback callback) const {
  auto uphold_wallet = GetWallet(ledger_);
  if (!uphold_wallet) {
    BLOG(0, "Uphold wallet is null!");
    return callback(type::Result::LEDGER_ERROR);
  }

  if (uphold_wallet->status != type::WalletStatus::PENDING &&
      uphold_wallet->status != type::WalletStatus::VERIFIED) {
    return callback(type::Result::LEDGER_OK);
  }

  DCHECK(!uphold_wallet->token.empty());
  DCHECK(uphold_wallet->status == type::WalletStatus::PENDING
             ? uphold_wallet->address.empty()
             : !uphold_wallet->address.empty());

  if (result == type::Result::EXPIRED_TOKEN) {
    BLOG(0, "Access token expired!");
    // Entering NOT_CONNECTED or DISCONNECTED_VERIFIED.
    ledger_->uphold()->DisconnectWallet(notifications::kWalletDisconnected);
    return callback(type::Result::EXPIRED_TOKEN);
  }

  if (result != type::Result::LEDGER_OK) {
    BLOG(0, "Couldn't get the user object from Uphold!");
    return callback(result);
  }

  if (user.bat_not_allowed) {
    BLOG(0, "BAT is not allowed for the user!");
    // Entering NOT_CONNECTED or DISCONNECTED_VERIFIED.
    ledger_->uphold()->DisconnectWallet(notifications::kBATNotAllowedForUser);
    return callback(type::Result::BAT_NOT_ALLOWED);
  }

  uphold_wallet->user_name = user.name;
  if (!ledger_->uphold()->SetWallet(uphold_wallet->Clone())) {
    BLOG(0, "Unable to set the Uphold wallet!");
    return callback(type::Result::LEDGER_ERROR);
  }

  if (user.status != UserStatus::OK || !user.verified) {
    const auto notification =
        GetNotificationForUserStatus(user.status, user.verified);

    if (uphold_wallet->status == type::WalletStatus::VERIFIED) {
      // Entering DISCONNECTED_VERIFIED.
      ledger_->uphold()->DisconnectWallet(
          !notification.empty() ? notification
                                : notifications::kWalletDisconnected);
    } else {
      if (!notification.empty()) {
        ledger_->ledger_client()->ShowNotification(notification, {},
                                                   [](type::Result) {});
      }
    }

    return callback(type::Result::LEDGER_OK);
  }

  if (uphold_wallet->status == type::WalletStatus::VERIFIED) {
    return ledger_->promotion()->TransferTokens(
        std::bind(&UpholdWallet::OnTransferTokens, this, _1, _2, callback));
  }

  ledger_->uphold()->CreateCard(
      std::bind(&UpholdWallet::OnCreateCard, this, _1, _2, callback));
}

void UpholdWallet::OnCreateCard(const type::Result result,
                                const std::string& id,
                                ledger::ResultCallback callback) const {
  auto uphold_wallet = GetWallet(ledger_);
  if (!uphold_wallet) {
    BLOG(0, "Uphold wallet is null!");
    return callback(type::Result::LEDGER_ERROR);
  }

  if (uphold_wallet->status != type::WalletStatus::PENDING) {
    return callback(type::Result::LEDGER_OK);
  }

  DCHECK(!uphold_wallet->token.empty());
  DCHECK(uphold_wallet->address.empty());

  if (result == type::Result::EXPIRED_TOKEN) {
    BLOG(0, "Access token expired!");
    // Entering NOT_CONNECTED.
    ledger_->uphold()->DisconnectWallet(notifications::kWalletDisconnected);
    return callback(type::Result::EXPIRED_TOKEN);
  }

  if (result != type::Result::LEDGER_OK) {
    return callback(result);
  }

  if (id.empty()) {
    BLOG(0, "Card ID is empty!");
    return callback(type::Result::LEDGER_ERROR);
  }

  GetAnonFunds(
      std::bind(&UpholdWallet::OnGetAnonFunds, this, _1, _2, id, callback));
}

void UpholdWallet::GetAnonFunds(
    endpoint::promotion::GetWalletBalanceCallback callback) const {
  // if we don't have user funds in anon card anymore
  // we can skip balance server ping
  if (!ledger_->state()->GetFetchOldBalanceEnabled()) {
    return callback(type::Result::LEDGER_OK, type::Balance::New());
  }

  const auto rewards_wallet = ledger_->wallet()->GetWallet();
  if (!rewards_wallet) {
    BLOG(1, "Rewards wallet is null!");
    ledger_->state()->SetFetchOldBalanceEnabled(false);
    return callback(type::Result::LEDGER_OK, type::Balance::New());
  }

  if (rewards_wallet->payment_id.empty()) {
    BLOG(0, "Payment ID is empty!");
    return callback(type::Result::LEDGER_ERROR, nullptr);
  }

  promotion_server_->get_wallet_balance()->Request(callback);
}

void UpholdWallet::OnGetAnonFunds(const type::Result result,
                                  type::BalancePtr balance,
                                  const std::string& id,
                                  ledger::ResultCallback callback) const {
  auto uphold_wallet = GetWallet(ledger_);
  if (!uphold_wallet) {
    BLOG(0, "Uphold wallet is null!");
    return callback(type::Result::LEDGER_ERROR);
  }

  if (uphold_wallet->status != type::WalletStatus::PENDING) {
    return callback(type::Result::LEDGER_OK);
  }

  DCHECK(!uphold_wallet->token.empty());
  DCHECK(uphold_wallet->address.empty());
  DCHECK(!id.empty());

  if (result != type::Result::LEDGER_OK) {
    BLOG(0, "Couldn't get anonymous funds!");
    return callback(result);
  }

  if (!balance) {
    BLOG(0, "Balance is null!");
    return callback(type::Result::LEDGER_ERROR);
  }

  if (balance->user_funds == 0.0) {  // == floating-point comparison!
    ledger_->state()->SetFetchOldBalanceEnabled(false);
  }

  LinkWallet(balance->user_funds, id,
             std::bind(&UpholdWallet::OnLinkWallet, this, _1, _2, callback));
}

void UpholdWallet::LinkWallet(
    const double user_funds,
    const std::string& id,
    ledger::endpoint::promotion::PostClaimUpholdCallback callback) const {
  promotion_server_->post_claim_uphold()->Request(user_funds, id, callback);
}

void UpholdWallet::OnLinkWallet(const type::Result result,
                                const std::string& id,
                                ledger::ResultCallback callback) const {
  auto uphold_wallet = GetWallet(ledger_);
  if (!uphold_wallet) {
    BLOG(0, "Uphold wallet is null!");
    return callback(type::Result::LEDGER_ERROR);
  }

  if (uphold_wallet->status != type::WalletStatus::PENDING) {
    return callback(type::Result::LEDGER_OK);
  }

  DCHECK(!uphold_wallet->token.empty());
  DCHECK(uphold_wallet->address.empty());
  DCHECK(!id.empty());

  if (result == type::Result::ALREADY_EXISTS) {
    // Entering NOT_CONNECTED.
    ledger_->uphold()->DisconnectWallet(
        notifications::kWalletDeviceLimitReached);

    ledger_->database()->SaveEventLog(
        log::kDeviceLimitReached,
        constant::kWalletUphold + std::string{"/"} + id.substr(0, 5));

    return callback(type::Result::ALREADY_EXISTS);
  }

  if (result != type::Result::LEDGER_OK) {
    return callback(result);  // used to be callback(type::Result::CONTINUE);
  }

  const auto from_status = uphold_wallet->status;
  uphold_wallet->status = type::WalletStatus::VERIFIED;
  const auto to_status = uphold_wallet->status;
  uphold_wallet->address = id;
  uphold_wallet = GenerateLinks(std::move(uphold_wallet));
  if (!ledger_->uphold()->SetWallet(std::move(uphold_wallet))) {
    BLOG(0, "Unable to set the Uphold wallet!");
    return callback(type::Result::LEDGER_ERROR);
  }

  ledger_->database()->SaveEventLog(
      log::kWalletStatusChange, (std::ostringstream{} << from_status).str() +
                                    " ==> " +
                                    (std::ostringstream{} << to_status).str());

  ledger_->database()->SaveEventLog(
      log::kWalletConnected,
      constant::kWalletUphold + std::string{"/"} + id.substr(0, 5));

  ledger_->promotion()->TransferTokens(
      std::bind(&UpholdWallet::OnTransferTokens, this, _1, _2, callback));
}

void UpholdWallet::OnTransferTokens(const type::Result result,
                                    const std::string& drain_id,
                                    ledger::ResultCallback callback) const {
  auto uphold_wallet = GetWallet(ledger_);
  if (!uphold_wallet) {
    BLOG(0, "Uphold wallet is null!");
    return callback(type::Result::LEDGER_ERROR);
  }

  if (uphold_wallet->status != type::WalletStatus::VERIFIED) {
    return callback(type::Result::LEDGER_OK);
  }

  DCHECK(!uphold_wallet->token.empty());
  DCHECK(!uphold_wallet->address.empty());

  if (result != type::Result::LEDGER_OK) {
    BLOG(0, "Transferring tokens failed!");
    return callback(type::Result::CONTINUE);
  }

  callback(type::Result::LEDGER_OK);
}

}  // namespace uphold
}  // namespace ledger
