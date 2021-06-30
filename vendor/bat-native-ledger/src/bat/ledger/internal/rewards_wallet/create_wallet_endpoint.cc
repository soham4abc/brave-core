/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ledger/internal/rewards_wallet/create_wallet_endpoint.h"

namespace ledger {

namespace {

const char kPath[] = "/v3/wallet/brave";

class RequestJob : public BATLedgerJob<mojom::RewardsWalletPtr> {
 public:
  void Start() {
    recovery_seed_ = util::Security::GenerateSeed();

    auto request = mojom::UrlRequest::New();
    request->url = GetUrl();  // TODO(zenparsing)
    request->headers = util::BuildSignHeaders("post " + kPath, "",
        util::Security::GetPublicKeyHexFromSeed(recovery_seed), recovery_seed);
    request->method = type::UrlMethod::POST;

    context()
        .Get<URLFetcher>()
        .Fetch(std::move(request))
        .Then(ContinueWith(&RequestJob::OnResponse));
  }

 private:
  void OnResponse(mojom::UrlResponsePtr response) {
    if (!IsValidStatus(response.status_code))
      return Complete(nullptr);

    std::string payment_id = ParseResponse();
    if (payment_id.empty())
      return Complete(nullptr);

    DCHECK(!recovery_seed_.empty());

    auto wallet = mojom::RewardsWallet::New();
    wallet->payment_id = std::move(payment_id);
    wallet->recovery_seed = std::move(recovery_seed_);

    Complete(std::move(wallet));
  }

  bool IsValidStatus(int status_code) {
    switch (status_code) {
      case net::HTTP_SERVICE_UNAVAILABLE:
        context().LogError() << "No conversion rate yet in ratios service";
        return false;
      case net::HTTP_CREATED:
        return true;
      default:
        context().LogError() << "Unexpected HTTP status: " << status_code;
        return false;
    }
  }

  std::string ParseResponse(const std::string& body) {
    auto root = base::JSONReader::Read(body);
    if (!root || !root->is_dict()) {
      context().LogError() << "Invalid JSON";
      return "";
    }

    auto* payment_id = root->FindStringKey("paymentId");
    if (!payment_id || payment_id->empty()) {
      context().LogError() << "Missing paymentId in response";
      return "";
    }

    return *payment_id;
  }

  std::vector<uint8_t> recovery_seed_;
};

}  // namespace

const size_t CreateWalletEndpoint::kComponentKey =
    BATLedgerContext::ReserveComponentKey();

Future<mojom::RewardsWalletPtr> CreateWalletEndpoint::RequestNewWallet() {
  return context().StartJob<RequestJob>();
}

}  // namespace ledger
