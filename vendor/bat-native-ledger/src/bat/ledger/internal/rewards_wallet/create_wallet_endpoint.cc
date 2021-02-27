/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ledger/internal/rewards_wallet/create_wallet_endpoint.h"

#include "base/json/json_reader.h"
#include "base/strings/string_number_conversions.h"
#include "bat/ledger/internal/common/request_util.h"
#include "bat/ledger/internal/common/security_util.h"
#include "net/http/http_status_code.h"

namespace ledger {

namespace {

const char kPath[] = "/v3/wallet/brave";

class RequestJob : public BATLedgerJob<optional<RewardsWallet>> {
 public:
  void Start() {
    auto keypair = wallet_.GenerateKeyPair();
    auto headers = wallet_.GetRequestSigningHeaders(
        "post", kPath, "", base::HexEncode(keypair.public_key));

    auto request = mojom::UrlRequest::New();
    request->method = mojom::UrlMethod::POST;
    request->url = GetUrl();  // TODO(zenparsing)
    request->headers = std::move(headers);

    context()
        .Get<URLFetcher>()
        .Fetch(std::move(request))
        .Then(ContinueWith(&RequestJob::OnResponse));
  }

 private:
  void OnResponse(mojom::UrlResponsePtr response) {
    if (!IsValidStatus(response.status_code))
      return Complete({});

    std::string payment_id = ParseResponse();
    if (payment_id.empty())
      return Complete({});

    Complete(RewardsWallet(payment_id, recovery_seed_));
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

  RewardsWallet wallet_ = RewardsWallet::CreateWithEmptyPaymentId();
};

}  // namespace

const size_t CreateWalletEndpoint::kComponentKey =
    BATLedgerContext::ReserveComponentKey();

Future<optional<RewardsWallet>> CreateWalletEndpoint::CreateRewardsWallet() {
  return context().StartJob<RequestJob>();
}

}  // namespace ledger
