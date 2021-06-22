/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "base/json/json_reader.h"
#include "base/strings/stringprintf.h"
#include "base/values.h"
#include "bat/ads/internal/ads_client_helper.h"
#include "bat/ads/internal/tokens/get_issuers/get_issuers.h"
#include "bat/ads/internal/tokens/get_issuers/get_issuers_url_request_builder.h"
#include "net/http/http_status_code.h"

namespace ads {

GetIssuers::GetIssuers() : initialized_(false) {}

GetIssuers::~GetIssuers() = default;

void GetIssuers::set_delegate(GetIssuersDelegate* delegate) {
  delegate_ = delegate;
}

void GetIssuers::RequestIssuers(const ConfirmationCallback& callback) {
  initialized_ = false;

  BLOG(1, "RequestIssuers");
  BLOG(2, base::StringPrintf("GET %s", kGetIssuersUrlPath));

  GetIssuersUrlRequestBuilder url_request_builder;
  UrlRequestPtr url_request = url_request_builder.Build();
  BLOG(5, UrlRequestToString(url_request));
  BLOG(7, UrlRequestHeadersToString(url_request));

  auto request_callback = std::bind(&GetIssuers::OnRequestIssuers, this,
                                    std::placeholders::_1, callback);
  AdsClientHelper::Get()->UrlRequest(std::move(url_request), request_callback);
}

void GetIssuers::OnRequestIssuers(
    const UrlResponse& url_response,
    const ConfirmationCallback& callback) {
  BLOG(1, "OnRequestIssuers");

  BLOG(6, UrlResponseToString(url_response));
  BLOG(7, UrlResponseHeadersToString(url_response));

  if (url_response.status_code != net::HTTP_OK) {
    BLOG(0, "Failed to get issuers");
    initialized_ = false;
    return;
  }

  bool parsed = ParseResponseBody(url_response);
  if (!parsed) {
    BLOG(3, "Failed to parse response: " << url_response.body);
    initialized_ = false;
    return;
  }

  initialized_ = true;
  if (callback) {
    callback();
  }
}

bool GetIssuers::ParseResponseBody(const UrlResponse& url_response) {
  issuer_name_to_public_keys_.clear();

  base::Optional<base::Value> issuer_list =
      base::JSONReader::Read(url_response.body);

  for (const auto& value : issuer_list->GetList()) {
    if (!value.is_dict()) {
      return false;
    }

    const base::Value* public_key_dict = value.FindPath("");
    const std::string* public_key_name = public_key_dict->FindStringKey("name");

    if (!public_key_name) {
      continue;
    }

    std::set<std::string> current_public_keys_;
    const base::Value* public_key_list = public_key_dict->FindListKey("publicKeys");
    for (const auto& public_key : public_key_list->GetList()) {
      if (!public_key.is_string()) {
        continue;
      }
      current_public_keys_.insert(public_key.GetString());
    }

    issuer_name_to_public_keys_[*public_key_name] = current_public_keys_;
  }

  return true;
}

bool GetIssuers::IsInitialized() {
  return initialized_;
}

bool GetIssuers::FindPublicKey(
    const std::string& issuer_name,
    const std::string& public_key) {
  if (!IsInitialized()) {
    return false;
  }

  auto iter = issuer_name_to_public_keys_.find(issuer_name);
  if (iter == issuer_name_to_public_keys_.end()) {
    return false;
  }

  return static_cast<bool>(iter->second.count(public_key));
}

void GetIssuers::OnDidGetIssuers() {
  if (!delegate_) {
    return;
  }

  delegate_->OnDidGetIssuers();
}

void GetIssuers::OnFailedToGetIssuers() {
  if (!delegate_) {
    return;
  }

  delegate_->OnFailedToGetIssuers();
}

}  // namespace ads
