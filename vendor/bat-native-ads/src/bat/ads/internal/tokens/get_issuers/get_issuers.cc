/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ads/internal/tokens/get_issuers/get_issuers.h"
#include "base/json/json_reader.h"
#include "base/strings/stringprintf.h"
#include "base/values.h"
#include "bat/ads/internal/ads_client_helper.h"
#include "bat/ads/internal/tokens/get_issuers/get_issuers_url_request_builder.h"
#include "net/http/http_status_code.h"

#include <iostream>

namespace ads {

GetIssuers::GetIssuers() : initialized_(false) {}

GetIssuers::~GetIssuers() = default;

void GetIssuers::set_delegate(GetIssuersDelegate* delegate) {
  delegate_ = delegate;
}

void GetIssuers::RequestIssuers(const ConfirmationCallback& callback) {
  std::cerr << "REQ ISS 1" << std::endl;

  initialized_ = false;

  BLOG(1, "RequestIssuers");
  BLOG(2, base::StringPrintf("GET %s", kGetIssuersUrlPath));

  GetIssuersUrlRequestBuilder url_request_builder;
  UrlRequestPtr url_request = url_request_builder.Build();
  BLOG(5, UrlRequestToString(url_request));
  BLOG(7, UrlRequestHeadersToString(url_request));

  std::cerr << "REQ ISS 2" << std::endl;

  auto request_callback = std::bind(&GetIssuers::OnRequestIssuers, this,
                                    std::placeholders::_1, callback);
  AdsClientHelper::Get()->UrlRequest(std::move(url_request), request_callback);
  std::cerr << "REQ ISS 3" << std::endl;
}

void GetIssuers::OnRequestIssuers(const UrlResponse& url_response,
                                  const ConfirmationCallback& callback) {
  std::cerr << "REQ ISS 4" << std::endl;
  BLOG(1, "OnRequestIssuers");

  BLOG(6, UrlResponseToString(url_response));
  BLOG(7, UrlResponseHeadersToString(url_response));

  std::cerr << "ISS: " << UrlResponseToString(url_response) << std::endl;

  if (url_response.status_code != net::HTTP_OK) {
    BLOG(0, "Failed to get issuers");
    initialized_ = false;
    OnFailedToGetIssuers();
    if (callback) {
      callback();
    }
    return;
  }

  std::cerr << "REQ ISS 5" << std::endl;

  bool parsed = ParseResponseBody(url_response);
  std::cerr << "REQ ISS PARSED: " << parsed << std::endl;
  if (!parsed) {
    BLOG(3, "Failed to parse response: " << url_response.body);
    initialized_ = false;
    OnFailedToGetIssuers();
    if (callback) {
      callback();
    }
    return;
  }

  std::cerr << "REQ ISS 6" << std::endl;

  initialized_ = true;
  OnDidGetIssuers();

  if (callback) {
    callback();
  }

  std::cerr << "REQ ISS 7" << std::endl;
}

bool GetIssuers::ParseResponseBody(const UrlResponse& url_response) {
  issuer_name_to_public_keys_.clear();

  base::Optional<base::Value> issuer_list =
      base::JSONReader::Read(url_response.body);

  if (!issuer_list || !issuer_list->is_list()) {
    return false;
  }

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
    const base::Value* public_key_list =
        public_key_dict->FindListKey("publicKeys");
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

bool GetIssuers::FindPublicKey(const std::string& issuer_name,
                               const std::string& public_key) {
  if (!IsInitialized()) {
    return false;
  }

  auto iter = issuer_name_to_public_keys_.find(issuer_name);
  if (iter == issuer_name_to_public_keys_.end()) {
    return false;
  }

  std::cerr << iter->second.count(public_key) << std::endl;

  return static_cast<bool>(iter->second.count(public_key));
}

void GetIssuers::OnDidGetIssuers() {
  if (!delegate_) {
    return;
  }

  std::cerr << "REQ ISS DID" << std::endl;
  delegate_->OnDidGetIssuers();
}

void GetIssuers::OnFailedToGetIssuers() {
  if (!delegate_) {
    return;
  }

  std::cerr << "REQ ISS DIDN'T" << std::endl;
  delegate_->OnFailedToGetIssuers();
}

}  // namespace ads
