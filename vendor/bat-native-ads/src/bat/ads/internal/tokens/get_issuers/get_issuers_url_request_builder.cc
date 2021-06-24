/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ads/internal/tokens/get_issuers/get_issuers_url_request_builder.h"

#include <cstdint>
#include <utility>

#include "base/base64.h"
#include "base/json/json_writer.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/values.h"
#include "bat/ads/ads.h"
#include "bat/ads/internal/logging.h"
#include "bat/ads/internal/security/crypto_util.h"
#include "bat/ads/internal/server/confirmations_server_util.h"
#include "bat/ads/internal/server/via_header_util.h"

namespace ads {

GetIssuersUrlRequestBuilder::GetIssuersUrlRequestBuilder() = default;

GetIssuersUrlRequestBuilder::~GetIssuersUrlRequestBuilder() = default;

// GET /v1/issuers/

UrlRequestPtr GetIssuersUrlRequestBuilder::Build() {
  UrlRequestPtr url_request = UrlRequest::New();
  url_request->url = BuildUrl();
  url_request->method = UrlRequestMethod::GET;

  return url_request;
}

///////////////////////////////////////////////////////////////////////////////

std::string GetIssuersUrlRequestBuilder::BuildUrl() const {
  const std::string kGetIssuersUrlMask =
      base::StringPrintf("%%s%s", kGetIssuersUrlPath);
  return base::StringPrintf(kGetIssuersUrlMask.c_str(),
                            confirmations::server::GetHost().c_str());
}

}  // namespace ads
