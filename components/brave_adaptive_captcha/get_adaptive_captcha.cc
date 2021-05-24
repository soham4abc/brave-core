/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "brave/components/brave_adaptive_captcha/get_adaptive_captcha.h"

#include <utility>

#include "base/check.h"
#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "net/http/http_status_code.h"

namespace {

const char kDevelopment[] = "https://grant.rewards.brave.software";
const char kStaging[] = "https://grant.rewards.bravesoftware.com";
const char kProduction[] = "https://grant.rewards.brave.com";

std::string GetServerUrl(brave_adaptive_captcha::Environment environment,
                         const std::string& path) {
  DCHECK(!path.empty());

  std::string url;
  switch (environment) {
    case brave_adaptive_captcha::Environment::DEVELOPMENT:
      url = kDevelopment;
      break;
    case brave_adaptive_captcha::Environment::STAGING:
      url = kStaging;
      break;
    case brave_adaptive_captcha::Environment::PRODUCTION:
      url = kProduction;
      break;
  }

  return url + path;
}

}  // namespace

namespace brave_adaptive_captcha {

GetAdaptiveCaptcha::GetAdaptiveCaptcha(UrlLoader* url_loader,
                                       Environment environment)
    : url_loader_(url_loader), environment_(environment) {
  DCHECK(url_loader);
}

GetAdaptiveCaptcha::~GetAdaptiveCaptcha() = default;

std::string GetAdaptiveCaptcha::GetUrl(const std::string& payment_id,
                                       const std::string& captcha_id) {
  const std::string path = base::StringPrintf(
      "/v3/captcha/%s/%s", payment_id.c_str(), captcha_id.c_str());

  return GetServerUrl(environment_, path);
}

bool GetAdaptiveCaptcha::CheckStatusCode(int status_code) {
#if 0
  if (status_code == net::HTTP_BAD_REQUEST) {
    LOG(ERROR) << "Invalid captcha id";
    return false;
  }
#endif

  if (status_code == net::HTTP_NOT_FOUND) {
    LOG(ERROR) << "No scheduled captcha for given payment id";
    return false;
  }

  if (status_code == net::HTTP_INTERNAL_SERVER_ERROR) {
    LOG(ERROR) << "Failed to retrieve the captcha";
    return false;
  }

  if (status_code != net::HTTP_OK) {
    LOG(ERROR) << "Unexpected HTTP status: " << status_code;
    return false;
  }

  return true;
}

bool GetAdaptiveCaptcha::ParseBody(const std::string& body, std::string* html) {
  DCHECK(html);

  *html = body;

  return true;
}

void GetAdaptiveCaptcha::Request(const std::string& payment_id,
                                 const std::string& captcha_id,
                                 OnGetAdaptiveCaptcha callback) {
  auto url_callback =
      base::BindOnce(&GetAdaptiveCaptcha::OnRequest, base::Unretained(this),
                     std::move(callback));

  UrlLoader::UrlRequest url_request;
  url_request.url = GetUrl(payment_id, captcha_id);

  url_loader_->Load(url_request, std::move(url_callback));
}

void GetAdaptiveCaptcha::OnRequest(OnGetAdaptiveCaptcha callback,
                                   const UrlLoader::UrlResponse& url_response) {
  //  ledger::LogUrlResponse(__func__, url_response, true);

  bool result = CheckStatusCode(url_response.status_code);
  if (!result) {
    std::move(callback).Run(result, "");
    return;
  }

  std::string html;
  result = ParseBody(url_response.body, &html);

  std::move(callback).Run(result, html);
}

}  // namespace brave_adaptive_captcha
