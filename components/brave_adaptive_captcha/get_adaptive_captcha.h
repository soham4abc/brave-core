/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_COMPONENTS_BRAVE_ADAPTIVE_CAPTCHA_GET_ADAPTIVE_CAPTCHA_H_
#define BRAVE_COMPONENTS_BRAVE_ADAPTIVE_CAPTCHA_GET_ADAPTIVE_CAPTCHA_H_

#include <string>

#include "base/callback.h"
#include "brave/components/brave_adaptive_captcha/environment.h"
#include "brave/components/brave_adaptive_captcha/url_loader.h"

// GET /v3/captcha/{payment_id}/{captcha_id}
//
// Success code:
// HTTP_OK (200)
//
// Error codes:
// HTTP_NOT_FOUND (404)
// HTTP_INTERNAL_SERVER_ERROR (500)
//
// Response body:
// {HTML/JavaScript BLOB}

namespace brave_adaptive_captcha {

using OnGetAdaptiveCaptcha =
    base::OnceCallback<void(bool result, const std::string&)>;

class GetAdaptiveCaptcha {
 public:
  GetAdaptiveCaptcha(UrlLoader* url_loader, Environment environment);
  ~GetAdaptiveCaptcha();

  void Request(const std::string& payment_id,
               const std::string& captcha_id,
               OnGetAdaptiveCaptcha callback);

 private:
  std::string GetUrl(const std::string& payment_id,
                     const std::string& captcha_id);

  bool CheckStatusCode(int status_code);

  bool ParseBody(const std::string& body, std::string* html);

  void OnRequest(OnGetAdaptiveCaptcha callback,
                 const UrlLoader::UrlResponse& response_body);

  UrlLoader* url_loader_;
  Environment environment_;
};

}  // namespace brave_adaptive_captcha

#endif  // BRAVE_COMPONENTS_BRAVE_ACAPTCHA_GET_ADAPTIVE_CAPTCHA_H_
