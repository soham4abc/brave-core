/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "brave/components/brave_adaptive_captcha/get_adaptive_captcha.h"

#include <memory>
#include <string>

#include "base/run_loop.h"
#include "base/test/task_environment.h"
#include "brave/components/brave_adaptive_captcha/environment.h"
#include "net/http/http_status_code.h"
#include "services/network/public/cpp/weak_wrapper_shared_url_loader_factory.h"
#include "services/network/test/test_url_loader_factory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

// npm run test -- brave_unit_tests --filter=GetAdaptiveCaptchaTest.*

namespace brave_adaptive_captcha {

class GetAdaptiveCaptchaTest : public testing::Test {
 public:
  GetAdaptiveCaptchaTest() {
    url_loader_ = std::make_unique<UrlLoader>(
        test_url_loader_factory_.GetSafeWeakWrapper());
    captcha_ = std::make_unique<GetAdaptiveCaptcha>(url_loader_.get(),
                                                    Environment::STAGING);
  }

  void OnGetAdaptiveCaptchaServerOK(bool result, const std::string& html) {
    EXPECT_EQ(result, true);
    EXPECT_EQ(html, "<html><body>Hello, world!</body></html>");
    SignalUrlLoadCompleted();
  }

  void OnGetAdaptiveCaptchaServerError404(bool result,
                                          const std::string& html) {
    EXPECT_EQ(result, false);
    EXPECT_EQ(html, "");
    SignalUrlLoadCompleted();
  }

  void OnGetAdaptiveCaptchaServerError500(bool result,
                                          const std::string& html) {
    EXPECT_EQ(result, false);
    EXPECT_EQ(html, "");
    SignalUrlLoadCompleted();
  }

  void OnGetAdaptiveCaptchaServerErrorRandom(bool result,
                                             const std::string& html) {
    EXPECT_EQ(result, false);
    EXPECT_EQ(html, "");
    SignalUrlLoadCompleted();
  }

 protected:
  network::TestURLLoaderFactory test_url_loader_factory_;
  std::unique_ptr<GetAdaptiveCaptcha> captcha_;

  void WaitForUrlLoadToComplete() {
    if (url_loaded_) {
      return;
    }

    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
  }

 private:
  base::test::TaskEnvironment scoped_task_environment_;
  std::unique_ptr<UrlLoader> url_loader_;
  std::unique_ptr<base::RunLoop> run_loop_;
  bool url_loaded_ = false;

  void SignalUrlLoadCompleted() {
    url_loaded_ = true;
    if (run_loop_) {
      run_loop_->Quit();
    }
  }
};

TEST_F(GetAdaptiveCaptchaTest, ServerOK) {
  test_url_loader_factory_.AddResponse(
      "https://grant.rewards.bravesoftware.com"
      "/v3/captcha/payment_id/captcha_id",
      "<html><body>Hello, world!</body></html>", net::HTTP_OK);
  captcha_->Request(
      "payment_id", "captcha_id",
      base::BindOnce(&GetAdaptiveCaptchaTest::OnGetAdaptiveCaptchaServerOK,
                     base::Unretained(this)));
  WaitForUrlLoadToComplete();
}

TEST_F(GetAdaptiveCaptchaTest, ServerError404) {
  test_url_loader_factory_.AddResponse(
      "https://grant.rewards.bravesoftware.com"
      "/v3/captcha/payment_id/captcha_id",
      "<html><body>Hello, world!</body></html>", net::HTTP_NOT_FOUND);
  captcha_->Request(
      "payment_id", "captcha_id",
      base::BindOnce(
          &GetAdaptiveCaptchaTest::OnGetAdaptiveCaptchaServerError404,
          base::Unretained(this)));
  WaitForUrlLoadToComplete();
}

TEST_F(GetAdaptiveCaptchaTest, ServerError500) {
  test_url_loader_factory_.AddResponse(
      "https://grant.rewards.bravesoftware.com"
      "/v3/captcha/payment_id/captcha_id",
      "<html><body>Hello, world!</body></html>",
      net::HTTP_INTERNAL_SERVER_ERROR);
  captcha_->Request(
      "payment_id", "captcha_id",
      base::BindOnce(
          &GetAdaptiveCaptchaTest::OnGetAdaptiveCaptchaServerError500,
          base::Unretained(this)));
  WaitForUrlLoadToComplete();
}

TEST_F(GetAdaptiveCaptchaTest, ServerErrorRandom) {
  test_url_loader_factory_.AddResponse(
      "https://grant.rewards.bravesoftware.com"
      "/v3/captcha/payment_id/captcha_id",
      "<html><body>Hello, world!</body></html>", net::HTTP_TOO_MANY_REQUESTS);
  captcha_->Request(
      "payment_id", "captcha_id",
      base::BindOnce(
          &GetAdaptiveCaptchaTest::OnGetAdaptiveCaptchaServerErrorRandom,
          base::Unretained(this)));
  WaitForUrlLoadToComplete();
}

}  // namespace brave_adaptive_captcha
