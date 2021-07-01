/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <string>

#include "bat/ledger/internal/endpoint/gemini/gemini_utils.h"
#include "bat/ledger/global_constants.h"
#include "bat/ledger/ledger.h"
#include "net/http/http_status_code.h"
#include "testing/gtest/include/gtest/gtest.h"

// npm run test -- brave_unit_tests --filter=GeminiUtilsTest.*

namespace ledger {
namespace endpoint {
namespace gemini {

class GeminiUtilsTest : public testing::Test {};

TEST(GeminiUtilsTest, GetApiServerUrlDevelopment) {
  ledger::_environment = type::Environment::DEVELOPMENT;
  const std::string url = GetApiServerUrl("/test");
  ASSERT_EQ(url, GEMINI_API_STAGING_URL "/test");
}

TEST(GeminiUtilsTest, GetApiServerUrlStaging) {
  ledger::_environment = type::Environment::STAGING;
  const std::string url = GetApiServerUrl("/test");
  ASSERT_EQ(url, GEMINI_API_STAGING_URL "/test");
}

TEST(GeminiUtilsTest, GetApiServerUrlProduction) {
  ledger::_environment = type::Environment::PRODUCTION;
  const std::string url = GetApiServerUrl("/test");
  ASSERT_EQ(url, GEMINI_API_URL "/test");
}

TEST(GeminiUtilsTest, GetOauthServerUrlDevelopment) {
  ledger::_environment = type::Environment::DEVELOPMENT;
  const std::string url = GetOauthServerUrl("/test");
  ASSERT_EQ(url, GEMINI_OAUTH_STAGING_URL "/test");
}

TEST(GeminiUtilsTest, GetOauthServerUrlStaging) {
  ledger::_environment = type::Environment::STAGING;
  const std::string url = GetOauthServerUrl("/test");
  ASSERT_EQ(url, GEMINI_OAUTH_STAGING_URL "/test");
}

TEST(GeminiUtilsTest, GetOauthServerUrlProduction) {
  ledger::_environment = type::Environment::PRODUCTION;
  const std::string url = GetOauthServerUrl("/test");
  ASSERT_EQ(url, GEMINI_OAUTH_URL "/test");
}

TEST(GeminiUtilsTest, CheckStatusCodeTest) {
  ASSERT_EQ(CheckStatusCode(net::HTTP_UNAUTHORIZED),
            type::Result::EXPIRED_TOKEN);
  ASSERT_EQ(CheckStatusCode(net::HTTP_NOT_FOUND), type::Result::NOT_FOUND);
  ASSERT_EQ(CheckStatusCode(net::HTTP_BAD_REQUEST), type::Result::LEDGER_ERROR);
  ASSERT_EQ(CheckStatusCode(net::HTTP_OK), type::Result::LEDGER_OK);
}

}  // namespace gemini
}  // namespace endpoint
}  // namespace ledger
