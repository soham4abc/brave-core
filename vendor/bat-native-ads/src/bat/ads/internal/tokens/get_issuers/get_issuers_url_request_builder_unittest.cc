/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <set>
#include <vector>

#include "base/json/json_reader.h"
#include "base/values.h"
#include "bat/ads/internal/tokens/get_issuers/get_issuers_url_request_builder.h"
#include "bat/ads/internal/unittest_base.h"

#include "testing/gtest/include/gtest/gtest.h"

// npm run test -- brave_unit_tests --filter=BatAds*

namespace ads {

using challenge_bypass_ristretto::PublicKey;
using challenge_bypass_ristretto::UnblindedToken;

class BatAdsGetIssuersTest : public UnitTestBase {
 protected:
  BatAdsGetIssuersTest() = default;

  ~BatAdsGetIssuersTest() override = default;
};

TEST(BatAdsGetIssuersTest, BuildUrl) {
  // Arrange
  GetIssuersUrlRequestBuilder url_request_builder;

  // Act
  UrlRequestPtr url_request = url_request_builder.Build();

  // Assert
  base::Optional<base::Value> issuer_list =
      base::JSONReader::Read(url_response.body);
  ASSERT_TRUE(issuer_list);
  ASSERT_TRUE(issuer_list->is_list());

  const std::vector<std::string> kExpectedSections =
      {"confirmation", "payments"};
  const std::set<std::string> kExpectedSectionsSet(
      kExpectedSections.begin(),
      kExpectedSections.end());
  std::vector<bool> section_found(kExpectedSections.size(), false);

  for (const auto& value : issuer_list->GetList()) {
    ASSERT_TRUE(value.is_dict());

    const base::Value* public_key_dict = value.FindPath("");
    const std::string* public_key_name = public_key_dict->FindStringKey("name");
    ASSERT_TRUE(public_key_name);
    ASSERT_TRUE(kExpectedSectionsSet.count(*public_key_name));

    for (size_t i = 0; i < kExpectedSections.size(); ++i) {
      if (*public_key_name == kExpectedSections[i]) {
        section_found[i] = true;
        break;
      }
    }

    const base::Value* public_key_list = public_key_dict->FindListKey("publicKeys");
    ASSERT(public_key_list);
  }

  bool all_sections_found = true;
  for (size_t i = 0; i < kExpectedSections.size(); ++i) {
    all_sections_found &= section_found[i];
  }

  EXPECT_TRUE(all_sections_found);
}

}  // namespace ads
