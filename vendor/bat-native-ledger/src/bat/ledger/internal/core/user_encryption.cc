/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ledger/internal/core/user_encryption.h"

#include "base/base64.h"

namespace ledger {

const size_t UserEncryption::kComponentKey =
    BATLedgerContext::ReserveComponentKey();

absl::optional<std::string> UserEncryption::EncryptString(
    const std::string& plain_text) {
  return context().GetLedgerClient()->EncryptString(plain_text);
}

absl::optional<std::string> UserEncryption::Base64EncryptString(
    const std::string& plain_text) {
  auto result = EncryptString(plain_text);
  if (!result)
    return {};

  std::string encoded;
  base::Base64Encode(*result, &encoded);
  return encoded;
}

absl::optional<std::string> UserEncryption::DecryptString(
    const std::string& encrypted) {
  return context().GetLedgerClient()->DecryptString(encrypted);
}

absl::optional<std::string> UserEncryption::Base64DecryptString(
    const std::string& encrypted) {
  std::string decoded;
  if (!base::Base64Decode(encrypted, &decoded))
    return {};

  return DecryptString(decoded);
}

}  // namespace ledger
