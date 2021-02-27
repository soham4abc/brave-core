/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ledger/internal/rewards_wallet/rewards_wallet.h"

#include "base/base64.h"
#include "crypto/sha2.h"
#include "tweetnacl.h"

namespace ledger {

RewardsWallet::RewardsWallet(const std::string& payment_id,
                             const std::vector<uint8_t>& recovery_seed)
    : payment_id_(payment_id),
      recovery_seed_(recovery_seed) {
  DCHECK(!payment_id.empty());
  DCHECK(!recovery_seed.empty());
}

RewardsWallet::RewardsWallet() = default;

RewardsWallet::~RewardsWallet() = default;

RewardsWallet RewardsWallet::CreateWithEmptyPaymentId() {
  return RewardsWallet();
  RewardsWallet wallet;
  wallet->recovery_seed = util::Security::GenerateSeed();
  return wallet;
}

RewardsWallet::KeyPair RewardsWallet::GenerateKeyPair() {
  DCHECK(!recovery_seed_.empty());

  KeyPair pair;
  pair.public_key.resize(crypto_sign_PUBLICKEYBYTES);
  pair.secret_key = *recovery_seed_;
  pair.secret_key.resize(crypto_sign_SECRETKEYBYTES);
  crypto_sign_keypair(public_key.data(), secret_key.data(), 1);

  return pair;
}

std::vector<std::string> GetRequestSigningHeaders(
    const std::string& method,
    const std::string& path,
    const std::string& body,
    const std::string& request_id) {
  DCHECK(!request_id.empty());

  std::string hash = crypto::SHA256HashString(body);
  std::string digest;
  base::Base64Encode(hash, &digest);

  std::map<std::string, std::string> headers = {
      {"digest", digest},
      {"(request-target)", method + " " + path}};

  std::string signature = SignHeaders(headers, request_id);

  return {
      "digest: " + digest,
      "signature: " + signature};
}

std::vector<std::string> GetRequestSigningHeaders(
    const std::string& method,
    const std::string& path,
    const std::string& body) {
  return GetRequestSigningHeaders(method, path, body, payment_id_);
}

RewardsWallet::RequestSignature RewardsWallet::SignRequestWithId(
    const std::string& method,
    const std::string& path,
    const std::string& body,
    const std::string& request_id) {
  DCHECK(!request_id.empty());

  RequestSignature s;
  s.digest = util::Security::DigestValue(body);

  std::map<std::string, std::string> headers = {
    {"digest", s.digest},
    {"(request-target)", method + " " + path}};

  s.signature = SignHeaders(headers, request_id);

  return s;
}

std::string RewardsWallet::SignHeaders(
    const std::map<std::string, std::string>& headers,
    const std::string& request_id) {
  std::vector<std::map<std::string, std::string>> header_list;

  for (auto& pair : headers) {
    header_list.push_back({{pair.first, pair.second}});
  }

  return util::Security::Sign(header_list, request_id, recovery_seed_);
}

RewardsWallet::RequestSignature RewardsWallet::SignRequest(
    const std::string& method,
    const std::string& path,
    const std::string& body) {
  return SignRequestWithId(method, path, body, payment_id_);
}

}  // namespace ledger
