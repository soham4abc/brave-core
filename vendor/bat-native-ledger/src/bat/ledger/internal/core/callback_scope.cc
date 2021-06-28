/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ledger/internal/core/callback_scope.h"

namespace ledger {

CallbackScope::CallbackScope() : valid_(std::make_shared<bool>(true)) {}

CallbackScope::~CallbackScope() { *valid_ = false; }

}  // namespace ledger
