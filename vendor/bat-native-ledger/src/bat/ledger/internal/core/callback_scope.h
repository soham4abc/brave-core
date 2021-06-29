/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_CORE_CALLBACK_SCOPE_H_
#define BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_CORE_CALLBACK_SCOPE_H_

#include <memory>
#include <utility>

#include "base/bind.h"

namespace ledger {

class CallbackScope {
 public:
  CallbackScope();
  ~CallbackScope();

  CallbackScope(const CallbackScope&) = delete;
  CallbackScope& operator=(const CallbackScope&) = delete;

  template <typename F>
  auto operator()(F fn) {
    return CallbackHelper<F>::Wrapper::Wrap(valid_, std::move(fn));
  }

 private:
  template <typename F, typename... Args>
  struct CallbackWrapper {
    static auto Wrap(std::shared_ptr<bool> valid, F fn) {
      return base::BindOnce(CallbackWrapper::OnCallback, valid, std::move(fn));
    }

    static void OnCallback(std::shared_ptr<bool> valid, F fn, Args... args) {
      if (*valid)
        fn(std::forward<Args>(args)...);
    }
  };

  template <typename F, typename Sig = decltype(&F::operator())>
  struct CallbackHelper;

  template <typename F, typename... Args>
  struct CallbackHelper<F, void (F::*)(Args...)> {
    using Wrapper = CallbackWrapper<F, Args...>;
  };

  template <typename F, typename... Args>
  struct CallbackHelper<F, void (F::*)(Args...) const> {
    using Wrapper = CallbackWrapper<F, Args...>;
  };

  std::shared_ptr<bool> valid_;
};

}  // namespace ledger

#endif  // BRAVE_VENDOR_BAT_NATIVE_LEDGER_SRC_BAT_LEDGER_INTERNAL_CORE_CALLBACK_SCOPE_H_
