/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_BROWSER_UI_VIEWS_SIDEBAR_SIDEBAR_ADD_ITEM_BUBBLE_DELEGATE_VIEW_H_
#define BRAVE_BROWSER_UI_VIEWS_SIDEBAR_SIDEBAR_ADD_ITEM_BUBBLE_DELEGATE_VIEW_H_

#include <memory>

#include "ui/views/bubble/bubble_dialog_delegate_view.h"

class BraveBrowser;

namespace sidebar {
struct SidebarItem;
}  // namespace sidebar

namespace views {
class Textfield;
}

// TODO(simonhong): Need to apply UI design spec. Currently, this just works.
class SidebarAddItemBubbleDelegateView
    : public views::BubbleDialogDelegateView {
 public:
  SidebarAddItemBubbleDelegateView(BraveBrowser* browser,
                                   views::View* anchor_view);
  ~SidebarAddItemBubbleDelegateView() override;

  SidebarAddItemBubbleDelegateView(const SidebarAddItemBubbleDelegateView&) =
      delete;
  SidebarAddItemBubbleDelegateView& operator=(
      const SidebarAddItemBubbleDelegateView&) = delete;

  // views::BubbleDialogDelegateView overrides:
  std::unique_ptr<views::NonClientFrameView> CreateNonClientFrameView(
      views::Widget* widget) override;

 private:
  void AddChildViews();

  // Passed |item| will be added to sidebar.
  void OnDefaultItemsButtonPressed(const sidebar::SidebarItem& item);
  void OnCurrentItemButtonPressed();

  BraveBrowser* browser_ = nullptr;

  // For VPN Test only. Delete before merging.
  void OnConnect();
  views::Textfield* host_;
  views::Textfield* username_;
  views::Textfield* password_;
};

#endif  // BRAVE_BROWSER_UI_VIEWS_SIDEBAR_SIDEBAR_ADD_ITEM_BUBBLE_DELEGATE_VIEW_H_
