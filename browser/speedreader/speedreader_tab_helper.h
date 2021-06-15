/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_BROWSER_SPEEDREADER_SPEEDREADER_TAB_HELPER_H_
#define BRAVE_BROWSER_SPEEDREADER_SPEEDREADER_TAB_HELPER_H_

#include "content/public/browser/web_contents_observer.h"
#include "content/public/browser/web_contents_user_data.h"

namespace content {
class NavigationHandle;
class WebContents;
}  // namespace content

namespace speedreader {

class SpeedreaderBubbleView;

// Determines if speedreader should be active for a given top-level navigation.
class SpeedreaderTabHelper
    : public content::WebContentsObserver,
      public content::WebContentsUserData<SpeedreaderTabHelper> {
 public:
  enum class DistillState {
    kNone,
    kReaderMode,
    kSpeedreaderMode,
  };
  ~SpeedreaderTabHelper() override;

  SpeedreaderTabHelper(const SpeedreaderTabHelper&) = delete;
  SpeedreaderTabHelper& operator=(SpeedreaderTabHelper&) = delete;

  bool IsActiveForMainFrame() const;

  // Returns |true| if Speedreader is turned on for all sites.
  bool IsSpeedreaderEnabled() const;

  // Returns |true| if the domain is Speedreader is enabled and the domain was
  // not blacklisted by the user.
  bool IsEnabledForSite();

  DistillState PageDistillState() const { return distill_state_; }

  // Allow or deny a site from being run through speedreader if |on| toggles
  // the setting. Triggers page reload on toggle.
  void MaybeToggleEnabledForSite(bool on);

  // Reload the page and mark the next request to run through Speedreader,
  // without turning it on. This mimics the standard reader mode.
  void SingleShotSpeedreader();

  // returns nullptr if no bubble currently shown
  SpeedreaderBubbleView* speedreader_bubble_view() const;

  // Displays speedreader information
  void ShowBubble();

  // Hides speedreader information
  void HideBubble();

  // Handler for when the bubble is dismissed.
  void OnBubbleClosed();

 private:
  friend class content::WebContentsUserData<SpeedreaderTabHelper>;
  explicit SpeedreaderTabHelper(content::WebContents* web_contents);

  void UpdateActiveState(content::NavigationHandle* handle);

  // content::WebContentsObserver
  void DidStartNavigation(
      content::NavigationHandle* navigation_handle) override;
  void DidRedirectNavigation(
      content::NavigationHandle* navigation_handle) override;
  void DidStopLoading() override;

  bool single_shot_next_request_ =
      false;  // run speedreader once on next page load
  DistillState distill_state_ = DistillState::kNone;
  SpeedreaderBubbleView* speedreader_bubble_ = nullptr;

  WEB_CONTENTS_USER_DATA_KEY_DECL();
};

}  // namespace speedreader

#endif  // BRAVE_BROWSER_SPEEDREADER_SPEEDREADER_TAB_HELPER_H_
