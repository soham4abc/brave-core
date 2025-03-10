/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "brave/browser/ui/browser_commands.h"

#include "base/files/file_path.h"
#include "brave/components/brave_wallet/common/buildflags/buildflags.h"
#include "brave/components/speedreader/buildflags.h"
#include "brave/components/tor/buildflags/buildflags.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/profiles/profile_manager.h"
#include "chrome/browser/profiles/profile_metrics.h"
#include "chrome/browser/profiles/profile_window.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/browser_commands.h"
#include "chrome/browser/ui/profile_picker.h"
#include "chrome/browser/ui/tabs/tab_strip_model.h"
#include "chrome/common/pref_names.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/web_contents.h"

#if defined(TOOLKIT_VIEWS)
#include "brave/browser/ui/views/frame/brave_browser_view.h"
#endif

#if BUILDFLAG(ENABLE_SPEEDREADER)
#include "brave/browser/speedreader/speedreader_service_factory.h"
#include "brave/browser/speedreader/speedreader_tab_helper.h"
#include "brave/components/speedreader/speedreader_service.h"
#endif

#if BUILDFLAG(ENABLE_TOR)
#include "brave/browser/tor/tor_profile_manager.h"
#include "brave/browser/tor/tor_profile_service_factory.h"
#include "brave/components/tor/tor_profile_service.h"
#endif

using content::WebContents;

namespace {
}  // namespace

namespace brave {

void NewOffTheRecordWindowTor(Browser* browser) {
  if (browser->profile()->IsTor()) {
    chrome::OpenEmptyWindow(browser->profile());
    return;
  }

  TorProfileManager::SwitchToTorProfile(browser->profile(),
                                        ProfileManager::CreateCallback());
}

void NewTorConnectionForSite(Browser* browser) {
#if BUILDFLAG(ENABLE_TOR)
  Profile* profile = browser->profile();
  DCHECK(profile);
  tor::TorProfileService* service =
    TorProfileServiceFactory::GetForContext(profile);
  DCHECK(service);
  WebContents* current_tab =
    browser->tab_strip_model()->GetActiveWebContents();
  if (!current_tab)
    return;
  service->SetNewTorCircuit(current_tab);
#endif
}

void AddNewProfile() {
  ProfilePicker::Show(ProfilePicker::EntryPoint::kProfileMenuAddNewProfile);
}

void OpenGuestProfile() {
  PrefService* service = g_browser_process->local_state();
  DCHECK(service);
  DCHECK(service->GetBoolean(prefs::kBrowserGuestModeEnabled));
  profiles::SwitchToGuestProfile(ProfileManager::CreateCallback());
}

void MaybeDistillAndShowSpeedreaderBubble(Browser* browser) {
#if BUILDFLAG(ENABLE_SPEEDREADER)
  using DistillState = speedreader::SpeedreaderTabHelper::DistillState;
  speedreader::SpeedreaderService* service =
      speedreader::SpeedreaderServiceFactory::GetForProfile(browser->profile());
  if (service) {
    WebContents* contents = browser->tab_strip_model()->GetActiveWebContents();
    if (contents) {
      auto* tab_helper =
          speedreader::SpeedreaderTabHelper::FromWebContents(contents);
      if (!tab_helper)
        return;

      const bool speedreader_enabled = tab_helper->IsSpeedreaderEnabled();
      const DistillState state = tab_helper->PageDistillState();

      if (state == DistillState::kSpeedreaderMode) {
        // The page was distilled by Speedreader and the user clicked the icon.
        // Show per-domain blacklists.
        tab_helper->ShowSpeedreaderBubble();
      } else if (state == DistillState::kReaderMode) {
        // The page was distilled manually and the user clicked the icon.
        // Three things can happen:
        //   (1) Speedreader is not enabled, so show the bubble about enabling
        //       the feature globally.
        //   (2) Speedreader is enabled and the domain is blacklisted. Show the
        //       Speedreader bubble to let the user remove from the list.
        //   (3) Speedreader is enabled and the domain doesn't match the url
        //       heuristic. Don't show any bubble.
        if (speedreader_enabled) {
          if (!tab_helper->IsEnabledForSite())
            tab_helper->ShowSpeedreaderBubble();
        } else {
          tab_helper->ShowReaderModeBubble();
        }
      } else {
        // The user clicked the reader mode icon to distill a page. If
        // Speedreader is not enabled then automatically show the bubble
        // prompting the user to turn on the feature.
        //
        // TODO(keur): Maybe register a pref to only automatically drop the
        // reader mode bubble once. The user can always get to it manually
        // later.
        tab_helper->SingleShotSpeedreader();
        if (!speedreader_enabled)
          tab_helper->ShowReaderModeBubble();
      }
    }
  }
#endif  // BUILDFLAG(ENABLE_SPEEDREADER)
}

void ShowWalletBubble(Browser* browser) {
#if BUILDFLAG(BRAVE_WALLET_ENABLED) && defined(TOOLKIT_VIEWS)
  static_cast<BraveBrowserView*>(browser->window())->CreateWalletBubble();
#endif
}

void CloseWalletBubble(Browser* browser) {
#if BUILDFLAG(BRAVE_WALLET_ENABLED) && defined(TOOLKIT_VIEWS)
  static_cast<BraveBrowserView*>(browser->window())->CloseWalletBubble();
#endif
}

}  // namespace brave
