/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "brave/components/brave_vpn/brave_vpn_connection_manager_mac.h"

#import <Foundation/Foundation.h>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/mac/bundle_locations.h"
#include "base/mac/foundation_util.h"
#include "base/strings/sys_string_conversions.h"

// Referenced GuardianConnect implementation.
// https://github.com/GuardianFirewall/GuardianConnect
namespace brave_vpn {

namespace {

NEVPNProtocolIKEv2* CreateProtocolConfig(
    const BraveVPNConnectionInfo& info) {
  NSString *hostname = [NSString stringWithUTF8String: info.hostname.c_str()];
  NSString *username = [NSString stringWithUTF8String: info.username.c_str()];
  NSString *password = [NSString stringWithUTF8String: info.password.c_str()];
  NSData* password_data = [password dataUsingEncoding:NSUTF8StringEncoding];

  NEVPNProtocolIKEv2* protocol_config = [[NEVPNProtocolIKEv2 alloc] init];
  protocol_config.serverAddress = hostname;
  protocol_config.serverCertificateCommonName = hostname;
  protocol_config.remoteIdentifier = hostname;
  protocol_config.enablePFS = YES;
  protocol_config.disableMOBIKE = NO;
  protocol_config.disconnectOnSleep = NO;
  protocol_config.authenticationMethod = NEVPNIKEAuthenticationMethodCertificate; // to validate the server-side cert issued by LetsEncrypt
  protocol_config.certificateType = NEVPNIKEv2CertificateTypeECDSA256;
  protocol_config.useExtendedAuthentication = YES;
  protocol_config.username = username;
  protocol_config.passwordReference = password_data;
  protocol_config.deadPeerDetectionRate = NEVPNIKEv2DeadPeerDetectionRateLow; /* increase DPD tolerance from default 10min to 30min */
  protocol_config.useConfigurationAttributeInternalIPSubnet = false;

  [[protocol_config IKESecurityAssociationParameters] setEncryptionAlgorithm:NEVPNIKEv2EncryptionAlgorithmAES256];
  [[protocol_config IKESecurityAssociationParameters] setIntegrityAlgorithm:NEVPNIKEv2IntegrityAlgorithmSHA384];
  [[protocol_config IKESecurityAssociationParameters] setDiffieHellmanGroup:NEVPNIKEv2DiffieHellmanGroup20];
  [[protocol_config IKESecurityAssociationParameters] setLifetimeMinutes:1440]; // 24 hours
  [[protocol_config childSecurityAssociationParameters] setEncryptionAlgorithm:NEVPNIKEv2EncryptionAlgorithmAES256GCM];
  [[protocol_config childSecurityAssociationParameters] setDiffieHellmanGroup:NEVPNIKEv2DiffieHellmanGroup20];
  [[protocol_config childSecurityAssociationParameters] setLifetimeMinutes:480]; // 8 hours

  return protocol_config;
}

}  // namespace

// static
BraveVPNConnectionManager* BraveVPNConnectionManager::GetInstance() {
  static base::NoDestructor<BraveVPNConnectionManagerMac> s_manager;
  return s_manager.get();
}

BraveVPNConnectionManagerMac::BraveVPNConnectionManagerMac() = default;
BraveVPNConnectionManagerMac::~BraveVPNConnectionManagerMac() = default;

BraveVPNConnectionInfo BraveVPNConnectionManagerMac::GetCurrentVPNConnectionInfo() const {
  return info_;
}

void BraveVPNConnectionManagerMac::CreateVPNConnection(
    const BraveVPNConnectionInfo& info) {
  info_ = info;
  CreateAndConnectVPNConnection(false);
}

void BraveVPNConnectionManagerMac::CreateAndConnectVPNConnection(bool connect) {
  NEVPNManager* vpn_manager = [NEVPNManager sharedManager];
  [vpn_manager loadFromPreferencesWithCompletionHandler:^(NSError* load_error) {
    if (load_error) {
      LOG(ERROR) << __func__ << "############## Load error";
      return;
    }

    NEVPNStatus current_status = [[vpn_manager connection] status];
    if (current_status == NEVPNStatusConnected) {
      LOG(ERROR) << __func__ << "############## CreateAndConnectVPNConnection - already connected";
      return;
    }

    auto current_info = GetInstance()->GetCurrentVPNConnectionInfo();
    vpn_manager.enabled = YES;
    vpn_manager.protocolConfiguration = CreateProtocolConfig(current_info);
    vpn_manager.localizedDescription =
        base::SysUTF8ToNSString(current_info.connection_name);

    [vpn_manager saveToPreferencesWithCompletionHandler:^(NSError* saveErr) {
      if (saveErr) {
        NSLog(@"[DEBUG] saveErr = %@", saveErr);
        return;
      } else {
        if (!connect)
          return;

        [vpn_manager loadFromPreferencesWithCompletionHandler:^(NSError* error) {
          NSError* vpnErr;
          [[vpn_manager connection] startVPNTunnelAndReturnError:&vpnErr];
          if (vpnErr != nil) {
            NSLog(@"[DEBUG] vpnErr from connection() = %@", vpnErr);
            return;
          } else {
            NSLog(@"[DEBUG] created successful VPN connection");
            return;
          }
        }];
      }
    }];
  }];
}

void BraveVPNConnectionManagerMac::UpdateVPNConnection(
    const BraveVPNConnectionInfo& info) {}

void BraveVPNConnectionManagerMac::RemoveVPNConnection(
    const BraveVPNConnectionInfo& info) {}

void BraveVPNConnectionManagerMac::Connect(const BraveVPNConnectionInfo& info) {
  info_ = info;
  CreateAndConnectVPNConnection(true);
}

void BraveVPNConnectionManagerMac::Disconnect(
    const BraveVPNConnectionInfo& info) {
  NEVPNManager* vpn_manager = [NEVPNManager sharedManager];
  [vpn_manager loadFromPreferencesWithCompletionHandler:^(NSError* load_error) {
    if (load_error) {
      LOG(ERROR) << __func__ << "############## Load error";
      return;
    }

    NEVPNStatus current_status = [[vpn_manager connection] status];
    if (current_status != NEVPNStatusConnected) {
      LOG(ERROR) << __func__ << "############## Disconnect - not connected";
      return;
    }

    [vpn_manager setEnabled:NO];
    [vpn_manager setOnDemandEnabled:NO];
    [vpn_manager saveToPreferencesWithCompletionHandler:^(NSError* saveErr) {
      if (saveErr) {
        NSLog(@"[DEBUG][disconnectVPN] error saving update for firewall config = "
              @"%@",
              saveErr);
      }
      [[vpn_manager connection] stopVPNTunnel];
    }];
  }];
}

}  // namespace brave_vpn
