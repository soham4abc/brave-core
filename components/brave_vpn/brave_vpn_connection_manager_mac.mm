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

NSData* GetPasswordRefForAccount(NSString* accountKeyStr) {
  NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
  CFTypeRef copyResult = NULL;
  NSDictionary *query = @{
      (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
      (__bridge id)kSecAttrService : bundleId,
      (__bridge id)kSecAttrAccount : accountKeyStr,
      (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
      (__bridge id)kSecReturnPersistentRef : (__bridge id)kCFBooleanTrue,
  };
  OSStatus results = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&copyResult);
  if (results != errSecSuccess) {
      NSLog(@"[GRDKeychain] error obtaining password ref: %ld", (long)results);
  }

  return (__bridge NSData *)copyResult;
}

OSStatus RemoveKeychanItemForAccount(NSString* accountKeyStr) {
  NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
  NSDictionary *query = @{
                          (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
                          (__bridge id)kSecAttrService : bundleId,
                          (__bridge id)kSecAttrAccount : accountKeyStr,
                          (__bridge id)kSecReturnPersistentRef : (__bridge id)kCFBooleanTrue,
                          };
  OSStatus result = SecItemDelete((__bridge CFDictionaryRef)query);
  if (result != errSecSuccess && result != errSecItemNotFound) {
      if (@available(iOS 11.3, *)) {
          NSString *errMessage = CFBridgingRelease(SecCopyErrorMessageString(result, nil));
          NSLog(@"%@", errMessage);
      }
      NSLog(@"[GRDKeychain] error deleting password entry %@ with status: %ld", query, (long)result);
  }

  return result;
}

OSStatus StorePassword(NSString* passwordStr, NSString* accountKeyStr) {
  if (passwordStr == nil){
      return errSecParam; //technically it IS a parameter issue, so this makes sense.
  }
  CFTypeRef result = NULL;
  NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
  NSData *valueData = [passwordStr dataUsingEncoding:NSUTF8StringEncoding];
  NSDictionary *secItem = @{
      (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
      (__bridge id)kSecAttrService : bundleId,
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
      (__bridge id)kSecAttrAccessible : (__bridge id)kSecAttrAccessibleAlways,
#pragma clang diagnostic pop
      (__bridge id)kSecAttrSynchronizable : (__bridge id)kCFBooleanFalse,
      (__bridge id)kSecAttrAccount : accountKeyStr,
      (__bridge id)kSecValueData : valueData,
  };
  OSStatus status = SecItemAdd((__bridge CFDictionaryRef)secItem, &result);
  if (status == errSecSuccess) {
      //NSLog(@"[GRDKeychain] successfully stored password %@ for %@", passwordStr, accountKeyStr);
  } else {
      if (status == errSecDuplicateItem){
          NSLog(@"[GRDKeychain] duplicate item exists for %@ removing and re-adding.", accountKeyStr);
          RemoveKeychanItemForAccount(accountKeyStr);
          return StorePassword(passwordStr, accountKeyStr);
      }
      NSLog(@"[GRDKeychain] error storing password (%@): %ld", passwordStr, (long)status);
  }
  return status;
}

NEVPNProtocolIKEv2* CreateProtocolConfig(
    const BraveVPNConnectionInfo& info) {
  NSString *hostname = [NSString stringWithUTF8String: info.hostname.c_str()];
  NSString *username = [NSString stringWithUTF8String: info.username.c_str()];

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
  protocol_config.passwordReference = GetPasswordRefForAccount(@"BraveVPNKey");
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
  StorePassword([NSString stringWithUTF8String: info.password.c_str()], @"BraveVPNKey");
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
  StorePassword([NSString stringWithUTF8String: info.hostname.c_str()], @"BraveVPNKey");
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
