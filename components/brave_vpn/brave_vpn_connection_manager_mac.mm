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

const NSString* kBraveVPNKey = @"BraveVPNKey";

NSData* GetPasswordRefForAccount(const NSString* account_key) {
  NSString* bundle_id = [[NSBundle mainBundle] bundleIdentifier];
  CFTypeRef copy_result = NULL;
  NSDictionary* query = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : bundle_id,
    (__bridge id)kSecAttrAccount : account_key,
    (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
    (__bridge id)kSecReturnPersistentRef : (__bridge id)kCFBooleanTrue,
  };
  OSStatus results = SecItemCopyMatching((__bridge CFDictionaryRef)query,
                                         (CFTypeRef*)&copy_result);
  if (results != errSecSuccess)
    LOG(ERROR) << "Error: obtaining password ref(status:" << results << ")";
  return (__bridge NSData*)copy_result;
}

OSStatus RemoveKeychanItemForAccount(const NSString* account_key) {
  NSString* bundle_id = [[NSBundle mainBundle] bundleIdentifier];
  NSDictionary* query = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : bundle_id,
    (__bridge id)kSecAttrAccount : account_key,
    (__bridge id)kSecReturnPersistentRef : (__bridge id)kCFBooleanTrue,
  };
  OSStatus result = SecItemDelete((__bridge CFDictionaryRef)query);
  if (result != errSecSuccess && result != errSecItemNotFound)
    LOG(ERROR) << "Error: deleting password entry(status:" << result << ")";
  return result;
}

OSStatus StorePassword(const NSString* password, const NSString* account_key) {
  if (password == nil) {
    LOG(ERROR) << "Error: password is empty";
    return errSecParam;
  }

  CFTypeRef result = NULL;
  NSString* bundle_id = [[NSBundle mainBundle] bundleIdentifier];
  NSData* password_data = [password dataUsingEncoding:NSUTF8StringEncoding];
  NSDictionary* sec_item = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : bundle_id,
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    (__bridge id)kSecAttrAccessible : (__bridge id)kSecAttrAccessibleAlways,
#pragma clang diagnostic pop
    (__bridge id)kSecAttrSynchronizable : (__bridge id)kCFBooleanFalse,
    (__bridge id)kSecAttrAccount : account_key,
    (__bridge id)kSecValueData : password_data,
  };
  OSStatus status = SecItemAdd((__bridge CFDictionaryRef)sec_item, &result);
  if (status != errSecSuccess) {
    if (status == errSecDuplicateItem) {
      VLOG(2) << "There is duplicates exists. removing and re-adding.";
      RemoveKeychanItemForAccount(account_key);
      return StorePassword(password, account_key);
    }
    LOG(ERROR) << "Error: storing password";
  }

  return status;
}

NEVPNProtocolIKEv2* CreateProtocolConfig(const BraveVPNConnectionInfo& info) {
  NSString* hostname = [NSString stringWithUTF8String:info.hostname.c_str()];
  NSString* username = [NSString stringWithUTF8String:info.username.c_str()];

  NEVPNProtocolIKEv2* protocol_config = [[NEVPNProtocolIKEv2 alloc] init];
  protocol_config.serverAddress = hostname;
  protocol_config.serverCertificateCommonName = hostname;
  protocol_config.remoteIdentifier = hostname;
  protocol_config.enablePFS = YES;
  protocol_config.disableMOBIKE = NO;
  protocol_config.disconnectOnSleep = NO;
  protocol_config.authenticationMethod =
      NEVPNIKEAuthenticationMethodCertificate;  // to validate the server-side
                                                // cert issued by LetsEncrypt
  protocol_config.certificateType = NEVPNIKEv2CertificateTypeECDSA256;
  protocol_config.useExtendedAuthentication = YES;
  protocol_config.username = username;
  protocol_config.passwordReference = GetPasswordRefForAccount(kBraveVPNKey);
  protocol_config.deadPeerDetectionRate =
      NEVPNIKEv2DeadPeerDetectionRateLow; /* increase DPD tolerance from default
                                             10min to 30min */
  protocol_config.useConfigurationAttributeInternalIPSubnet = false;

  [[protocol_config IKESecurityAssociationParameters]
      setEncryptionAlgorithm:NEVPNIKEv2EncryptionAlgorithmAES256];
  [[protocol_config IKESecurityAssociationParameters]
      setIntegrityAlgorithm:NEVPNIKEv2IntegrityAlgorithmSHA384];
  [[protocol_config IKESecurityAssociationParameters]
      setDiffieHellmanGroup:NEVPNIKEv2DiffieHellmanGroup20];
  [[protocol_config IKESecurityAssociationParameters]
      setLifetimeMinutes:1440];  // 24 hours
  [[protocol_config childSecurityAssociationParameters]
      setEncryptionAlgorithm:NEVPNIKEv2EncryptionAlgorithmAES256GCM];
  [[protocol_config childSecurityAssociationParameters]
      setDiffieHellmanGroup:NEVPNIKEv2DiffieHellmanGroup20];
  [[protocol_config childSecurityAssociationParameters]
      setLifetimeMinutes:480];  // 8 hours

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

BraveVPNConnectionInfo
BraveVPNConnectionManagerMac::GetCurrentVPNConnectionInfo() const {
  return info_;
}

void BraveVPNConnectionManagerMac::CreateVPNConnection(
    const BraveVPNConnectionInfo& info) {
  CreateAndConnectVPNConnection(false /*connect*/);
}

void BraveVPNConnectionManagerMac::CreateAndConnectVPNConnection(bool connect) {
  if (StorePassword([NSString stringWithUTF8String:info_.password.c_str()],
                    kBraveVPNKey) != errSecSuccess)
    return;

  NEVPNManager* vpn_manager = [NEVPNManager sharedManager];
  [vpn_manager loadFromPreferencesWithCompletionHandler:^(NSError* error) {
    if (error) {
      LOG(ERROR) << "CreateAndConnectVPNConnection - loadFromPrefs error: "
                 << base::SysNSStringToUTF8([error localizedDescription]);
      return;
    }

    NEVPNStatus current_status = [[vpn_manager connection] status];
    // Early return if already connected.
    if (current_status == NEVPNStatusConnected) {
      VLOG(2) << "CreateAndConnectVPNConnection - Already connected";
      return;
    }

    auto current_info = GetInstance()->GetCurrentVPNConnectionInfo();
    vpn_manager.enabled = YES;
    vpn_manager.protocolConfiguration = CreateProtocolConfig(current_info);
    vpn_manager.localizedDescription =
        base::SysUTF8ToNSString(current_info.connection_name);

    [vpn_manager saveToPreferencesWithCompletionHandler:^(NSError* error) {
      if (error) {
        LOG(ERROR) << "CreateAndConnectVPNConnection - saveToPrefs error: "
                   << base::SysNSStringToUTF8([error localizedDescription]);
        return;
      } else {
        VLOG(2) << "CreateAndConnectVPNConnection - saveToPrefs success";

        if (!connect)
          return;

        [vpn_manager loadFromPreferencesWithCompletionHandler:^(
                         NSError* error) {
          NSError* start_error;
          [[vpn_manager connection] startVPNTunnelAndReturnError:&start_error];
          if (start_error != nil) {
            LOG(ERROR)
                << "CreateAndConnectVPNConnection - startVPNTunnel error: "
                << base::SysNSStringToUTF8([start_error localizedDescription]);
            return;
          }
          VLOG(2) << "Successfully connected";
        }];
      }
    }];
  }];
}

void BraveVPNConnectionManagerMac::UpdateVPNConnection(
    const BraveVPNConnectionInfo& info) {}

void BraveVPNConnectionManagerMac::RemoveVPNConnection(
    const BraveVPNConnectionInfo& info) {
  DisconnectAndDeleteCreds(true);
}

void BraveVPNConnectionManagerMac::Connect(const BraveVPNConnectionInfo& info) {
  info_ = info;
  CreateAndConnectVPNConnection(true /* connect */);
}

void BraveVPNConnectionManagerMac::DisconnectAndDeleteCreds(bool delete_creds) {
  NEVPNManager* vpn_manager = [NEVPNManager sharedManager];
  [vpn_manager loadFromPreferencesWithCompletionHandler:^(NSError* error) {
    if (error) {
      LOG(ERROR) << "Disconnect: loadFromPrefs: "
                 << base::SysNSStringToUTF8([error localizedDescription]);
      return;
    }

    NEVPNStatus current_status = [[vpn_manager connection] status];
    if (current_status != NEVPNStatusConnected) {
      VLOG(2) << "Disconnect: Not connected";

      if (delete_creds)
        RemoveKeychanItemForAccount(kBraveVPNKey);

      return;
    }

    [vpn_manager setEnabled:NO];
    [vpn_manager setOnDemandEnabled:NO];
    [vpn_manager saveToPreferencesWithCompletionHandler:^(NSError* error) {
      if (error) {
        LOG(ERROR) << "Disconnect: saveToPrefs: "
                   << base::SysNSStringToUTF8([error localizedDescription]);
      }
      [[vpn_manager connection] stopVPNTunnel];
      if (delete_creds)
        RemoveKeychanItemForAccount(kBraveVPNKey);
    }];
  }];
}

void BraveVPNConnectionManagerMac::Disconnect(
    const BraveVPNConnectionInfo& info) {
  DisconnectAndDeleteCreds(false);
}

}  // namespace brave_vpn
