/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_IOS_BROWSER_API_LEDGER_BRAVE_LEDGER_H_
#define BRAVE_IOS_BROWSER_API_LEDGER_BRAVE_LEDGER_H_

#import <Foundation/Foundation.h>
#import "ledger.mojom.objc.h"

@class BraveLedgerObserver, PromotionSolution, RewardsNotification;

NS_ASSUME_NONNULL_BEGIN

typedef NSString* ExternalWalletType NS_SWIFT_NAME(ExternalWalletType)
    NS_STRING_ENUM;

static ExternalWalletType const ExternalWalletTypeUphold = @"uphold";
static ExternalWalletType const ExternalWalletTypeAnonymous = @"anonymous";
static ExternalWalletType const ExternalWalletTypeUnblindedTokens = @"blinded";

typedef void (^LedgerFaviconFetcher)(
    NSURL* pageURL,
    void (^completion)(NSURL* _Nullable faviconURL));

/// The error domain for ledger related errors
OBJC_EXPORT NSString* const BraveLedgerErrorDomain;

OBJC_EXPORT NSNotificationName const BraveLedgerNotificationAdded
    NS_SWIFT_NAME(BraveLedger.notificationAdded);

typedef NSString* BraveGeneralLedgerNotificationID NS_STRING_ENUM;
OBJC_EXPORT BraveGeneralLedgerNotificationID const
    BraveGeneralLedgerNotificationIDWalletNowVerified;
OBJC_EXPORT BraveGeneralLedgerNotificationID const
    BraveGeneralLedgerNotificationIDWalletDisconnected;

OBJC_EXPORT
@interface BraveLedger : NSObject

@property(nonatomic, copy, nullable) LedgerFaviconFetcher faviconFetcher;

/// Create a brave ledger that will read and write its state to the given path
- (instancetype)initWithStateStoragePath:(NSString*)path;

- (instancetype)init NS_UNAVAILABLE;

#pragma mark - Initialization

/// Initialize the ledger service.
///
/// This must be called before other methods on this class are called
- (void)initializeLedgerService:(nullable void (^)())completion;

/// Whether or not the ledger service has been initialized already
@property(nonatomic, readonly, getter=isInitialized) BOOL initialized;

/// Whether or not the ledger service is currently initializing
@property(nonatomic, readonly, getter=isInitializing) BOOL initializing;

/// The result when initializing the ledger service. Should be
/// `BATResultLedgerOk` if `initialized` is `true`
///
/// If this is not `BATResultLedgerOk`, rewards is not usable for the user
@property(nonatomic, readonly) BATResult initializationResult;

/// Whether or not data migration failed when initializing and the user should
/// be notified.
@property(nonatomic, readonly) BOOL dataMigrationFailed;

#pragma mark - Observers

/// Add an interface to the list of observers
///
/// Observers are stored weakly and do not necessarily need to be removed
- (void)addObserver:(BraveLedgerObserver*)observer;

/// Removes an interface from the list of observers
- (void)removeObserver:(BraveLedgerObserver*)observer;

#pragma mark - Global

/// Whether or not to use staging servers. Defaults to false
@property(nonatomic, class, getter=isDebug) BOOL debug;
/// The environment that ledger is communicating with
@property(nonatomic, class) BATEnvironment environment;
/// Marks if this is being ran in a test environment. Defaults to false
@property(nonatomic, class, getter=isTesting) BOOL testing;
/// Number of minutes between reconciles override. Defaults to 0 (no override)
@property(nonatomic, class) int reconcileInterval;
/// Whether or not to use short contribution retries. Defaults to false
@property(nonatomic, class) BOOL useShortRetries;

#pragma mark - Wallet

/// Whether or not the wallet is currently in the process of being created
@property(nonatomic, readonly, getter=isInitializingWallet)
    BOOL initializingWallet;

/// Creates a cryptocurrency wallet
- (void)createWallet:(nullable void (^)(NSError* _Nullable error))completion;

/// Get the brave wallet's payment ID and seed for ads confirmations
- (void)currentWalletInfo:
    (void (^)(BATBraveWallet* _Nullable wallet))completion;

/// Get parameters served from the server
- (void)getRewardsParameters:
    (nullable void (^)(BATRewardsParameters* _Nullable))completion;

/// The parameters send from the server
@property(nonatomic, readonly, nullable)
    BATRewardsParameters* rewardsParameters;

/// Fetch details about the users wallet (if they have one) and assigns it to
/// `balance`
- (void)fetchBalance:(nullable void (^)(BATBalance* _Nullable))completion;

/// The users current wallet balance and related info
@property(nonatomic, readonly, nullable) BATBalance* balance;

/// The wallet's passphrase. nil if the wallet has not been created yet
@property(nonatomic, readonly, nullable) NSString* walletPassphrase;

/// Recover the users wallet using their passphrase
- (void)recoverWalletUsingPassphrase:(NSString*)passphrase
                          completion:
                              (nullable void (^)(NSError* _Nullable))completion;

/// Retrieves the users most up to date balance to determin whether or not the
/// wallet has a sufficient balance to complete a reconcile
- (void)hasSufficientBalanceToReconcile:(void (^)(BOOL sufficient))completion;

/// Returns reserved amount of pending contributions to publishers.
- (void)pendingContributionsTotal:(void (^)(double amount))completion
    NS_SWIFT_NAME(pendingContributionsTotal(completion:));

/// Links a desktop brave wallet given some payment ID
- (void)linkBraveWalletToPaymentId:(NSString*)paymentId
                        completion:(void (^)(BATResult result,
                                             NSString* drainID))completion
    NS_SWIFT_NAME(linkBraveWallet(paymentId:completion:));

/// Obtain a drain status given some drain ID previously obtained from
/// `linkBraveWalletToPaymentId:completion:`
- (void)drainStatusForDrainId:(NSString *)drainId
                   completion:(void (^)(BATResult result,
                                        BATDrainStatus status))completion
    NS_SWIFT_NAME(drainStatus(for:completion:));

/// Get the amount of BAT that is transferrable via wallet linking
- (void)transferrableAmount:(void (^)(double amount))completion;

#pragma mark - User Wallets

/// The last updated external wallet if a user has hooked one up
@property(nonatomic, readonly, nullable) BATExternalWallet* upholdWallet;

- (void)fetchUpholdWallet:
    (nullable void (^)(BATExternalWallet* _Nullable wallet))completion;

- (void)disconnectWalletOfType:(ExternalWalletType)walletType
                    completion:(nullable void (^)(BATResult result))completion;

- (void)authorizeExternalWalletOfType:(ExternalWalletType)walletType
                           queryItems:
                               (NSDictionary<NSString*, NSString*>*)queryItems
                           completion:(void (^)(BATResult result,
                                                NSURL* _Nullable redirectURL))
                                          completion;

#pragma mark - Publishers

@property(nonatomic, readonly, getter=isLoadingPublisherList)
    BOOL loadingPublisherList;

/// Get publisher info & its activity based on its publisher key
///
/// This key is _not_ always the URL's host. Use `publisherActivityFromURL`
/// instead when obtaining a publisher given a URL
///
/// @note `completion` callback is called synchronously
- (void)listActivityInfoFromStart:(unsigned int)start
                            limit:(unsigned int)limit
                           filter:(BATActivityInfoFilter*)filter
                       completion:
                           (void (^)(NSArray<BATPublisherInfo*>*))completion;

/// Start a fetch to get a publishers activity information given a URL
///
/// Use `BraveLedgerObserver` to retrieve a panel publisher if one is found
- (void)fetchPublisherActivityFromURL:(NSURL*)URL
                           faviconURL:(nullable NSURL*)faviconURL
                        publisherBlob:(nullable NSString*)publisherBlob
                                tabId:(uint64_t)tabId;

/// Update a publishers exclusion state
- (void)updatePublisherExclusionState:(NSString*)publisherId
                                state:(BATPublisherExclude)state
    NS_SWIFT_NAME(updatePublisherExclusionState(withId:state:));

/// Restore all sites which had been previously excluded
- (void)restoreAllExcludedPublishers;

/// Get the publisher banner given some publisher key
///
/// This key is _not_ always the URL's host. Use `publisherActivityFromURL`
/// instead when obtaining a publisher given a URL
///
/// @note `completion` callback is called synchronously
- (void)publisherBannerForId:(NSString*)publisherId
                  completion:(void (^)(BATPublisherBanner* _Nullable banner))
                                 completion;

/// Refresh a publishers verification status
- (void)refreshPublisherWithId:(NSString*)publisherId
                    completion:(void (^)(BATPublisherStatus status))completion;

#pragma mark - SKUs

- (void)processSKUItems:(NSArray<BATSKUOrderItem*>*)items
             completion:
                 (void (^)(BATResult result, NSString* orderID))completion;

#pragma mark - Tips

/// Get a list of publishers who the user has recurring tips on
///
/// @note `completion` callback is called synchronously
- (void)listRecurringTips:(void (^)(NSArray<BATPublisherInfo*>*))completion;

- (void)addRecurringTipToPublisherWithId:(NSString*)publisherId
                                  amount:(double)amount
                              completion:(void (^)(BOOL success))completion
    NS_SWIFT_NAME(addRecurringTip(publisherId:amount:completion:));

- (void)removeRecurringTipForPublisherWithId:(NSString*)publisherId
    NS_SWIFT_NAME(removeRecurringTip(publisherId:));

/// Get a list of publishers who the user has made direct tips too
///
/// @note `completion` callback is called synchronously
- (void)listOneTimeTips:(void (^)(NSArray<BATPublisherInfo*>*))completion;

- (void)tipPublisherDirectly:(BATPublisherInfo*)publisher
                      amount:(double)amount
                    currency:(NSString*)currency
                  completion:(void (^)(BATResult result))completion;

#pragma mark - Promotions

@property(nonatomic, readonly) NSArray<BATPromotion*>* pendingPromotions;

@property(nonatomic, readonly) NSArray<BATPromotion*>* finishedPromotions;

/// Updates `pendingPromotions` and `finishedPromotions` based on the database
- (void)updatePendingAndFinishedPromotions:
    (nullable void (^)(bool shouldReconcileAds))completion;

- (void)fetchPromotions:(nullable void (^)(NSArray<BATPromotion*>* grants,
                                           bool shouldReconcileAds))completion;

- (void)claimPromotion:(NSString*)promotionId
             publicKey:(NSString*)deviceCheckPublicKey
            completion:(void (^)(BATResult result,
                                 NSString* _Nonnull nonce))completion;

- (void)attestPromotion:(NSString*)promotionId
               solution:(PromotionSolution*)solution
             completion:(nullable void (^)(BATResult result,
                                           BATPromotion* _Nullable promotion))
                            completion;

#pragma mark - Pending Contributions

- (void)pendingContributions:
    (void (^)(NSArray<BATPendingContributionInfo*>* publishers))completion;

- (void)removePendingContribution:(BATPendingContributionInfo*)info
                       completion:(void (^)(BATResult result))completion;

- (void)removeAllPendingContributions:(void (^)(BATResult result))completion;

#pragma mark - History

- (void)balanceReportForMonth:(BATActivityMonth)month
                         year:(int)year
                   completion:(void (^)(BATBalanceReportInfo* _Nullable info))
                                  completion;

@property(nonatomic, readonly)
    BATAutoContributeProperties* autoContributeProperties;

#pragma mark - Misc

+ (bool)isMediaURL:(NSURL*)url
     firstPartyURL:(nullable NSURL*)firstPartyURL
       referrerURL:(nullable NSURL*)referrerURL;

- (void)rewardsInternalInfo:
    (void(NS_NOESCAPE ^)(BATRewardsInternalsInfo* _Nullable info))completion;

- (void)allContributions:
    (void (^)(NSArray<BATContributionInfo*>* contributions))completion;

@property(nonatomic, readonly, copy) NSString* rewardsDatabasePath;

#pragma mark - Reporting

@property(nonatomic) UInt32 selectedTabId;

/// Report that a page has loaded in the current browser tab, and the HTML is
/// available for analysis
- (void)reportLoadedPageWithURL:(NSURL*)url
                          tabId:(UInt32)tabId
    NS_SWIFT_NAME(reportLoadedPage(url:tabId:));

- (void)reportXHRLoad:(NSURL*)url
                tabId:(UInt32)tabId
        firstPartyURL:(NSURL*)firstPartyURL
          referrerURL:(nullable NSURL*)referrerURL;

- (void)reportPostData:(NSData*)postData
                   url:(NSURL*)url
                 tabId:(UInt32)tabId
         firstPartyURL:(NSURL*)firstPartyURL
           referrerURL:(nullable NSURL*)referrerURL;

/// Report that a tab with a given id navigated or was closed by the user
- (void)reportTabNavigationOrClosedWithTabId:(UInt32)tabId
    NS_SWIFT_NAME(reportTabNavigationOrClosed(tabId:));

#pragma mark - Preferences

/// The number of seconds before a publisher is added.
@property(nonatomic, assign) int minimumVisitDuration;
/// The minimum number of visits before a publisher is added
@property(nonatomic, assign) int minimumNumberOfVisits;
/// Whether or not to allow auto contributions to unverified publishers
@property(nonatomic, assign) BOOL allowUnverifiedPublishers;
/// Whether or not to allow auto contributions to videos
@property(nonatomic, assign) BOOL allowVideoContributions;
/// The auto-contribute amount
@property(nonatomic, assign) double contributionAmount;
/// Whether or not the user will automatically contribute
@property(nonatomic, assign, getter=isAutoContributeEnabled)
    BOOL autoContributeEnabled;
/// A custom user agent for network operations on ledger
@property(nonatomic, copy, nullable) NSString* customUserAgent;

#pragma mark - Notifications

/// Gets a list of notifications awaiting user interaction
@property(nonatomic, readonly) NSArray<RewardsNotification*>* notifications;

/// Clear a given notification
- (void)clearNotification:(RewardsNotification*)notification;

/// Clear all the notifications
- (void)clearAllNotifications;

@end

NS_ASSUME_NONNULL_END

#endif  // BRAVE_IOS_BROWSER_API_LEDGER_BRAVE_LEDGER_H_
