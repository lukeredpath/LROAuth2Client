//
//  LROAuth2ClientDelegate.h
//  LROAuth2Client
//
//  Created by Luke Redpath on 14/05/2010.
//  Copyright 2010 LJR Software Limited. All rights reserved.
//

#import <UIKit/UIKit.h>

@class LROAuth2Client;

@protocol LROAuth2ClientDelegate <UIWebViewDelegate>

@required
- (void)oauthClientDidReceiveAccessToken:(LROAuth2Client *)client;
- (void)oauthClientDidRefreshAccessToken:(LROAuth2Client *)client;

@optional
- (void)oauthClientDidReceiveAccessCode:(LROAuth2Client *)client;
- (void)oauthClientDidCancel:(LROAuth2Client *)client;

@end
