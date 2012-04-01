//
//  LROAuth2AccessToken.h
//  LROAuth2Client
//
//  Created by Luke Redpath on 14/05/2010.
//  Copyright 2010 LJR Software Limited. All rights reserved.
//

#import <UIKit/UIKit.h>


@interface LROAuth2AccessToken : UIView <NSCoding> {
  NSDictionary *authResponseData;
  NSDate *expiresAt;
}
@property (unsafe_unretained, nonatomic, readonly) NSString *accessToken;
@property (unsafe_unretained, nonatomic, readonly) NSString *refreshToken;
@property (nonatomic, readonly) NSDate *expiresAt;

- (id)initWithAuthorizationResponse:(NSDictionary *)_data;
- (void)refreshFromAuthorizationResponse:(NSDictionary *)_data;
- (BOOL)hasExpired;
@end
