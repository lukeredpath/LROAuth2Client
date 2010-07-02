//
//  LROAuth2AccessToken.m
//  LROAuth2Client
//
//  Created by Luke Redpath on 14/05/2010.
//  Copyright 2010 LJR Software Limited. All rights reserved.
//

#import "LROAuth2AccessToken.h"


@implementation LROAuth2AccessToken

@dynamic accessToken;
@dynamic refreshToken;
@synthesize expiresAt;

- (id)initWithAuthorizationResponse:(NSDictionary *)_data;
{
  if (self = [super init]) {
    authResponseData = [_data copy];
    
    NSTimeInterval expiresIn = (NSTimeInterval)[[authResponseData valueForKey:@"expires_in"] intValue];
    expiresAt = [[NSDate alloc] initWithTimeIntervalSinceNow:expiresIn];
  }
  return self;
}

- (void)dealloc;
{
  [expiresAt release];
  [authResponseData release];
  [super dealloc];
}

- (NSString *)description;
{
  return [NSString stringWithFormat:@"<LROAuth2AccessToken token:%@ expiresAt:%@>", self.accessToken, self.expiresAt];
}

- (BOOL)hasExpired;
{
  return ([[NSDate date] earlierDate:expiresAt] == expiresAt);
}

- (void)refreshFromAuthorizationResponse:(NSDictionary *)_data;
{
  NSMutableDictionary *_tokenData = [authResponseData mutableCopy];
  [_tokenData setValue:[_data valueForKey:@"access_token"] forKey:@"access_token"];
  
  NSTimeInterval expiresIn = (NSTimeInterval)[[authResponseData valueForKey:@"expires_in"] intValue];
  expiresAt = [[NSDate alloc] initWithTimeIntervalSinceNow:expiresIn];
  
  [authResponseData release];
  authResponseData = [_tokenData copy];
  [_tokenData release];
}

#pragma mark -
#pragma mark Dynamic accessors

- (NSString *)accessToken;
{
  return [authResponseData valueForKey:@"access_token"];
}

- (NSString *)refreshToken;
{
  return [authResponseData valueForKey:@"refresh_token"];
}

#pragma mark -
#pragma mark NSCoding

- (void)encodeWithCoder:(NSCoder *)aCoder
{
  [aCoder encodeObject:authResponseData forKey:@"data"];
  [aCoder encodeObject:expiresAt forKey:@"expiresAt"];
}

- (id)initWithCoder:(NSCoder *)aDecoder
{
  if (self = [super init]) {
    authResponseData = [[aDecoder decodeObjectForKey:@"data"] copy];
    expiresAt = [[aDecoder decodeObjectForKey:@"expiresAt"] retain];
  }
  return self;
}

@end
