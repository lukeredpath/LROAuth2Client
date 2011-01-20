//
//  LROAuth2AccessToken.m
//  LROAuth2Client
//
//  Created by Luke Redpath on 14/05/2010.
//  Copyright 2010 LJR Software Limited. All rights reserved.
//

#import "LROAuth2AccessToken.h"

@interface LROAuth2AccessToken ()
@property (nonatomic, copy) NSDictionary *authResponseData;
- (void)extractExpiresAtFromResponse;
@end

#pragma mark -

@implementation LROAuth2AccessToken

@dynamic accessToken;
@dynamic refreshToken;
@synthesize authResponseData;
@synthesize expiresAt;

- (id)initWithAuthorizationResponse:(NSDictionary *)data;
{
  if (self = [super init]) {
    authResponseData = [data copy];
    [self extractExpiresAtFromResponse];    
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

- (void)refreshFromAuthorizationResponse:(NSDictionary *)data;
{
  NSMutableDictionary *tokenData = [self.authResponseData mutableCopy];

  [tokenData setObject:[data valueForKey:@"access_token"] forKey:@"access_token"];
  [tokenData setObject:[data objectForKey:@"expires_in"]  forKey:@"expires_in"];
  
  [self setAuthResponseData:tokenData];
  [tokenData release];
  [self extractExpiresAtFromResponse];
}

- (void)extractExpiresAtFromResponse
{
  NSTimeInterval expiresIn = (NSTimeInterval)[[self.authResponseData objectForKey:@"expires_in"] intValue];
  expiresAt = [[NSDate alloc] initWithTimeIntervalSinceNow:expiresIn];
}

#pragma mark -
#pragma mark Dynamic accessors

- (NSString *)accessToken;
{
  return [authResponseData objectForKey:@"access_token"];
}

- (NSString *)refreshToken;
{
  return [authResponseData objectForKey:@"refresh_token"];
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
