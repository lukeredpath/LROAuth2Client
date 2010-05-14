//
//  LROAuth2Client.m
//  Firelight
//
//  Created by Luke Redpath on 14/05/2010.
//  Copyright 2010 LJR Software Limited. All rights reserved.
//

#import "LROAuth2Client.h"
#import "ASIHTTPRequest.h"
#import "NSURL+QueryInspector.h"
#import "CJSONDeserializer.h"
#import "LROAuth2AccessToken.h"

#pragma mark -

@implementation LROAuth2Client

@synthesize clientID;
@synthesize clientSecret;
@synthesize redirectURL;
@synthesize verificationURL;
@synthesize delegate;
@synthesize accessToken;
@synthesize debug;

- (id)initWithClientID:(NSString *)_clientID 
                secret:(NSString *)_secret 
           redirectURL:(NSURL *)url;
{
  if (self = [super init]) {
    clientID = [_clientID copy];
    clientSecret = [_secret copy];
    redirectURL = [url copy];
    debug = NO;
  }
  return self;
}

- (void)dealloc;
{
  [accessToken release];
  [clientID release];
  [clientSecret release];
  [verificationURL release];
  [redirectURL release];
  [super dealloc];
}

#pragma mark -
#pragma mark Authorization

- (NSURLRequest *)requestForAuthorizationWithURL:(NSURL *)baseURL;
{
  NSString *queryString = [NSString stringWithFormat:
                           @"type=web_server&client_id=%@&redirect_uri=%@", 
                           clientID, redirectURL];
  
  NSURL *fullURL = [NSURL URLWithString:[[baseURL absoluteString] stringByAppendingFormat:@"?%@", queryString]];
  NSMutableURLRequest *authRequest = [NSMutableURLRequest requestWithURL:fullURL];
  [authRequest setHTTPMethod:@"GET"];

  return [[authRequest copy] autorelease];
}

- (void)verifyAuthorizationWithAccessCode:(NSString *)accessCode;
{
  @synchronized(self) {
    if (isVerifying) return; // don't allow more than one auth request
    
    isVerifying = YES;
    
    NSString *postBody = [NSString stringWithFormat:
                             @"type=web_server&client_id=%@&redirect_uri=%@&client_secret=%@&code=%@", 
                             clientID, redirectURL, clientSecret, accessCode];
    
    ASIHTTPRequest *request = [ASIHTTPRequest requestWithURL:self.verificationURL];
    [request setRequestMethod:@"POST"];
    [request appendPostData:[postBody dataUsingEncoding:NSUTF8StringEncoding]];
    [request setDelegate:self];
    [request startAsynchronous];
  }
}

#pragma mark -
#pragma mark Authorization data accessors

#pragma mark -
#pragma mark ASIHTTPRequestDelegate methods

- (void)requestStarted:(ASIHTTPRequest *)request
{
  if (self.debug) {
    NSLog(@"[oauth] starting verification request");
  }
}

- (void)requestFinished:(ASIHTTPRequest *)request
{
  if (self.debug) {
    NSLog(@"[oauth] finished verification request");
  }
  isVerifying = NO;
}

- (void)request:(ASIHTTPRequest *)request didReceiveData:(NSData *)data
{
  NSError *parseError = nil;
  NSDictionary *authorizationData = [[CJSONDeserializer deserializer] deserializeAsDictionary:data error:&parseError];
  
  accessToken = [[LROAuth2AccessToken alloc] initWithAuthorizationResponse:authorizationData];
  
  if (parseError == nil) {
    if ([self.delegate respondsToSelector:@selector(oauthClientDidReceiveAccessToken:)]) {
      [self.delegate oauthClientDidReceiveAccessToken:self];
    } 
  }
}

@end

@implementation LROAuth2Client (UIWebViewIntegration)

- (void)authorizeUsingWebView:(UIWebView *)webView url:(NSURL *)authURL;
{
  [webView setDelegate:self];
  [webView loadRequest:[self requestForAuthorizationWithURL:authURL]];
}

- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType
{
  return YES;
}

- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error
{
  NSString *failingURLString = [error.userInfo objectForKey:NSErrorFailingURLStringKey];
  
  if ([failingURLString hasPrefix:@"spark://"]) {
    [webView stopLoading];
    
    NSURL *callbackURL = [NSURL URLWithString:failingURLString];
    NSString *accessCode = [[callbackURL queryDictionary] valueForKey:@"code"];
    
    if ([self.delegate respondsToSelector:@selector(oauthClientDidReceiveAccessCode:)]) {
      [self.delegate oauthClientDidReceiveAccessCode:self];
    }
    [self verifyAuthorizationWithAccessCode:accessCode];
  }
}

@end
