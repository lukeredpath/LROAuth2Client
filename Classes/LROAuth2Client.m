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
#import "NSDictionary+QueryString.h"

#pragma mark -

@implementation LROAuth2Client

@synthesize clientID;
@synthesize clientSecret;
@synthesize redirectURL;
@synthesize userURL;
@synthesize tokenURL;
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
  [userURL release];
  [tokenURL release];
  [redirectURL release];
  [super dealloc];
}

#pragma mark -
#pragma mark Authorization

- (NSURLRequest *)userAuthorizationRequest;
{
  NSDictionary *params = [NSMutableDictionary dictionary];
  [params setValue:@"web_server" forKey:@"type"];
  [params setValue:clientID forKey:@"client_id"];
  [params setValue:[redirectURL absoluteString] forKey:@"redirect_uri"];
  
  NSURL *fullURL = [NSURL URLWithString:[[self.userURL absoluteString] stringByAppendingFormat:@"?%@", [params stringWithFormEncodedComponents]]];
  NSMutableURLRequest *authRequest = [NSMutableURLRequest requestWithURL:fullURL];
  [authRequest setHTTPMethod:@"GET"];

  return [[authRequest copy] autorelease];
}

- (void)verifyAuthorizationWithAccessCode:(NSString *)accessCode;
{
  @synchronized(self) {
    if (isVerifying) return; // don't allow more than one auth request
    
    isVerifying = YES;
    
    NSDictionary *params = [NSMutableDictionary dictionary];
    [params setValue:@"web_server" forKey:@"type"];
    [params setValue:clientID forKey:@"client_id"];
    [params setValue:[redirectURL absoluteString] forKey:@"redirect_uri"];
    [params setValue:clientSecret forKey:@"client_secret"];
    [params setValue:accessCode forKey:@"code"];
    
    ASIHTTPRequest *request = [ASIHTTPRequest requestWithURL:self.tokenURL];
    [request setRequestMethod:@"POST"];
    [request appendPostData:[[params stringWithFormEncodedComponents] dataUsingEncoding:NSUTF8StringEncoding]];
    [request setDelegate:self];
    [request startAsynchronous];
  }
}

- (void)refreshAccessToken:(LROAuth2AccessToken *)_accessToken;
{
  accessToken = [_accessToken retain];
  
  NSDictionary *params = [NSMutableDictionary dictionary];
  [params setValue:@"refresh" forKey:@"type"];
  [params setValue:clientID forKey:@"client_id"];
  [params setValue:[redirectURL absoluteString] forKey:@"redirect_uri"];
  [params setValue:clientSecret forKey:@"client_secret"];
  [params setValue:_accessToken.refreshToken forKey:@"refresh_token"];
  
  ASIHTTPRequest *request = [ASIHTTPRequest requestWithURL:self.tokenURL];
  [request setRequestMethod:@"POST"];
  [request appendPostData:[[params stringWithFormEncodedComponents] dataUsingEncoding:NSUTF8StringEncoding]];
  [request setDelegate:self];
  [request startAsynchronous];
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
    NSLog(@"[oauth] finished verification request, %@ (%d)", [request responseString], [request responseStatusCode]);
  }
  isVerifying = NO;
}

- (void)requestFailed:(ASIHTTPRequest *)request
{
  if (self.debug) {
    NSLog(@"[oauth] request failed with code %d, %@", [request responseStatusCode], [request responseString]);
  }
}

- (void)request:(ASIHTTPRequest *)request didReceiveData:(NSData *)data
{
  NSError *parseError = nil;
  NSDictionary *authorizationData = [[CJSONDeserializer deserializer] deserializeAsDictionary:data error:&parseError];
  
  if (parseError == nil) {
    if (accessToken == nil) {
      accessToken = [[LROAuth2AccessToken alloc] initWithAuthorizationResponse:authorizationData];
      if ([self.delegate respondsToSelector:@selector(oauthClientDidReceiveAccessToken:)]) {
        [self.delegate oauthClientDidReceiveAccessToken:self];
      } 
    } else {
      [accessToken refreshFromAuthorizationResponse:authorizationData];
      if ([self.delegate respondsToSelector:@selector(oauthClientDidRefreshAccessToken:)]) {
        [self.delegate oauthClientDidRefreshAccessToken:self];
      } 
    }
  }
}

@end

@implementation LROAuth2Client (UIWebViewIntegration)

- (void)authorizeUsingWebView:(UIWebView *)webView;
{
  [webView setDelegate:self];
  [webView loadRequest:[self userAuthorizationRequest]];
}

- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType
{
  return YES;
}

- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error
{
  NSString *failingURLString = [error.userInfo objectForKey:NSErrorFailingURLStringKey];
  
  if ([failingURLString hasPrefix:[self.redirectURL absoluteString]]) {
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
