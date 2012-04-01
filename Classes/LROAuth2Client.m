//
//  LROAuth2Client.m
//  LROAuth2Client
//
//  Created by Luke Redpath on 14/05/2010.
//  Copyright 2010 LJR Software Limited. All rights reserved.
//

#import "LROAuth2Client.h"
#import "NSURL+QueryInspector.h"
#import "LROAuth2AccessToken.h"
#import "LRURLRequestOperation.h"
#import "NSDictionary+QueryString.h"

#pragma mark -

@implementation LROAuth2Client {
  NSOperationQueue *_networkQueue;
}

@synthesize clientID;
@synthesize clientSecret;
@synthesize redirectURL;
@synthesize cancelURL;
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
    requests = [[NSMutableArray alloc] init];
    debug = NO;
    _networkQueue = [[NSOperationQueue alloc] init];
  }
  return self;
}

- (void)dealloc;
{
  [_networkQueue cancelAllOperations];
}

#pragma mark -
#pragma mark Authorization

- (NSURLRequest *)userAuthorizationRequestWithParameters:(NSDictionary *)additionalParameters;
{
  NSDictionary *params = [NSMutableDictionary dictionary];
  [params setValue:@"web_server" forKey:@"type"];
  [params setValue:clientID forKey:@"client_id"];
  [params setValue:[redirectURL absoluteString] forKey:@"redirect_uri"];
  
  if (additionalParameters) {
    for (NSString *key in additionalParameters) {
      [params setValue:[additionalParameters valueForKey:key] forKey:key];
    }
  }  
  NSURL *fullURL = [NSURL URLWithString:[[self.userURL absoluteString] stringByAppendingFormat:@"?%@", [params stringWithFormEncodedComponents]]];
  NSMutableURLRequest *authRequest = [NSMutableURLRequest requestWithURL:fullURL];
  [authRequest setHTTPMethod:@"GET"];

  return [authRequest copy];
}

- (void)verifyAuthorizationWithAccessCode:(NSString *)accessCode;
{
  @synchronized(self) {
    if (isVerifying) return; // don't allow more than one auth request
    
    isVerifying = YES;
    
    NSDictionary *params = [NSMutableDictionary dictionary];
    [params setValue:@"authorization_code" forKey:@"grant_type"];
    [params setValue:clientID forKey:@"client_id"];
    [params setValue:clientSecret forKey:@"client_secret"];
    [params setValue:[redirectURL absoluteString] forKey:@"redirect_uri"];
    [params setValue:accessCode forKey:@"code"];
    
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:self.tokenURL];
    [request setHTTPMethod:@"POST"];
    [request setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    [request setHTTPBody:[[params stringWithFormEncodedComponents] dataUsingEncoding:NSUTF8StringEncoding]];
    
    LRURLRequestOperation *operation = [[LRURLRequestOperation alloc] initWithURLRequest:request];

    __unsafe_unretained id blockOperation = operation;

    [operation setCompletionBlock:^{
      [self handleCompletionForAuthorizationRequestOperation:blockOperation];
    }];
      
    [_networkQueue addOperation:operation];
  }
}

- (void)refreshAccessToken:(LROAuth2AccessToken *)_accessToken;
{
  accessToken = _accessToken;
  
  NSDictionary *params = [NSMutableDictionary dictionary];
  [params setValue:@"refresh_token" forKey:@"grant_type"];
  [params setValue:clientID forKey:@"client_id"];
  [params setValue:clientSecret forKey:@"client_secret"];
  [params setValue:[redirectURL absoluteString] forKey:@"redirect_uri"];
  [params setValue:_accessToken.refreshToken forKey:@"refresh_token"];
  
  NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:self.tokenURL];
  [request setHTTPMethod:@"POST"];
  [request setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
  [request setHTTPBody:[[params stringWithFormEncodedComponents] dataUsingEncoding:NSUTF8StringEncoding]];
  
  LRURLRequestOperation *operation = [[LRURLRequestOperation alloc] initWithURLRequest:request];
  
  __unsafe_unretained id blockOperation = operation;
  
  [operation setCompletionBlock:^{
    [self handleCompletionForAuthorizationRequestOperation:blockOperation];
  }];
  
  [_networkQueue addOperation:operation];
}

- (void)handleCompletionForAuthorizationRequestOperation:(LRURLRequestOperation *)operation
{
  NSHTTPURLResponse *response = (NSHTTPURLResponse *)operation.URLResponse;
  
  if (response.statusCode == 200) {
    NSError *parserError;
    NSDictionary *authData = [NSJSONSerialization JSONObjectWithData:operation.responseData options:0 error:&parserError];
    
    if (authData == nil) {
      // try and decode the response body as a query string instead
      NSString *responseString = [[NSString alloc] initWithData:operation.responseData encoding:NSUTF8StringEncoding];
      authData = [NSDictionary dictionaryWithFormEncodedString:responseString];
    }
    if ([authData objectForKey:@"access_token"] == nil) {
      NSAssert(NO, @"Unhandled parsing failure");
    }
    if (accessToken == nil) {
      accessToken = [[LROAuth2AccessToken alloc] initWithAuthorizationResponse:authData];
      if ([self.delegate respondsToSelector:@selector(oauthClientDidReceiveAccessToken:)]) {
        [self.delegate oauthClientDidReceiveAccessToken:self];
      } 
    } else {
      [accessToken refreshFromAuthorizationResponse:authData];
      if ([self.delegate respondsToSelector:@selector(oauthClientDidRefreshAccessToken:)]) {
        [self.delegate oauthClientDidRefreshAccessToken:self];
      }
    }
  }
  else {
    if (operation.connectionError) {
      NSLog(@"Connection error: %@", operation.connectionError);
    }
  }
}

@end

@implementation LROAuth2Client (UIWebViewIntegration)

- (void)authorizeUsingWebView:(UIWebView *)webView;
{
  [self authorizeUsingWebView:webView additionalParameters:nil];
}

- (void)authorizeUsingWebView:(UIWebView *)webView additionalParameters:(NSDictionary *)additionalParameters;
{
  [webView setDelegate:self];
  [webView loadRequest:[self userAuthorizationRequestWithParameters:additionalParameters]];
}

- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType;
{  
  if ([[request.URL absoluteString] hasPrefix:[self.redirectURL absoluteString]]) {
    [self extractAccessCodeFromCallbackURL:request.URL];

    return NO;
  } else if (self.cancelURL && [[request.URL absoluteString] hasPrefix:[self.cancelURL absoluteString]]) {
    if ([self.delegate respondsToSelector:@selector(oauthClientDidCancel:)]) {
      [self.delegate oauthClientDidCancel:self];
    }
    
    return NO;
  }
  
  if ([self.delegate respondsToSelector:@selector(webView:shouldStartLoadWithRequest:navigationType:)]) {
    return [self.delegate webView:webView shouldStartLoadWithRequest:request navigationType:navigationType];
  }
  
  return YES;
}

/**
 * custom URL schemes will typically cause a failure so we should handle those here
 */
- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error
{
  
#if __IPHONE_OS_VERSION_MAX_ALLOWED <= __IPHONE_3_2
  NSString *failingURLString = [error.userInfo objectForKey:NSErrorFailingURLStringKey];
#else
  NSString *failingURLString = [error.userInfo objectForKey:NSURLErrorFailingURLStringErrorKey];
#endif
  
  if ([failingURLString hasPrefix:[self.redirectURL absoluteString]]) {
    [webView stopLoading];
    [self extractAccessCodeFromCallbackURL:[NSURL URLWithString:failingURLString]];
  } else if (self.cancelURL && [failingURLString hasPrefix:[self.cancelURL absoluteString]]) {
    [webView stopLoading];
    if ([self.delegate respondsToSelector:@selector(oauthClientDidCancel:)]) {
      [self.delegate oauthClientDidCancel:self];
    }
  }
  
  if ([self.delegate respondsToSelector:@selector(webView:didFailLoadWithError:)]) {
    [self.delegate webView:webView didFailLoadWithError:error];
  }
}

- (void)webViewDidStartLoad:(UIWebView *)webView
{
  if ([self.delegate respondsToSelector:@selector(webViewDidStartLoad:)]) {
    [self.delegate webViewDidStartLoad:webView];
  }
}

- (void)webViewDidFinishLoad:(UIWebView *)webView
{
  if ([self.delegate respondsToSelector:@selector(webViewDidFinishLoad:)]) {
    [self.delegate webViewDidFinishLoad:webView];
  }
}

- (void)extractAccessCodeFromCallbackURL:(NSURL *)callbackURL;
{
  NSString *accessCode = [[callbackURL queryDictionary] valueForKey:@"code"];
  
  if ([self.delegate respondsToSelector:@selector(oauthClientDidReceiveAccessCode:)]) {
    [self.delegate oauthClientDidReceiveAccessCode:self];
  }
  [self verifyAuthorizationWithAccessCode:accessCode];
}

@end
