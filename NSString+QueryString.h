@interface NSString (QueryString)
- (NSString*)stringByEscapingForURLQuery;
- (NSString*)stringByUnescapingFromURLQuery;
@end
