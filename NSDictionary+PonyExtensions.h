@interface NSDictionary (PonyExtensions)
+ (NSDictionary *)dictionaryWithFormEncodedString:(NSString *)encodedString
- (NSString *)stringWithFormEncodedComponents;
@end
