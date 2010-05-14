//
//  NSURL+QueryInspector.m
//  Firelight
//
//  Created by Luke Redpath on 14/05/2010.
//  Copyright 2010 LJR Software Limited. All rights reserved.
//

#import "NSURL+QueryInspector.h"


@implementation NSURL (QueryInspector)

- (NSDictionary *)queryDictionary;
{
  NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
  for (NSString *keyPair in [self.query componentsSeparatedByString:@"&"]) {
    NSArray *components = [keyPair componentsSeparatedByString:@"="];
    [dictionary setValue:[components objectAtIndex:1] forKey:[components objectAtIndex:0]];
  }  
  return [[dictionary copy] autorelease];
}

@end
