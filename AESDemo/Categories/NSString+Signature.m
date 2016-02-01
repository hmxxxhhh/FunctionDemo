//
//  NSString+Signature.m
//  ListedCompany
//
//  Created by IOS_HMX on 15/7/21.
//  Copyright (c) 2015年 Mitake Inc. All rights reserved.
//

#import "NSString+Signature.h"
#import "decrypt.h"

@implementation NSString (Signature)
- (NSString *)signatureString {
    SignContext ctx;
    SignInit(&ctx, (char*)[self UTF8String]);
    GenSignature(&ctx);
    //NSLog(@"%@", [NSString stringWithUTF8String:ctx.result]);
    return [NSString stringWithUTF8String:ctx.result];
}

- (NSString *)keyRecoverString {
    size_t sz = sizeof(char)*self.length+1;
    char *s = malloc(sz);
    memset(s, 0, sz);
    memcpy(s, [self UTF8String], self.length);
    a(s);
    NSString *str = [NSString stringWithUTF8String:s];
    free(s);
    s = nil;
    return str;
}

@end
