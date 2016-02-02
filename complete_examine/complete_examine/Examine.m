//
//  Examine.m
//  complete_examine
//
//  Created by 曹燕兵 on 16/2/1.
//  Copyright © 2016年 曹燕兵. All rights reserved.
//

#import "Examine.h"
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#if TARGET_IPHONE_SIMULATOR
#define MM @"a83699ef3115f8771b9e7ff9cd27aaae"
#else
#define MM @"7656a394ff178638d73e1d68378267ea"
#endif

@implementation Examine

+ (NSString *) stringFromMD5:(NSData *)data{
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5((const void *)[data bytes], (CC_LONG)[data length], result);
    NSMutableString *hash = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [hash appendFormat:@"%02X", result[i]];
    return [hash lowercaseString];
}
+(NSData *)dataInPath:(NSString *)path
{
    NSMutableData *data = [NSMutableData data];
    NSError *error;
    NSArray *contents = [[NSFileManager defaultManager]contentsOfDirectoryAtPath:path error:&error];
    if (contents == nil) {
        if (![[path lastPathComponent]isEqualToString:[[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleName"]] &&
            ![[path lastPathComponent] hasSuffix:@".car"] &&
            ![[path lastPathComponent] hasSuffix:@"CodeResources"] &&
            ![[path lastPathComponent] hasSuffix:@".nib"]&&
            ![[path lastPathComponent] hasSuffix:@".xcent"]&&
            ![[path lastPathComponent] hasSuffix:@".mobileprovision"]&&
            ![path hasSuffix:@"Main.storyboardc/Info.plist"]) {
            [data appendData:[NSData dataWithContentsOfFile:path options:NSDataReadingUncached error:nil]];
            return data;
        }
        return nil;
    }
    for (NSString *content in contents) {
        
        NSString *fullPath = [path stringByAppendingPathComponent:content];
        NSData *d = [self dataInPath:fullPath];
        if (d) {
            [data appendData:d];
        }
    }
    return data;
}
+(void)examine{
    NSString * string = [self stringFromMD5:[self dataInPath:[[NSBundle mainBundle] resourcePath]]];
    NSLog(@"%@",string);
    if (![MM isEqualToString:string]) {
        UIAlertView *alertView = [[UIAlertView alloc] initWithTitle:@""
                                                            message:@"档案损毁，请重新下载安装APP。"
                                                           delegate:self
                                                  cancelButtonTitle:nil
                                                  otherButtonTitles:nil];
        [alertView show];
        return;
    }

}

@end
