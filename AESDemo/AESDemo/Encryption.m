//
//  API.m
//  Demo
//
//  Created by 曹燕兵 on 16/1/26.
//  Copyright © 2016年 曹燕兵. All rights reserved.
//

#import "Encryption.h"
#import "NSString+AES.h"
#import "NSString+Signature.h"
@implementation Encryption

//加密处理
+(NSDictionary *)jsonParamWithParam:(NSDictionary *)parameters KeyString:(NSString *)keystring
{
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:parameters options:NSJSONWritingPrettyPrinted error:nil];
    
    NSString *tempParamString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSString *kString = [tempParamString encryptStringUseAESForKey:[keystring keyRecoverString]];
    NSString *sString = [tempParamString signatureString];
    return @{@"k":kString,@"s":sString};
}

+(NSDictionary *)paseDataWithDict:(NSData *)data KeyString:(NSString *)keystring
{
    NSMutableDictionary *dic = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableLeaves error:nil];
    NSString *iString = [dic objectForKey:@"i"];
    NSString *sString = [dic objectForKey:@"s"];
    if (iString!=nil&&![iString isEqualToString:@""]) {
        return @{@"status":@0,@"i":iString};
    }else{
        NSString *kString = [[dic objectForKey:@"k"] decryptStringUseAESForKey:[keystring keyRecoverString]];
        if ([[kString signatureString] isEqualToString:sString]) {
            NSData *data = [kString dataUsingEncoding:NSUTF8StringEncoding];
            id response = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableLeaves error:nil];
            return @{@"status":@1,@"data":response};
        }else
        {
            return @{@"status":@0};
        }
    }
    
}
@end
