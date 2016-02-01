//
//  NSString+Signature.h
//  ListedCompany
//
//  Created by IOS_HMX on 15/7/21.
//  Copyright (c) 2015年 Mitake Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (Signature)
/**
 *  字符串加密
 *
 *  @return 返回加密后的字符串
 */
- (NSString *)signatureString;
/**
 *  解加密key的混淆
 *
 *  @return 返回加密后的key字符串
 */
- (NSString *)keyRecoverString;
@end
