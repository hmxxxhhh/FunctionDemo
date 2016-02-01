//
//  NSString+AES.h
//  ListedCompany
//
//  Created by IOS_HMX on 15/7/21.
//  Copyright (c) 2015年 Mitake Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
/**
 *  NSString 分类 用于给字符串做AES的加密解密
 */
@interface NSString (AES)
/**
 *  AES加密
 *
 *  @param key 加密Key
 *
 *  @return 返回一个加密后的字符串
 */
-(NSString *)encryptStringUseAESForKey:(NSString*)key;
/**
 *  AES解密
 *
 *  @param key 解密Key
 *
 *  @return 返回一个解密的字符串
 */
-(NSString *)decryptStringUseAESForKey:(NSString*)key;
@end
