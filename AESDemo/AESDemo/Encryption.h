//
//  API.h
//  Demo
//
//  Created by 曹燕兵 on 16/1/26.
//  Copyright © 2016年 曹燕兵. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "AFNetworking.h"
@interface Encryption : NSObject
/**
 *  加密
 *
 *  @param parameters 参数
 *  @param keystring  加密因子
 *
 *  @return 加密后的数据
 */
+(NSDictionary *)jsonParamWithParam:(NSDictionary *)parameters KeyString:(NSString *)keystring;
/**
 *  解析返回的数据
 *
 *  @param data 服务器返回的数据
 *
 *  @param keystring 标示符，必须和加密因子一致，否则无法解密
 *
 *  @return 返回一个字典 格式为：｛status：0，i:"dsfdfs",data:data｝
 *  当status等于1时，解析成功, i 值为空，responseData为解析后的数据
 *  当status等于0时，解析失败,responseData为空，当i有值时，重新发送请求
 */
+(NSDictionary *)paseDataWithDict:(NSData *)data KeyString:(NSString *)keystring;

@end
