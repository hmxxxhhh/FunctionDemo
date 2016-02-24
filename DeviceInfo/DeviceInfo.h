//
//  DeviceInfo.h
//  IP
//
//  Created by IOS_HMX on 15/11/13.
//  Copyright (c) 2015年 humingxing. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface DeviceInfo : NSObject
/**
 *  设备ID 唯一标示
 */
@property(nonatomic,copy,readonly)NSString *deviceId;
/**
 *  设备型号
 */
@property(nonatomic,copy,readonly)NSString *deviceModel;
/**
 *  设备分辨率
 */
@property(nonatomic,copy,readonly)NSString *deviceScreenScale;
/**
 *  APP名称
 */
@property(nonatomic,copy,readonly)NSString *appBundleName;
/**
 *  APP版本
 */
@property(nonatomic,copy,readonly)NSString *appVersion;
/**
 *  APP市场（下载渠道，默认为App Store）
 */
@property(nonatomic,copy)NSString *appMarket;
/**
 *  系统名称
 */
@property(nonatomic,copy,readonly)NSString *systemName;
/**
 *  系统版本
 */
@property(nonatomic,copy,readonly)NSString *systemVersion;
/**
 *  运营商
 */
@property(nonatomic,copy,readonly)NSString *carrierName;
/**
 *  当前网络类型
 */
@property(nonatomic,copy,readonly)NSString *currentRadioAccessTechnology;
/**
 *  IP地址
 */
@property(nonatomic,copy,readonly)NSString *ipAdress;

+(DeviceInfo *)currentDeviceInfo;
@end
