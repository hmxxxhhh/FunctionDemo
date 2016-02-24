//
//  DeviceInfo.m
//  IP
//
//  Created by IOS_HMX on 15/11/13.
//  Copyright (c) 2015年 humingxing. All rights reserved.
//

#import "DeviceInfo.h"
#import <UIKit/UIKit.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
@interface DeviceInfo()

@property(nonatomic,copy,readwrite)NSString *deviceId;
@property(nonatomic,copy,readwrite)NSString *deviceModel;
@property(nonatomic,copy,readwrite)NSString *deviceScreenScale;
@property(nonatomic,copy,readwrite)NSString *appBundleName;
@property(nonatomic,copy,readwrite)NSString *appVersion;
@property(nonatomic,copy,readwrite)NSString *systemName;
@property(nonatomic,copy,readwrite)NSString *systemVersion;
@property(nonatomic,copy,readwrite)NSString *carrierName;
@property(nonatomic,copy,readwrite)NSString *currentRadioAccessTechnology;
@property(nonatomic,copy,readwrite)NSString *ipAdress;
@property(nonatomic,strong)CTTelephonyNetworkInfo *telephonyInfo;

@end
@implementation DeviceInfo
-(instancetype)init
{
    if (self = [super init]) {
        [self initProperties];
    }
    return self;
}
+(DeviceInfo *)currentDeviceInfo
{
    static DeviceInfo *currentDeviceInfo;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        currentDeviceInfo = [[DeviceInfo alloc]init];
    });
    return currentDeviceInfo;
}
-(void)initProperties
{
    CGRect rect = [[UIScreen mainScreen] bounds];
    CGFloat scale_screen = [UIScreen mainScreen].scale;
    self.deviceId = [[UIDevice currentDevice].identifierForVendor UUIDString];
    self.deviceModel = [[UIDevice currentDevice]model];
    self.deviceScreenScale = [NSString stringWithFormat:@"%d*%d",(int)(rect.size.width*scale_screen),(int)(rect.size.height*scale_screen) ];
    self.appBundleName = [[NSBundle  mainBundle]bundleIdentifier];
    self.appVersion = [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleShortVersionString"];
    self.appMarket = @"App Store";
    self.systemName = [UIDevice currentDevice].systemName;
    self.systemVersion = [[UIDevice currentDevice] systemVersion];
    self.telephonyInfo = [CTTelephonyNetworkInfo new];
    self.carrierName = self.telephonyInfo.subscriberCellularProvider.carrierName;
    self.currentRadioAccessTechnology = self.telephonyInfo.currentRadioAccessTechnology;
//    CTTelephonyNetworkInfo *telephonyInfo = [CTTelephonyNetworkInfo new];
//    NSLog(@"Current Radio Access Technology: %@ %@ %@", telephonyInfo.currentRadioAccessTechnology,telephonyInfo.subscriberCellularProvider.carrierName,telephonyInfo.subscriberCellularProvider.isoCountryCode);
//
//    [NSNotificationCenter.defaultCenter addObserverForName:CTRadioAccessTechnologyDidChangeNotification
//                                                    object:nil
//                                                     queue:nil
//                                                usingBlock:^(NSNotification *note)
//    {
//        NSLog(@"New Radio Access Technology: %@", telephonyInfo.currentRadioAccessTechnology);
//    }];
}
-(NSString *)ipAdress
{
    NSString *address = @"an error occurred when obtaining ip address";
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    
    success = getifaddrs(&interfaces);
    
    if (success == 0) { // 0 表示获取成功
        
        temp_addr = interfaces;
        while (temp_addr != NULL) {
            if( temp_addr->ifa_addr->sa_family == AF_INET) {
                // Check if interface is en0 which is the wifi connection on the iPhone
                if ([[NSString stringWithUTF8String:temp_addr->ifa_name] isEqualToString:@"en0"]) {
                    // Get NSString from C String
                    address = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr)];
                }
            }
            
            temp_addr = temp_addr->ifa_next;
        }
    }
    
    freeifaddrs(interfaces);
    return address;
}
@end
