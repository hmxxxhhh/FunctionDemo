//
//  ViewController.m
//  AESDemo
//
//  Created by 曹燕兵 on 16/1/29.
//  Copyright © 2016年 曹燕兵. All rights reserved.
//

#import "ViewController.h"
#import "Encryption.h"
#import "AFNetworking.h"
#import <AFNetworking/AFHTTPRequestOperation.h>
@interface ViewController ()
@property(nonatomic,strong)NSMutableData *myData;
@property(nonatomic,copy)NSString *key;
@end
//jnxtbRqiBVpdwzPQ
@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    [self creatbutton];
    self.key = @"dsf";
}
-(void)creatbutton{
    UIButton *button = [UIButton buttonWithType:UIButtonTypeCustom];
    [button setTitle:@"测试" forState:UIControlStateNormal];
    button.frame = CGRectMake(80, 150, 100, 30);
    button.backgroundColor = [UIColor orangeColor];
    [button addTarget:self action:@selector(clickbutton1) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:button];
}
-(void)clickbutton1{
    NSMutableDictionary *dic = [NSMutableDictionary dictionary];
    [dic setObject:@"600360" forKey:@"user_name"];
    [dic setObject:@"123456" forKey:@"password"];
    [dic setObject:@"38bea8dc9582f98a09c24b9390c55d2b" forKey:@"device_id"];
    [dic setObject:@"iOS" forKey:@"device_type"];
    [dic setObject:[[NSBundle mainBundle] bundleIdentifier] forKey:@"app_id"];
    [dic setObject:@"1234" forKey:@"device_token"];
    
    AFHTTPRequestOperation *operation;
    operation = [[self defaultOperationManager] POST:@"http://10.10.12.55:8080/ListCompanyApiServer/central.do" parameters:[Encryption jsonParamWithParam:@{@"data":dic,@"method":@"login"} KeyString:self.key] success:^(AFHTTPRequestOperation * _Nonnull operation, id  _Nonnull responseObject) {
        NSDictionary *response = [Encryption paseDataWithDict:responseObject KeyString:self.key];
        if ([response[@"status"]integerValue]==1) {
            NSLog(@"success data:%@",response[@"data"]);
        }else {
            if (response[@"i"]) {
                self.key = response[@"i"];
                [self clickbutton1];
            }else
            {
                NSLog(@"error");
            }
        }
        
    } failure:^(AFHTTPRequestOperation * _Nullable operation, NSError * _Nonnull error) {
        
    }];
}
-(AFHTTPRequestOperationManager *)defaultOperationManager
{
    static AFHTTPRequestOperationManager *manager;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        manager = [AFHTTPRequestOperationManager manager];
        manager.requestSerializer = [AFJSONRequestSerializer serializer];
        manager.responseSerializer = [AFHTTPResponseSerializer serializer];
});
    return manager;
}
@end
