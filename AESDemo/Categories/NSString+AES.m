//
//  NSString+AES.m
//  ListedCompany
//
//  Created by IOS_HMX on 15/7/21.
//  Copyright (c) 2015年 Mitake Inc. All rights reserved.
//

#import "NSString+AES.h"
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
@implementation NSString (AES)
-(NSString *)encryptStringUseAESForKey:(NSString*)key
{
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    const void * keyPtr2 = [key UTF8String];
    
    NSUInteger dataLength = [data length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128,
                                          kCCOptionECBMode | kCCOptionPKCS7Padding,
                                          keyPtr2, kCCKeySizeAES128,
                                          NULL,
                                          [data bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        
       // NSData* originData = [originStr dataUsingEncoding:NSASCIIStringEncoding];
        
        NSString* s = [[NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted] base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
        return s;
        
    }
    free(buffer);
    return nil;
}
-(NSString *)decryptStringUseAESForKey:(NSString *)key
{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:self options:NSDataBase64DecodingIgnoreUnknownCharacters];
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr, kCCBlockSizeAES128,
                                          NULL,
                                          [data bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesDecrypted);
    if (cryptStatus == kCCSuccess) {
        NSString *s = [[NSString alloc] initWithData:[NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted] encoding:NSUTF8StringEncoding];
        return s;
    }
    free(buffer);
    return nil;
}
@end
