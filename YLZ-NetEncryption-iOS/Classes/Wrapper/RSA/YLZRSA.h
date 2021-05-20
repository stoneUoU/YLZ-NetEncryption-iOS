//
//  YLZRSA.h
//  YLZ-NetEncryption-iOS
//
//  Created by stone on 2020/2/15.
//

#import <Foundation/Foundation.h>

#define kFastLoginPublicKey  @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCetI8aE7/Vf/AhVixzShW/JJPNmoU8ZkliyaIgKykkdAfsY5FmOaZZa7zP9sSwNUs6HTjU8Powp8vtxW39uTmmaiCgmzTyJq1xH1wmLCsXS2ASk7Jq+5t5Ii8P5wcjgSYOoYEkXsT0EtNk8DrBDVtglP2asX1s4Jq0IO8lOze6aQIDAQAB"

@interface YLZRSA : NSObject

// return base64 encoded string
+ (NSString *)encryptString:(NSString *)str publicKey:(NSString *)pubKey;
// return raw data
+ (NSData *)encryptData:(NSData *)data publicKey:(NSString *)pubKey;
// return base64 encoded string
+ (NSString *)encryptString:(NSString *)str privateKey:(NSString *)privKey;
// return raw data
+ (NSData *)encryptData:(NSData *)data privateKey:(NSString *)privKey;

// decrypt base64 encoded string, convert result to string(not base64 encoded)
+ (NSString *)decryptString:(NSString *)str publicKey:(NSString *)pubKey;
+ (NSData *)decryptData:(NSData *)data publicKey:(NSString *)pubKey;
+ (NSString *)decryptString:(NSString *)str privateKey:(NSString *)privKey;
+ (NSData *)decryptData:(NSData *)data privateKey:(NSString *)privKey;

@end
