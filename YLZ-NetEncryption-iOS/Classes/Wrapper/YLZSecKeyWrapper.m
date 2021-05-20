//
//  YLZSecKeyWrapper.m
//  YiKaTongAPP
//
//  Created by YLZ-MAC on 15-1-6.
//  Copyright (c) 2015年 YLZ-MAC. All rights reserved.
//

#import "YLZSecKeyWrapper.h"
#import "NSData+YLZBase64.h"
#import "NSData+YLZHexadecimal.h"
#import "YLZRequestEncryptConfigKeys.h"
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>


@implementation YLZSecKeyWrapper

+ (NSString *)encryptUseRSA:(NSString *)content publicKey:(NSString *)publicKeyString
{
    return [self encryptUseRSA:content publicKey:publicKeyString secPadding:kTypeOfPwdPadding];
}

+ (NSString *)encryptUseRSA:(NSString *)content publicKey:(NSString *)publicKeyString secPadding:(SecPadding)secPadding
{
    
    NSData *publicKey = [NSData ylz_dataFromBase64String:publicKeyString];
    NSData *contentUTF8 = [content dataUsingEncoding: NSUTF8StringEncoding];
    
    SecKeyRef publicKeyRef = NULL;
    YLZSecKeyWrapper * secKeyWrapper = [YLZSecKeyWrapper sharedWrapper];
    
    publicKeyRef = [secKeyWrapper addPublicKey:kPublicKeyName keyBits:[secKeyWrapper stripPublicKeyHeader:publicKey]];
    if (NULL == publicKeyRef)
    {
        return nil;
    }
    NSData *newKey= [secKeyWrapper encrypt:contentUTF8 keyRef:publicKeyRef SecPadding:secPadding];
    NSString *result = [newKey  ylz_base64EncodedString];
    [secKeyWrapper removePublicKey:kPublicKeyName];
    
    result = [result stringByReplacingOccurrencesOfString:@"\r\n" withString:@""];
    return result;
    
}

/*
 * RSA 数字签名验证
 * content 待签名字符串
 * sig 待验证的签名字符串
 * return 真假
 */
+ (BOOL)verifySignatureWithString:(NSString *)content signature:(NSString *)sig publicKey:(NSString *)publicKeyStr
{
    if (!sig) {
        //未签名
        return YES;
    }
    SecKeyRef publicKeyRef = NULL;
    NSData *publicKey = [NSData ylz_dataFromBase64String:publicKeyStr];
    publicKeyRef = [[YLZSecKeyWrapper sharedWrapper] addPublicKey:kPublicKeyName keyBits:[[YLZSecKeyWrapper sharedWrapper] stripPublicKeyHeader:publicKey]];
    if (NULL == publicKeyRef)
    {
        return NO;
    }
    NSData *contentUTF8 = [content dataUsingEncoding: NSUTF8StringEncoding];
    NSData *sigData = [NSData ylz_dataFromBase64String:sig];
    BOOL result= [[YLZSecKeyWrapper sharedWrapper] verifySignature:contentUTF8 secKeyRef:publicKeyRef signature:sigData];
    [[YLZSecKeyWrapper sharedWrapper] removePublicKey:kPublicKeyName];
    return result;
}


//32位MD5加密方式
+(NSString *) md5: (NSString *) inPutText
{
    const char *cStr = [inPutText UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5( cStr, (int)strlen(cStr), digest );
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [result appendFormat:@"%02x", digest[i]];
    
    return result;
}


+ (NSString *)sha256:(NSString *)string {
    
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, result);
    NSMutableString *hash = [NSMutableString
                             stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    return hash;
}


#pragma mark

/*
 * AES 加密
 * content 待加密字符
 * symmetricKey    对称密钥 前16位有效
 * return 加密后的字符串
 */
+ (NSString *)encryptUseAES:(NSString *)content withKey:(NSString *)key withIv:(NSString *)iv withEncodeType:(NSString *)encode
{
    NSData * contentData = [content dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encryptedData = [[YLZSecKeyWrapper sharedWrapper] doAESCipher:contentData operation:kCCEncrypt key:key iv:iv];
    //加密后的数据
    NSString *result = nil;
    if (encryptedData) {
        if ([encode isEqualToString:@"base64"]) {
            result = [encryptedData  ylz_base64EncodedString];
        }else if ([encode isEqualToString:@"hex"]){
            result = [encryptedData ylz_hexadecimalString];
        }
    }
    
    return result;
}
/*
 * AES 解密
 * encryptedString 待解密字符
 * symmetricKey    对称密钥 前16位有效
 * return 解密后的Data
 */
+ (NSData *)dataWithDecryptAESWrap:(NSString *)encryptedString withKey:(NSString *)key withIv:(NSString *)iv withEncodeType:(NSString *)encode
{
    if (!encryptedString||[encryptedString isEqualToString:@""]) {
        return nil;
    }
    NSData * encryptedData = nil;
    
    if ([encode isEqualToString:@"base64"]) {
        
        encryptedData = [NSData ylz_dataFromBase64String:encryptedString];
        
    }else if ([encode isEqualToString:@"hex"]){
        
        encryptedData = [NSData ylz_dataFromHexadecimalString:encryptedString];
    }
    //解密
    NSData *decryptedData = [[YLZSecKeyWrapper sharedWrapper] doAESCipher:encryptedData operation:kCCDecrypt key:key iv:iv];
    return decryptedData;
}

+ (NSString *)decryptAESWrap:(NSString *)encryptedString withKey:(NSString *)key withIv:(NSString *)iv withEncodeType:(NSString *)encode
{
    //解密
    NSData *decryptedData = [self dataWithDecryptAESWrap:encryptedString withKey:key withIv:iv withEncodeType:encode];
    NSString * resultString= nil;
    if (decryptedData) {
        resultString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
        if (!resultString) {
            resultString = [decryptedData  ylz_base64EncodedString];
        }
    }
    return resultString;
    
}


//-----//



static YLZSecKeyWrapper * __sharedKeyWrapper = nil;

/* Begin method definitions */

+ (YLZSecKeyWrapper *)sharedWrapper {
    @synchronized(self) {
        if (__sharedKeyWrapper == nil) {
            __sharedKeyWrapper=[[self alloc] init];
        }
    }
    return __sharedKeyWrapper;
}

+ ( id)allocWithZone:(NSZone *)zone {
    @synchronized(self) {
        if (__sharedKeyWrapper == nil) {
            __sharedKeyWrapper = [super allocWithZone:zone];
            return __sharedKeyWrapper;
        }
    }
    return nil;
}

- ( id)copyWithZone:(NSZone *)zone {
    return self;
}


-(NSData *)stripPublicKeyHeader:(NSData *)keyData
{
    // Skip ASN.1 public key header
    if (0 == [keyData length])
    {
        return nil;
    }
    
    unsigned char *keyBytes = (unsigned char *)[keyData bytes];
    unsigned int  index    = 0;
    
    if (keyBytes[index++] != 0x30) return nil;
    
    if (keyBytes[index] > 0x80) index += keyBytes[index] - 0x80 + 1;
    else index++;
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&keyBytes[index], seqiod, 15)) return nil;
    
    index += 15;
    
    if (keyBytes[index++] != 0x03) return nil;
    
    if (keyBytes[index] > 0x80) index += keyBytes[index] - 0x80 + 1;
    else index++;
    
    if (keyBytes[index++] != '\0') return nil;
    
    // Now make a new NSData from this buffer
    return([NSData dataWithBytes:&keyBytes[index] length:[keyData length] - index]);
}

- (SecKeyRef)addPublicKey:(NSString *)keyName keyBits:(NSData *)publicKey
{
    OSStatus sanityCheck = noErr;
    SecKeyRef peerKeyRef = NULL;
    CFTypeRef persistPeer = NULL;
    NSAssert( keyName != nil, @"Key name parameter is nil." );
    NSAssert( publicKey != nil, @"Public key parameter is nil." );
    
    NSData * keyTag = [[NSData alloc] initWithBytes:(const void *)[keyName UTF8String] length:[keyName length]];
    NSMutableDictionary * peerPublicKeyAttr = [[NSMutableDictionary alloc] init];
    
    [peerPublicKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [peerPublicKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [peerPublicKeyAttr setObject:keyTag forKey:(__bridge id)kSecAttrApplicationTag];
    [peerPublicKeyAttr setObject:publicKey forKey:(__bridge id)kSecValueData];
    [peerPublicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    sanityCheck = SecItemAdd((__bridge CFDictionaryRef) peerPublicKeyAttr, (CFTypeRef *)&persistPeer);
    
    NSAssert((sanityCheck == noErr || sanityCheck == errSecDuplicateItem), @"Problem adding the app public key to the keychain, OSStatus == %d.", (int)sanityCheck);
    
    if (persistPeer)
    {
        peerKeyRef = [self getKeyRefWithPersistentKeyRef:persistPeer];
    }
    else
    {
        [peerPublicKeyAttr removeObjectForKey:(__bridge id)kSecValueData];
        [peerPublicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        // Let's retry a different way.
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef) peerPublicKeyAttr, (CFTypeRef *)&peerKeyRef);
    }
    
    NSAssert((sanityCheck == noErr), @"Problem acquiring reference to the public key, OSStatus == %d.", (int)sanityCheck);
    
    if (persistPeer)
        CFRelease(persistPeer);
    return peerKeyRef;
}

- (SecKeyRef)getKeyRefWithPersistentKeyRef:(CFTypeRef)persistentRef
{
    OSStatus sanityCheck = noErr;
    SecKeyRef keyRef = NULL;
    
    //    LOGGING_FACILITY(persistentRef != NULL, @"persistentRef object cannot be NULL." );
    
    NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];
    
    // Set the SecKeyRef query dictionary.
    [queryKey setObject:(__bridge id)persistentRef forKey:(__bridge id)kSecValuePersistentRef];
    [queryKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    // Get the persistent key reference.
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, (CFTypeRef *)&keyRef);
    
    NSAssert((sanityCheck == noErr), @"Problem acquiring reference to the public key, OSStatus == %d.", (int)sanityCheck);
    
    return keyRef;
}

//验证签名
- (BOOL)verifySignature:(NSData *)plainText secKeyRef:(SecKeyRef)publicKey signature:(NSData *)sig
{
    size_t signedHashBytesSize = 0;
    OSStatus sanityCheck = noErr;
    
    // Get the size of the assymetric block.
    signedHashBytesSize = SecKeyGetBlockSize(publicKey);
    sanityCheck = SecKeyRawVerify(    publicKey,
                                  kTypeOfSigPadding,
                                  (const uint8_t *)[[self getHashBytes:plainText] bytes],
                                  kChosenDigestLength,
                                  (const uint8_t *)[sig bytes],
                                  signedHashBytesSize
                                  );
    
    return (sanityCheck == noErr) ? YES : NO;
}

/**
 AES对称加密解密
 @param plainText   明文数据
 @param symmetricKey   密钥
 @param encryptOrDecrypt   操作类型，加密或者解密
 @param iv     初始化向量，可选
 默认加密模式为AES/CBC/PKCS7
 @returns 验证成功返回YES，否则返回NO。
 */
- (NSData *)doAESCipher:(NSData *)plainText operation:(CCOperation)encryptOrDecrypt key:(NSString *)symmetricKey iv:(NSString *)iv
{
    if (symmetricKey.length > kCCKeySizeAES128) {
        symmetricKey = [symmetricKey substringToIndex:kCCKeySizeAES128];
    }
    char keyPtr[kCCKeySizeAES128 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [symmetricKey getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCBlockSizeAES128 + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [plainText length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesCrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(encryptOrDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          ivPtr,
                                          [plainText bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
    }
    free(buffer);
    return nil;
}
/**
 * 生成对称密钥
 */
- (NSString *)generateSymmetricKey
{
    return @"";
    //    return YLZ_AES_KEY;
}

//加密
//kSecPadding
- (NSData*)encrypt:(NSData*)plainText keyRef:(SecKeyRef)publicKeyRef SecPadding:(SecPadding)kSecPadding
{
    OSStatus sanityCheck = noErr;
    NSMutableData* cipherData = [NSMutableData data];
    
    if (NULL == publicKeyRef)
    {
        return nil;
    }
    
    size_t cipherLen = SecKeyGetBlockSize(publicKeyRef);
    void *blockBuf = malloc(sizeof(uint8_t) * kMaxBlockSize);
    void *cipherTextBuf = malloc(sizeof(uint8_t) * cipherLen);
    long plainTextLen = [plainText length];
    
    for (int i = 0 ; i < plainTextLen; i += kMaxBlockSize) {
        long blockSize = MIN(kMaxBlockSize, plainTextLen - i);
        memset(blockBuf, 0, kMaxBlockSize);
        memset(cipherTextBuf, 0, cipherLen);
        [plainText getBytes:blockBuf range:NSMakeRange(i, blockSize)];
        sanityCheck = SecKeyEncrypt(publicKeyRef,
                                    kSecPadding,
                                    blockBuf,
                                    blockSize,
                                    cipherTextBuf,
                                    &cipherLen);
        
        if(sanityCheck == noErr) {
            [cipherData appendBytes:cipherTextBuf length:cipherLen];
        } else {
            cipherData = nil;
            break;
        }
    }
    
    free(blockBuf);
    free(cipherTextBuf);
    CFRelease(publicKeyRef);
    
    return cipherData;
}



- (NSData *)getHashBytes:(NSData *)plainText
{
    CC_SHA1_CTX ctx;
    uint8_t * hashBytes = NULL;
    NSData * hash = nil;
    
    // Malloc a buffer to hold hash.
    hashBytes = malloc( kChosenDigestLength * sizeof(uint8_t) );
    memset((void *)hashBytes, 0x0, kChosenDigestLength);
    
    // Initialize the context.
    CC_SHA1_Init(&ctx);
    // Perform the hash.
    CC_SHA1_Update(&ctx, (const void *)[plainText bytes], (CC_LONG)[plainText length]);
    // Finalize the output.
    CC_SHA1_Final(hashBytes, &ctx);
    
    // Build up the SHA1 hash.
    hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)kChosenDigestLength];
    
    if (hashBytes) free(hashBytes);
    
    return hash;
}

- (void)removePublicKey:(NSString *)keyName
{
    OSStatus sanityCheck = noErr;
    
    NSAssert( keyName != nil, @"Peer name parameter is nil." );
    
    NSData * peerTag = [[NSData alloc] initWithBytes:(const void *)[keyName UTF8String] length:[keyName length]];
    NSMutableDictionary * peerPublicKeyAttr = [[NSMutableDictionary alloc] init];
    
    [peerPublicKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [peerPublicKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [peerPublicKeyAttr setObject:peerTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef) peerPublicKeyAttr);
    
    NSAssert((sanityCheck == noErr || sanityCheck == errSecItemNotFound), @"Problem deleting the peer public key to the keychain, OSStatus == %d.", (int)sanityCheck);
    
}

+ (NSString *)encryptUseAES:(NSString *)content key:(NSString *)key iv:(NSString *)iv
{
    NSData * contentData = [content dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encryptedData = [[YLZSecKeyWrapper sharedWrapper] doAESCipher:contentData operation:kCCEncrypt key:key iv:iv];
    //加密后的数据
    NSString *result = encryptedData?[encryptedData  ylz_base64EncodedString]:nil;
    
    return result;
}



@end

