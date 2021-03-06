//
//  YLZNetEncryptManager.m
//  YLZ-NetEncryption-iOS
//
//  Created by cy on 2018/12/7.
//

#import "YLZNetEncryptManager.h"
#import "YLZSMEncryption.h"
#import "YLZSecKeyWrapper.h"
#import "NSData+YLZBase64.h"
#import "NSData+YLZHexadecimal.h"
#import "NSDictionary+YLZSign.h"
#import <CommonCrypto/CommonDigest.h>
#import "YLZMSEncryptionConfig.h"

#define YLZ_SMDefault_iv @"0102030405060708"

@implementation YLZNetEncryptManager

+ (YLZRequestEncryptConfigKeys *)finalKeyConfigWithConfig:(YLZRequestEncryptConfigKeys *)config {
    YLZRequestEncryptConfigKeys *finalConfig = [[YLZRequestEncryptConfigKeys alloc] init];
    
    finalConfig.appIdKey  = config.appIdKey ?: ylz_defaultEncryptConfigKeys().appIdKey;
    finalConfig.appSecretKey = config.appSecretKey ?: ylz_defaultEncryptConfigKeys().appSecretKey;
    finalConfig.signTypeKey = config.signTypeKey ?: ylz_defaultEncryptConfigKeys().signTypeKey;
    finalConfig.encryptTypeKey = config.encryptTypeKey ?: ylz_defaultEncryptConfigKeys().encryptTypeKey;
    finalConfig.encodeTypeKey = config.encodeTypeKey ?: ylz_defaultEncryptConfigKeys().encodeTypeKey;
    finalConfig.signKey = config.signKey ?: ylz_defaultEncryptConfigKeys().signKey;
    finalConfig.verifySignKey = config.verifySignKey ?: ylz_defaultEncryptConfigKeys().verifySignKey;
    finalConfig.signBlackListKey = config.signBlackListKey ?: ylz_defaultEncryptConfigKeys().signBlackListKey;
    finalConfig.decryptKey = config.decryptKey ?: ylz_defaultEncryptConfigKeys().decryptKey;
    finalConfig.encryptKey = config.encryptKey ?: ylz_defaultEncryptConfigKeys().encryptKey;
    finalConfig.asymEncryptPublickeyKey = config.asymEncryptPublickeyKey ?: ylz_defaultEncryptConfigKeys().asymEncryptPublickeyKey;
    finalConfig.asymEncryptPrivatekeyKey = config.asymEncryptPrivatekeyKey ?: ylz_defaultEncryptConfigKeys().asymEncryptPrivatekeyKey;
    finalConfig.encryptMapKey = config.encryptMapKey ?: ylz_defaultEncryptConfigKeys().encryptMapKey;
    
    return finalConfig;
}

#pragma mark ----------------------------:: ?????? ::----------------------------

+(NSMutableDictionary *)encryptNetData:(NSDictionary *)param
{
    return [self encryptNetData:param extra:nil];
}

+(NSMutableDictionary *)encryptNetData:(NSDictionary *)param extra:(NSDictionary *)extra
{
    return [self encryptNetData:param withConfigKeys:ylz_defaultEncryptConfigKeys() extra:extra];
}

/**
 ???????????????
 
 @Discussion  ??????????????????????????????????????????????????????????????????
 
 @param param ????????????
 @param ylz_configKeys key??????
 @param extra ??????????????????????????????????????????????????????
 @return ??????????????????
 */
+(NSMutableDictionary *)encryptNetData:(NSDictionary *)param withConfigKeys:(YLZRequestEncryptConfigKeys *)ylz_configKeys extra:(NSDictionary *)extra
{
    if (!param) {return nil;}
    YLZRequestEncryptConfigKeys *configKeys = [self finalKeyConfigWithConfig:ylz_configKeys];
    NSMutableDictionary *encryptParam = [NSMutableDictionary dictionaryWithDictionary:param];
    [encryptParam addEntriesFromDictionary:extra];
    NSString *appId = [encryptParam objectForKey:configKeys.appIdKey];
    NSString *appSecret = [encryptParam objectForKey:configKeys.appSecretKey];
    NSString *signType = [encryptParam objectForKey:configKeys.signTypeKey];
    NSString *encryptType = [encryptParam objectForKey:configKeys.encryptTypeKey];
    NSString *encodeType = [encryptParam objectForKey:configKeys.encodeTypeKey];
    NSString *privatekey = [encryptParam objectForKey:configKeys.asymEncryptPrivatekeyKey];
    NSArray *signBlackList = [encryptParam objectForKey:configKeys.signBlackListKey];
    NSMutableDictionary *encryptPropertyMapper = [NSMutableDictionary dictionaryWithDictionary:[encryptParam objectForKey:configKeys.encryptMapKey]];
    if (configKeys.encryptKey && configKeys.decryptKey) {
        [encryptPropertyMapper setObject:configKeys.encryptKey forKey:configKeys.decryptKey];
    }
    NSMutableDictionary *reqParam = [NSMutableDictionary dictionaryWithDictionary:param];
    //??????
    NSString *sign = [YLZNetEncryptManager signNetData:param withSecret:appSecret signType:signType blackList:signBlackList asymEncryptPrivatekey:privatekey];
    if (sign.length) {
        [reqParam setObject:sign forKey:configKeys.signKey];
    }
    //??????
    for (NSString *oriKey in encryptPropertyMapper) {
        NSString *mapKey = encryptPropertyMapper[oriKey];
        id paramObj = [reqParam objectForKey:oriKey];
        NSString * encryptDataStr = [self encryptData:paramObj appId:appId appSecret:appSecret encryptType:encryptType encodeType:encodeType];
        if (encryptDataStr && encryptDataStr.length > 0) {
            //?????????????????????oriKey==mapKey????????????removeObjectForKey
            [reqParam removeObjectForKey:oriKey];
            [reqParam setObject:encryptDataStr forKey:mapKey];
        }
    }
    return reqParam;
}


#pragma mark ----------------------------:: ?????? ::----------------------------

+ (NSMutableDictionary *)decryptNetData:(id)data {
    return [self decryptNetData:data extra:nil];
}

+ (NSMutableDictionary *)decryptNetData:(id)data extra:(NSDictionary * _Nullable)extra {
    return [self decryptNetData:data withConfigKeys:ylz_defaultEncryptConfigKeys() extra:extra];
}

/**
 ???????????????.

 @Discussion ?????????????????????????????????????????????key?????????????????????????????????????????????????????????
 
 @param encData ?????????Json??????????????????
 @param ylz_configKeys key??????
 @param extra ??????????????????data??????????????????????????????
 @return ??????????????????
 */
+ (NSMutableDictionary *)decryptNetData:(id)encData withConfigKeys:(YLZRequestEncryptConfigKeys *)ylz_configKeys extra:(NSDictionary *)extra {
    
    NSMutableDictionary *encDic;
    
    if ([encData isKindOfClass:[NSDictionary class]]) {
        
        encDic = [NSMutableDictionary dictionaryWithDictionary:encData];
        
    }else if([encData isKindOfClass:[NSString class]]){
        
        NSDictionary * object = [NSJSONSerialization JSONObjectWithData:[encData dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingAllowFragments error:nil];
        if (object) {
            encDic = [NSMutableDictionary dictionaryWithDictionary:object];
        }
    }
    
    if (!encDic) {return nil;}
    
    YLZRequestEncryptConfigKeys *configKeys = [self finalKeyConfigWithConfig:ylz_configKeys];
    
    NSMutableDictionary *encryptParam = [NSMutableDictionary dictionaryWithDictionary:encDic];
    [encryptParam addEntriesFromDictionary:extra];
    
    NSString *appId = [encryptParam objectForKey:configKeys.appIdKey];
    NSString *appSecret = [encryptParam objectForKey:configKeys.appSecretKey];
    NSString *signType = [encryptParam objectForKey:configKeys.signTypeKey];
    NSString *encryptType = [encryptParam objectForKey:configKeys.encryptTypeKey];
    NSString *encodeType = [encryptParam objectForKey:configKeys.encodeTypeKey];
    NSString *publickey = [encryptParam objectForKey:configKeys.asymEncryptPublickeyKey];
    NSArray *signBlackList = [encryptParam objectForKey:configKeys.signBlackListKey];
    NSMutableDictionary *decryptPropertyMapper = [NSMutableDictionary dictionaryWithDictionary:[encryptParam objectForKey:configKeys.encryptMapKey]];
    if (configKeys.encryptKey && configKeys.decryptKey) {
        [decryptPropertyMapper setObject:configKeys.decryptKey forKey:configKeys.encryptKey];
    }
    
    //??????
    for (NSString *oriKey in decryptPropertyMapper) {
        NSString *mapKey = [decryptPropertyMapper objectForKey:oriKey];
        
        NSString * encryptData = [encDic objectForKey:oriKey];
        
        if (!encryptData) {
            //??????????????????
            if ([encDic objectForKey:mapKey] == nil) {
                [encDic setObject:@"" forKey:mapKey];
            }
            continue;
        }
        id decryptParam = [self decryptData:encryptData appId:appId appSecret:appSecret encryptType:encryptType encodeType:encodeType];
        
        if (decryptParam != nil) {
            //????????????
            [encDic removeObjectForKey:oriKey];
            [encDic setObject:decryptParam forKey:mapKey];
        }else{
            //????????????
        }
    }
    /**
     ????????????
     */
    NSString *responseSign = [encDic objectForKey:configKeys.signKey];
    
    BOOL isCorrectSign = [YLZNetEncryptManager verifySign:responseSign withNetData:encDic withSecret:appSecret signType:signType blackList:signBlackList asymEncryptPublickey:publickey];
    [encDic setObject:@(isCorrectSign) forKey:configKeys.verifySignKey];
    
    return encDic;
}

+ (NSMutableDictionary *)encryptNetData:(NSDictionary *)param appId:(NSString *)appId appSecret:(NSString *)appSecret encryptType:(NSString *)encryptType signType:(NSString *)signType signPropertyKey:(NSString *)signKey signBlackList:(NSArray <NSString *> *)signBlackList encryptPropertyMapper:(NSDictionary *)encryptPropertyMapper {
    if (!param) {return nil;}
    NSMutableDictionary *reqParam = [NSMutableDictionary dictionaryWithDictionary:param];
    //??????
    NSString *sign = [YLZNetEncryptManager signNetData:param withSecret:appSecret signType:signType blackList:signBlackList asymEncryptPrivatekey:[YLZMSEncryptionConfig shareConfig].encryptConfig.sm2PrivateKey];
    if (sign.length) {
        [reqParam setObject:sign forKey:signKey];
    }
    //??????
    for (NSString *oriKey in encryptPropertyMapper) {
        NSString *mapKey = encryptPropertyMapper[oriKey];
        id paramObj = [reqParam objectForKey:oriKey];
        NSString *encodeType = [YLZMSEncryptionConfig shareConfig].encryptConfig.encodeType;
        NSString * encryptDataStr = [self encryptData:paramObj appId:appId appSecret:appSecret encryptType:encryptType encodeType:encodeType];
        if (encryptDataStr && encryptDataStr.length > 0) {
            [reqParam removeObjectForKey:oriKey];
            [reqParam setObject:encryptDataStr forKey:mapKey];
        }
    }
    return reqParam;
}

+ (NSString *)encryptData:(id)data appId:(NSString *)appId appSecret:(NSString *)appSecret encryptType:(NSString *)encryptType encodeType:(NSString *)encodeType {
    NSString * paramJsonString = nil;
    if ([data isKindOfClass:[NSDictionary class]]) {
        paramJsonString = [(NSDictionary *)data ylz_sortJsonString];
    } else if([data isKindOfClass:[NSString class]]) {
        paramJsonString = (NSString *)data;
    }
    if (!paramJsonString) {return nil;}
    //---????????????---//
    if ([@"AES" isEqualToString:encryptType]) {
        NSString * aesKey = [YLZSecKeyWrapper encryptUseAES:appSecret withKey:appId withIv:[YLZMSEncryptionConfig shareConfig].encryptConfig.aesIv withEncodeType:encodeType];
        NSString * encryptDataStr = [YLZSecKeyWrapper encryptUseAES:paramJsonString withKey:aesKey withIv:[YLZMSEncryptionConfig shareConfig].encryptConfig.aesIv withEncodeType:encodeType];
        return encryptDataStr;
    } else if ([@"SM4" isEqualToString:encryptType]) {
        NSString *sm4Key = [self sm4Content:appSecret key:appId encodeType:encodeType];
        NSString *encryptDataStr = [self sm4Content:paramJsonString key:sm4Key encodeType:encodeType];
        return encryptDataStr;
    } else {
#if DEBUG
        NSAssert([@"plain" isEqualToString:encryptType], @"????????????????????????[%@]",encryptType);
#endif
    }
    return nil;
}


+(NSString *)sm4Content:(NSString *)content key:(NSString *)key encodeType:(NSString *)encodeType
{
    NSData *appSecretData = [content dataUsingEncoding:NSUTF8StringEncoding];
    if ([encodeType isEqualToString:@"base64"]) {
        return  [[[YLZSMEncryption shared] sm4_encryptData:appSecretData withCipherKey:key] ylz_base64EncodedString];
    } else if ([encodeType isEqualToString:@"hex"]) {
        return  [[[[YLZSMEncryption shared] sm4_encryptData:appSecretData withCipherKey:key] ylz_hexadecimalString] uppercaseString];
    }
    return nil;
}

#pragma mark ----------------------------:: ?????? ::----------------------------

/**
 ???????????????.

 @Discussion ???????????????encryptType?????????????????????signType???????????????
 
 @return ??????????????????
 */
 +(NSMutableDictionary *)decryptNetData:(id)responseObj appId:(NSString *)appId appSecret:(NSString *)appSecret encryptType:(NSString *)encryptType signType:(NSString *)signType signPropertyKey:(NSString *)signKey signBlackList:(NSArray <NSString *> *)signBlackList decryptPropertyMapper:(NSDictionary *)decryptPropertyMapper {
     
    NSMutableDictionary * responseDic;
    
    if ([responseObj isKindOfClass:[NSDictionary class]]) {
        responseDic = [NSMutableDictionary dictionaryWithDictionary:responseObj];
    } else if([responseObj isKindOfClass:[NSString class]]) {
        NSDictionary * object = [NSJSONSerialization JSONObjectWithData:[responseObj dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingAllowFragments error:nil];
        if (object) {
            responseDic = [NSMutableDictionary dictionaryWithDictionary:object];
        }
    }
    if (!responseDic) {return nil;}
    //??????
    for (NSString *oriKey in decryptPropertyMapper) {
        NSString *mapKey = [decryptPropertyMapper objectForKey:oriKey];
        NSString * encryptData = [responseDic objectForKey:oriKey];
        if (!encryptData) {
            //??????????????????
            if ([responseDic objectForKey:mapKey] == nil) {
                [responseDic setObject:@"" forKey:mapKey];
            }
            continue;
        }
        NSString *encodeType = [YLZMSEncryptionConfig shareConfig].encryptConfig.encodeType;
        id decryptParam = [self decryptData:encryptData appId:appId appSecret:appSecret encryptType:encryptType encodeType:encodeType];
        if (decryptParam != nil) {
            //????????????
            [responseDic removeObjectForKey:oriKey];
            [responseDic setObject:decryptParam forKey:mapKey];
        }else{
            //????????????
        }
    }
    /**
     ????????????
     */
    YLZRequestEncryptConfigKeys *configKeys = ylz_defaultEncryptConfigKeys();
    NSString *responseSign = [responseDic objectForKey:signKey];
    BOOL isCorrectSign = [YLZNetEncryptManager verifySign:responseSign withNetData:responseDic withSecret:appSecret signType:signType blackList:signBlackList asymEncryptPublickey:[YLZMSEncryptionConfig shareConfig].encryptConfig.sm2PublicKey];
    [responseDic setObject:@(isCorrectSign) forKey:configKeys.verifySignKey];
    return responseDic;
}

+ (id)decryptData:(NSString *)encryptData appId:(NSString *)appId appSecret:(NSString *)appSecret encryptType:(NSString *)encryptType encodeType:(NSString *)encodeType
{
    NSDictionary* param = nil;
    NSString *decryptDataString = nil;
    if(encryptData && [encryptData isKindOfClass:[NSString class]] && ![@"" isEqualToString:encryptData]){
        //??????
        if ([@"AES" isEqualToString:encryptType]){
            //AES??????
    
            NSString * aesKey = [YLZSecKeyWrapper encryptUseAES:appSecret withKey:appId withIv:[YLZMSEncryptionConfig shareConfig].encryptConfig.aesIv withEncodeType:encodeType];
            decryptDataString = [YLZSecKeyWrapper decryptAESWrap:encryptData withKey:aesKey withIv:[YLZMSEncryptionConfig shareConfig].encryptConfig.aesIv withEncodeType:encodeType];

            param = [NSJSONSerialization JSONObjectWithData:[decryptDataString dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingAllowFragments error:nil];
            
        }else if ([@"SM4" isEqualToString:encryptType]){
            //SM4??????
            NSData *responseObjData = nil;

            if ([encodeType isEqualToString:@"base64"]) {
                responseObjData = [NSData ylz_dataFromHexadecimalString:encryptData];
            } else if ([encodeType isEqualToString:@"hex"]) {
                responseObjData = [NSData ylz_dataFromHexadecimalString:encryptData];
            }
            
            NSString *sm4Key = [self sm4Content:appSecret key:appId encodeType:encodeType];
            NSData *decryptedData = [[YLZSMEncryption shared] sm4_decryptData:responseObjData withCipherKey:sm4Key];
            decryptDataString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
            
            param = [NSJSONSerialization JSONObjectWithData:[decryptDataString dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingAllowFragments error:nil];
            
            
        } else if ([@"plain" isEqualToString:encryptType]) {
            //?????????
            decryptDataString = encryptData;
            
            param = [NSJSONSerialization JSONObjectWithData:[decryptDataString dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingAllowFragments error:nil];
            
        }
        
        if (param == nil && decryptDataString != nil) {
            //???????????? JSON text did not start with array or object and option to allow fragments not set.
            if ([decryptDataString hasPrefix:@"\""] && [decryptDataString hasSuffix:@"\""]) {
                //?????????
                decryptDataString = [decryptDataString substringWithRange:NSMakeRange(1, decryptDataString.length-2)];
            }
            return decryptDataString;
        }
        
    }else if([encryptData isKindOfClass:[NSDictionary class]]){
        
        param = (NSDictionary *)encryptData;
        
    }
    
    return param;
}


#pragma mark --------------------------:: ?????? ::--------------------------
/**
???????????????????????????

 @param secret ????????????
 @param signType ???????????????MD5/SM3???
 @param blackList ????????????key????????????
 @return ???????????????
 */
+(NSString *)signNetData:(NSDictionary *)param withSecret:(NSString *)secret signType:(NSString *)signType blackList:(NSArray<NSString *> *)blackList asymEncryptPrivatekey:(NSString *)privatekey
{
    if (!secret || !signType) {return nil;}
    
    NSString *sign = nil;
    
    NSString * sortString = [NSString stringWithFormat:@"%@&key=%@",[param ylz_signSortStringWithBlackList:blackList],secret];
    
    if ([@"SM3" isEqualToString:signType]) {
        
        sign = [[self sm3Hex:sortString] uppercaseString];

    }else if ([@"MD5" isEqualToString:signType]){
        
        sign = [[YLZSecKeyWrapper md5:sortString] uppercaseString];
        
    }else if ([@"SM2" isEqualToString:signType]) {
        
        sign = [[YLZSMEncryption shared] sm2_signPlainString:sortString withUID:[YLZMSEncryptionConfig shareConfig].encryptConfig.sm2Iv withPrivateKey:privatekey withEncyptType:[YLZMSEncryptionConfig shareConfig].encryptConfig.signEncodeType];
        
    }else if ([@"SHA256" isEqualToString:signType]){
        
        sign = [[[YLZSecKeyWrapper sha256:sortString] dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
        
    }
#ifdef DEBUG
//    YLZLog(@"?????????%@",[param ylz_sortJsonString]);
//    YLZLog(@"??????????????????%@",sortString);
//    YLZLog(@"%@????????????%@",signType,sign?:@"?????????????????????!");
#endif
    return sign;
}

/**????????????*/
+(BOOL)verifySign:(NSString *)sign withNetData:(NSDictionary *)data withSecret:(NSString *)secret signType:(NSString *)signType blackList:(NSArray<NSString *> *)blackList asymEncryptPublickey:(NSString *)publickey
{
    NSString * sortString = [NSString stringWithFormat:@"%@&key=%@",[data ylz_signSortStringWithBlackList:blackList],secret];

#ifdef DEBUG
//    YLZLog(@"???????????????????????????%s\n",[sortString UTF8String]);
#endif
    if ([@"SM2" isEqualToString:signType]){
        
        BOOL isPass = [[YLZSMEncryption shared] sm2_verifyWithPlainString:sortString withSigned:sign withUID:[YLZMSEncryptionConfig shareConfig].encryptConfig.sm2Iv withPublicKey:publickey withEncyptType:[YLZMSEncryptionConfig shareConfig].encryptConfig.signEncodeType];
        
        return isPass;
        
    } else if ([@"SM3" isEqualToString:signType]) {
        
        NSString *sign_new = [[self sm3Hex:sortString] uppercaseString];
        
        return [sign isEqualToString:sign_new];

    }else if ([@"MD5" isEqualToString:signType]){
        
        NSString * sign_new = [[YLZSecKeyWrapper md5:sortString] uppercaseString];
        
        return [sign isEqualToString:sign_new];
        
    }else if ([@"SHA256" isEqualToString:signType]){
        
        NSString * sign_new = [[[YLZSecKeyWrapper sha256:sortString] dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
        
        return [sign isEqualToString:sign_new];
        
    } else {
        YLZLog(@"----????????????[%@]?????????!----",signType);
    }
    return YES;
}

#pragma mark --------------------------:: ????????????????????????????????????????????????SM4?????????SM3????????? ::--------------------------
+(BOOL)verifySMAuthFilePath:(NSString *)filePath
{
    return [self verifySMAuthFilePath:filePath appId:nil appSecret:nil];
}

+(BOOL)verifySMAuthFilePath:(NSString *)filePath appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret
{
    return [self verifySMAuthFilePath:filePath appId:appId appSecret:appSecret smKey:[[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleIdentifier"] iv:YLZ_SMDefault_iv];
}


+(BOOL)verifySMAuthFilePath:(NSString *)filePath smKey:(NSString *)smKey iv:(NSString *)iv
{
    return [self verifySMAuthFilePath:filePath appId:nil appSecret:nil smKey:smKey iv:iv];
}

+(BOOL)verifySMAuthFilePath:(NSString *)filePath appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret smKey:(NSString *)smKey iv:(NSString *)iv
{
    return [self verifySMAuthFilePath:filePath appId:appId appSecret:appSecret version:nil smKey:smKey iv:iv];
}

+(BOOL)verifySMAuthFilePath:(NSString *)filePath appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret version:(nullable NSString *)version smKey:(NSString *)smKey iv:(NSString *)iv
{
    if(!filePath || filePath.length <= 0 || ![[NSFileManager defaultManager] fileExistsAtPath:filePath]){return NO;}
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    
    return [self verifySMAuthFileData:data appId:appId appSecret:appSecret version:version smKey:smKey iv:iv];
}

#pragma mark --------------------------:: ??????????????????????????????????????????SM4?????????SM3????????? ::--------------------------
+(BOOL)verifySMAuthFileData:(NSData *)data
{
    return [self verifySMAuthFileData:data appId:nil appSecret:nil];
}

+(BOOL)verifySMAuthFileData:(NSData *)data appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret
{
    return [self verifySMAuthFileData:data appId:appId appSecret:appSecret smKey:[[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleIdentifier"] iv:YLZ_SMDefault_iv];
}

+(BOOL)verifySMAuthFileData:(NSData *)data smKey:(NSString *)smKey iv:(NSString *)iv
{
    return [self verifySMAuthFileData:data appId:nil appSecret:nil smKey:smKey iv:iv];
}

+(BOOL)verifySMAuthFileData:(NSData *)data appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret smKey:(NSString *)smKey iv:(NSString *)iv
{
    return [self verifySMAuthFileData:data appId:appId appSecret:appSecret  version:nil smKey:smKey iv:iv];
}

+(BOOL)verifySMAuthFileData:(NSData *)data appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret version:(nullable NSString *)version smKey:(NSString *)smKey iv:(NSString *)iv
{
    if (!data || data.length <= 0) {return NO;}
    
    //sm4??????????????????
    YLZLog(@"????????????????????????");
    NSString *dataStr = [self removeSpaceAndNewline:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]];
    NSData *authFileSM4Data = [NSData ylz_dataFromHexadecimalString:dataStr];
    YLZLog(@"??????????????????: %@", dataStr);
    NSData *keyData = [smKey dataUsingEncoding:NSUTF8StringEncoding];
    NSString *keyHexStr = [[keyData ylz_hexadecimalString] uppercaseString];
    YLZLog(@"??????????????????");
    NSData *authFileData = [[YLZSMEncryption shared] sm4_decryptData:authFileSM4Data withCipherKey:keyHexStr];
    NSDictionary *authFileDic = (NSDictionary *)[self _ylz_dictionaryWithJSON:authFileData];
    YLZLog(@"????????????SM4???????????????: %@", authFileDic);
    
    if (!authFileDic || authFileDic.count <= 0) {
        YLZLog(@"????????????????????????: ??????????????????");
        return NO;
    }
    
    if (authFileDic[@"app_id"] && appId && ![appId isEqualToString:authFileDic[@"app_id"]]) {
        YLZLog(@"??????????????????????????? app_id?????????");
        return NO;
    }
    
    if (authFileDic[@"app_secret"] && appSecret && ![appSecret isEqualToString:authFileDic[@"app_secret"]]) {
        YLZLog(@"???????????????????????????app_secret?????????");
        return NO;
    }
    
    NSDictionary *infoDictionary = [[NSBundle mainBundle] infoDictionary];
    
    NSString *app_id = appId ?: authFileDic[@"app_id"];
    NSString *app_secret = appSecret ?: authFileDic[@"app_secret"];
    NSString *auth_file_code = authFileDic[@"auth_code"] ?: @"";
    NSString *app_name = [infoDictionary objectForKey:@"CFBundleDisplayName"];
    NSString *app_bundle_id = [infoDictionary objectForKey:@"CFBundleIdentifier"];
    NSString *app_version =  version ?: [infoDictionary objectForKey:@"CFBundleShortVersionString"];
    
    NSString *authCode = [NSString stringWithFormat:@"%@%@%@%@%@", app_id, app_name, app_bundle_id, app_version, app_secret];

    YLZLog(@"??????????????? SM3?????????: %@", authCode);
    
    NSString *authCodesm3DataHexStr = [[self sm3Hex:authCode] lowercaseString];
    YLZLog(@"?????????SM3????????????: %@", authCodesm3DataHexStr);
    
    YLZLog(@"??????????????????: %d", [[auth_file_code lowercaseString] isEqualToString:authCodesm3DataHexStr]);
    return [[auth_file_code lowercaseString] isEqualToString:authCodesm3DataHexStr];
}

#pragma mark -------------------Tool---------------------
+ (NSString *)removeSpaceAndNewline:(NSString *)str
{
    NSString *temp = [str stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString *text = [temp stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet ]];
    return text;
}

+ (NSDictionary *)_ylz_dictionaryWithJSON:(id)json {
    if (!json || json == (id)kCFNull) return nil;
    NSDictionary *dic = nil;
    NSData *jsonData = nil;
    if ([json isKindOfClass:[NSDictionary class]]) {
        dic = json;
    } else if ([json isKindOfClass:[NSString class]]) {
        jsonData = [(NSString *)json dataUsingEncoding : NSUTF8StringEncoding];
    } else if ([json isKindOfClass:[NSData class]]) {
        jsonData = json;
    }
    if (jsonData) {
        dic = [NSJSONSerialization JSONObjectWithData:jsonData options:kNilOptions error:NULL];
        if (![dic isKindOfClass:[NSDictionary class]]) dic = nil;
    }
    return dic;
}

+(NSString *)md5: (NSString *) inPutText
{
    const char *cStr = [inPutText UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5( cStr, (int)strlen(cStr), digest );
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
    [result appendFormat:@"%02x", digest[i]];
    
    return result;
}

/**
 SM3 ??????
 */
+(NSString *)sm3Hex:(NSString *)dataString
{
    NSData *data = [dataString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *sm3Data = [[YLZSMEncryption shared] sm3_hashWithPainData:data];
    NSString *sm3HexString = [sm3Data ylz_hexadecimalString];
    return sm3HexString;
}

/*
 * AES ??????
 * content ????????????????????????
 * return ?????????????????????
 */
+ (NSString *)encryptUseAES:(NSString *)content
{
    NSString *secret = [YLZSecKeyWrapper encryptUseAES:content withKey:[[NSBundle mainBundle] bundleIdentifier] withIv:[YLZMSEncryptionConfig shareConfig].encryptConfig.aesIv withEncodeType:[YLZMSEncryptionConfig shareConfig].encryptConfig.encodeType];
    return secret;
}

/*
 * AES ??????
 * content ???????????????
 * return ?????????????????????
 */
+ (NSString *)decryptUseAES:(NSString *)content
{
    NSString *secret = [YLZSecKeyWrapper decryptAESWrap:content withKey:[[NSBundle mainBundle] bundleIdentifier] withIv:[YLZMSEncryptionConfig shareConfig].encryptConfig.aesIv withEncodeType:[YLZMSEncryptionConfig shareConfig].encryptConfig.encodeType];
    return secret;
}

@end
