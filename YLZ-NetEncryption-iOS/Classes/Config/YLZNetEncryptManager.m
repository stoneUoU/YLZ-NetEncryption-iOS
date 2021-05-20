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

#define YLZ_SMDefault_iv @"0102030405060708"
#define YLZ_SM2Default_iv @"1234567812345678"
#define YLZ_SM2Default_PublicKey @"044f1df6069a086ac4e1d1c4ad60a3ab26a19ba5fc97a45dedf386c7480dcab18fa745c3a0f6dba6ed6993d0367d9f6b12c06dc01d4079c9eda3f807e21f93edc6"
#define YLZ_SM2Default_PrivateKey @"25286c04e24bd1180f0283edb44075860b4f02f0a290e974575a133982fb9395"

#ifdef DEBUG
#define CHSLOG(FORMAT, ...) fprintf(stderr,"%s:%d\t%s\n",[[[NSString stringWithUTF8String:__FILE__] lastPathComponent] UTF8String], __LINE__, [[NSString stringWithFormat:FORMAT, ##__VA_ARGS__] UTF8String]);
#else
#define CHSLOG(...)
#endif

@implementation YLZNetEncryptManager

+ (YLZRequestEncryptConfigKeys)finalKeyConfigWithConfig:(YLZRequestEncryptConfigKeys)config {
    YLZRequestEncryptConfigKeys finalConfig;
    
    finalConfig.appIdKey  = config.appIdKey ?: ylz_defaultEncryptConfigKeys.appIdKey;
    finalConfig.appSecretKey = config.appSecretKey ?: ylz_defaultEncryptConfigKeys.appSecretKey;
    finalConfig.signTypeKey = config.signTypeKey ?: ylz_defaultEncryptConfigKeys.signTypeKey;
    finalConfig.encryptTypeKey = config.encryptTypeKey ?: ylz_defaultEncryptConfigKeys.encryptTypeKey;
    finalConfig.encodeTypeKey = config.encodeTypeKey ?: ylz_defaultEncryptConfigKeys.encodeTypeKey;
    finalConfig.signKey = config.signKey ?: ylz_defaultEncryptConfigKeys.signKey;
    finalConfig.verifySignKey = config.verifySignKey ?: ylz_defaultEncryptConfigKeys.verifySignKey;
    finalConfig.signBlackListKey = config.signBlackListKey ?: ylz_defaultEncryptConfigKeys.signBlackListKey;
    finalConfig.decryptKey = config.decryptKey ?: ylz_defaultEncryptConfigKeys.decryptKey;
    finalConfig.encryptKey = config.encryptKey ?: ylz_defaultEncryptConfigKeys.encryptKey;
    finalConfig.asymEncryptPublickeyKey = config.asymEncryptPublickeyKey ?: ylz_defaultEncryptConfigKeys.asymEncryptPublickeyKey;
    finalConfig.asymEncryptPrivatekeyKey = config.asymEncryptPrivatekeyKey ?: ylz_defaultEncryptConfigKeys.asymEncryptPrivatekeyKey;
    finalConfig.encryptMapKey = config.encryptMapKey ?: ylz_defaultEncryptConfigKeys.encryptMapKey;
    
    return finalConfig;
}

#pragma mark ----------------------------:: 加密 ::----------------------------

+(NSMutableDictionary *)encryptNetData:(NSDictionary *)param
{
    return [self encryptNetData:param extra:nil];
}

+(NSMutableDictionary *)encryptNetData:(NSDictionary *)param extra:(NSDictionary *)extra
{
    return [self encryptNetData:param withConfigKeys:ylz_defaultEncryptConfigKeys extra:extra];
}

/**
 加密、签名
 
 @Discussion  根据请求数据中对应的参数，加密相关数据并签名
 
 @param param 请求数据
 @param ylz_configKeys key说明
 @param extra 不包含在请求数据中的加密签名相关参数
 @return 加密后的数据
 */
+(NSMutableDictionary *)encryptNetData:(NSDictionary *)param withConfigKeys:(YLZRequestEncryptConfigKeys)ylz_configKeys extra:(NSDictionary *)extra
{
    
    if (!param) {return nil;}
    
    YLZRequestEncryptConfigKeys configKeys = [self finalKeyConfigWithConfig:ylz_configKeys];
    
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
    
    //签名
    NSString *sign = [YLZNetEncryptManager signNetData:param withSecret:appSecret signType:signType blackList:signBlackList asymEncryptPrivatekey:privatekey];
    if (sign.length) {
        
        [reqParam setObject:sign forKey:configKeys.signKey];
    }
    
    //加密
    for (NSString *oriKey in encryptPropertyMapper) {
        
        NSString *mapKey = encryptPropertyMapper[oriKey];
        
        id paramObj = [reqParam objectForKey:oriKey];
        
        NSString * encryptDataStr = [self encryptData:paramObj appId:appId appSecret:appSecret encryptType:encryptType encodeType:encodeType];
        if (encryptDataStr && encryptDataStr.length > 0) {
            //特别注意有可能oriKey==mapKey，因此先removeObjectForKey
            [reqParam removeObjectForKey:oriKey];
            [reqParam setObject:encryptDataStr forKey:mapKey];
        }
    }
    return reqParam;
}


#pragma mark ----------------------------:: 解密 ::----------------------------

+(NSMutableDictionary *)decryptNetData:(id)data
{
    return [self decryptNetData:data extra:nil];
}

+(NSMutableDictionary *)decryptNetData:(id)data extra:(NSDictionary * _Nullable)extra
{
    return [self decryptNetData:data withConfigKeys:ylz_defaultEncryptConfigKeys extra:extra];
}

/**
 解密、验签.

 @Discussion 解密数据，根据解密验签相关参数key说明，从数据中获取具体方式进行解密验签
 
 @param encData 数据，Json字符串或字典
 @param ylz_configKeys key说明
 @param extra 不包含在数据data中的解密验签相关参数
 @return 加密后的数据
 */
+(NSMutableDictionary *)decryptNetData:(id)encData withConfigKeys:(YLZRequestEncryptConfigKeys)ylz_configKeys extra:(NSDictionary *)extra
{
    
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
    
    YLZRequestEncryptConfigKeys configKeys = [self finalKeyConfigWithConfig:ylz_configKeys];
    
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
    
    //解密
    for (NSString *oriKey in decryptPropertyMapper) {
        NSString *mapKey = [decryptPropertyMapper objectForKey:oriKey];
        
        NSString * encryptData = [encDic objectForKey:oriKey];
        
        if (!encryptData) {
            //没有待解数据
            if ([encDic objectForKey:mapKey] == nil) {
                [encDic setObject:@"" forKey:mapKey];
            }
            continue;
        }
        id decryptParam = [self decryptData:encryptData appId:appId appSecret:appSecret encryptType:encryptType encodeType:encodeType];
        
        if (decryptParam != nil) {
            //解密成功
            [encDic removeObjectForKey:oriKey];
            [encDic setObject:decryptParam forKey:mapKey];
        }else{
            //解密失败
        }
    }
    
    /**
     验证签名
     */
    NSString *responseSign = [encDic objectForKey:configKeys.signKey];
    
    BOOL isCorrectSign = [YLZNetEncryptManager verifySign:responseSign withNetData:encDic withSecret:appSecret signType:signType blackList:signBlackList asymEncryptPublickey:publickey];
    [encDic setObject:isCorrectSign?@"1":@"0" forKey:configKeys.verifySignKey];
    
    return encDic;
}


#pragma mark --------------------------:: old ::--------------------------

+(NSMutableDictionary *)encryptNetData:(NSDictionary *)param appId:(NSString *)appId appSecret:(NSString *)appSecret encryptType:(NSString *)encryptType signType:(NSString *)signType signPropertyKey:(NSString *)signKey signBlackList:(NSArray <NSString *> *)signBlackList encryptPropertyMapper:(NSDictionary *)encryptPropertyMapper encodeType:(YLZEncryptionEncodeType)encodeType
{
    if (!param) {return nil;}
    
    NSMutableDictionary *reqParam = [NSMutableDictionary dictionaryWithDictionary:param];
    //签名
    NSString *sign = [YLZNetEncryptManager signNetData:param withSecret:appSecret signType:signType blackList:signBlackList asymEncryptPrivatekey:YLZ_SM2Default_PrivateKey];
    if (sign.length) {
        
        [reqParam setObject:sign forKey:signKey];
    }
    
    //加密
    for (NSString *oriKey in encryptPropertyMapper) {
        
        NSString *mapKey = encryptPropertyMapper[oriKey];
        
        id paramObj = [reqParam objectForKey:oriKey];
        
        NSString *encodeTypeAes = (encodeType == YLZEncryptionHexEncodeType)?YLZ_ENCRYPT_ENCODE_TYPE_HEX:((encodeType == YLZEncryptionBase64EncodeType)?YLZ_ENCRYPT_ENCODE_TYPE_BASE64:@"");
        NSString * encryptDataStr = [self encryptData:paramObj appId:appId appSecret:appSecret encryptType:encryptType encodeType:encodeTypeAes];
        if (encryptDataStr && encryptDataStr.length > 0) {
            //特别注意有可能oriKey==mapKey，因此先removeObjectForKey
            [reqParam removeObjectForKey:oriKey];
            [reqParam setObject:encryptDataStr forKey:mapKey];
        }
    }
    return reqParam;
    
}

+ (NSString *)encryptData:(id)data appId:(NSString *)appId appSecret:(NSString *)appSecret encryptType:(NSString *)encryptType encodeType:(NSString *)encodeType
{
    NSString * paramJsonString = nil;
    
    if ([data isKindOfClass:[NSDictionary class]]) {
        
        paramJsonString = [(NSDictionary *)data ylz_sortJsonString];
        
    }else if([data isKindOfClass:[NSString class]]){
        
        paramJsonString = (NSString *)data;
    }
    
    if (!paramJsonString) {return nil;}
    
    //---加密操作---//
    if ([@"AES" isEqualToString:encryptType]) {
        
        NSString * aesKey = [YLZSecKeyWrapper encryptUseAES:appSecret withKey:appId withIv:AES_IV withEncodeType:encodeType];
        NSString * encryptDataStr = [YLZSecKeyWrapper encryptUseAES:paramJsonString withKey:aesKey withIv:AES_IV withEncodeType:encodeType];
        
        return encryptDataStr;
        
    }else if ([@"SM4" isEqualToString:encryptType]){
        
        NSString *sm4Key = [self sm4Content:appSecret key:appId encodeType:encodeType];
        NSString *encryptDataStr = [self sm4Content:paramJsonString key:sm4Key encodeType:encodeType];
        
        return encryptDataStr;
        
    }else{
#if DEBUG
        NSAssert([@"plain" isEqualToString:encryptType], @"暂不支持加密方式[%@]",encryptType);
#endif
    }
    return nil;
}


+(NSString *)sm4Content:(NSString *)content key:(NSString *)key encodeType:(NSString *)encodeType
{
    NSData *appSecretData = [content dataUsingEncoding:NSUTF8StringEncoding];

    if ([encodeType isEqualToString:YLZ_ENCRYPT_ENCODE_TYPE_BASE64]) {
        
        
        return  [[[YLZSMEncryption shared] sm4_encryptData:appSecretData withCipherKey:key] ylz_base64EncodedString];
        
    }else if ([encodeType isEqualToString:YLZ_ENCRYPT_ENCODE_TYPE_HEX]){
        
        
        return  [[[[YLZSMEncryption shared] sm4_encryptData:appSecretData withCipherKey:key] ylz_hexadecimalString] uppercaseString];
    }
    
    return nil;
}

#pragma mark ----------------------------:: 解密 ::----------------------------

/**
 解密、验签.

 @Discussion 该方法根据encryptType解密数据，根据signType验证签名。
 
 @return 解密后的数据
 */
 +(NSMutableDictionary *)decryptNetData:(id)responseObj appId:(NSString *)appId appSecret:(NSString *)appSecret encryptType:(NSString *)encryptType signType:(NSString *)signType signPropertyKey:(NSString *)signKey signBlackList:(NSArray <NSString *> *)signBlackList decryptPropertyMapper:(NSDictionary *)decryptPropertyMapper encodeType:(YLZEncryptionEncodeType)encodeType
{
    NSMutableDictionary * responseDic;
    if ([responseObj isKindOfClass:[NSDictionary class]]) {
        
        responseDic = [NSMutableDictionary dictionaryWithDictionary:responseObj];
        
    }else if([responseObj isKindOfClass:[NSString class]]){
        
        NSDictionary * object = [NSJSONSerialization JSONObjectWithData:[responseObj dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingAllowFragments error:nil];
        if (object) {
            responseDic = [NSMutableDictionary dictionaryWithDictionary:object];
        }
    }
    
    if (!responseDic) {return nil;}
    
    //解密
    for (NSString *oriKey in decryptPropertyMapper) {
        NSString *mapKey = [decryptPropertyMapper objectForKey:oriKey];
        
        NSString * encryptData = [responseDic objectForKey:oriKey];
        if (!encryptData) {
            //没有待解数据
            if ([responseDic objectForKey:mapKey] == nil) {
                [responseDic setObject:@"" forKey:mapKey];
            }
            continue;
        }
        NSString *encodeTypeAes = (encodeType == YLZEncryptionHexEncodeType)?YLZ_ENCRYPT_ENCODE_TYPE_HEX:((encodeType == YLZEncryptionBase64EncodeType)?YLZ_ENCRYPT_ENCODE_TYPE_BASE64:@"");
        id decryptParam = [self decryptData:encryptData appId:appId appSecret:appSecret encryptType:encryptType encodeType:encodeTypeAes];
        
        if (decryptParam != nil) {
            //解密成功
            [responseDic removeObjectForKey:oriKey];
            [responseDic setObject:decryptParam forKey:mapKey];
        }else{
            //解密失败
        }
    }
    
    /**
     验证签名
     */
    NSString *responseSign = [responseDic objectForKey:signKey];
    
    BOOL isCorrectSign = [YLZNetEncryptManager verifySign:responseSign withNetData:responseDic withSecret:appSecret signType:signType blackList:signBlackList asymEncryptPublickey:YLZ_SM2Default_PublicKey];
    
    [responseDic setObject:@(isCorrectSign) forKey:@"isCorrectSign"];
    
    return responseDic;
}

+(id)decryptData:(NSString *)encryptData appId:(NSString *)appId appSecret:(NSString *)appSecret encryptType:(NSString *)encryptType encodeType:(NSString *)encodeType
{
    NSDictionary* param = nil;
    NSString *decryptDataString = nil;
    if(encryptData && [encryptData isKindOfClass:[NSString class]] && ![@"" isEqualToString:encryptData]){
        //解密
        if ([@"AES" isEqualToString:encryptType]){
            //AES解密
    
            NSString * aesKey = [YLZSecKeyWrapper encryptUseAES:appSecret withKey:appId withIv:AES_IV withEncodeType:encodeType];
            decryptDataString = [YLZSecKeyWrapper decryptAESWrap:encryptData withKey:aesKey withIv:AES_IV withEncodeType:encodeType];

            param = [NSJSONSerialization JSONObjectWithData:[decryptDataString dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingAllowFragments error:nil];
            
        }else if ([@"SM4" isEqualToString:encryptType]){
            //SM4解密
            NSData *responseObjData = nil;

            if ([encodeType isEqualToString:YLZ_ENCRYPT_ENCODE_TYPE_BASE64]) {
                
                responseObjData = [NSData ylz_dataFromHexadecimalString:encryptData];
                
            }else if ([encodeType isEqualToString:YLZ_ENCRYPT_ENCODE_TYPE_HEX]){
                
                responseObjData = [NSData ylz_dataFromHexadecimalString:encryptData];
            }
            
            NSString *sm4Key = [self sm4Content:appSecret key:appId encodeType:encodeType];
            NSData *decryptedData = [[YLZSMEncryption shared] sm4_decryptData:responseObjData withCipherKey:sm4Key];
            decryptDataString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
            
            param = [NSJSONSerialization JSONObjectWithData:[decryptDataString dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingAllowFragments error:nil];
            
            
        }else if([@"plain" isEqualToString:encryptType]){
            //未加密
            decryptDataString = encryptData;
            
            param = [NSJSONSerialization JSONObjectWithData:[decryptDataString dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingAllowFragments error:nil];
            
        }
        
        if (param == nil && decryptDataString != nil) {
            //解析失败 JSON text did not start with array or object and option to allow fragments not set.
            if ([decryptDataString hasPrefix:@"\""] && [decryptDataString hasSuffix:@"\""]) {
                //字符串
                decryptDataString = [decryptDataString substringWithRange:NSMakeRange(1, decryptDataString.length-2)];
            }
            return decryptDataString;
        }
        
    }else if([encryptData isKindOfClass:[NSDictionary class]]){
        
        param = (NSDictionary *)encryptData;
        
    }
    
    return param;
}


#pragma mark --------------------------:: 签名 ::--------------------------
/**
对字典数据进行签名

 @param secret 签名私钥
 @param signType 签名类型（MD5/SM3）
 @param blackList 需要剔除key的集合。
 @return 签名后数据
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
        
    }else if ([@"SM2" isEqualToString:signType]){
        
        sign = [[YLZSMEncryption shared] sm2_signPlainString:sortString withUID:YLZ_SM2Default_iv withPrivateKey:privatekey];
        
    }else if ([@"SHA256" isEqualToString:signType]){
        
        sign = [[[YLZSecKeyWrapper sha256:sortString] dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
        
    }
#ifdef DEBUG
//    CHSLOG(@"参数：%@",[param ylz_sortJsonString]);
//    CHSLOG(@"签名字符串：%@",sortString);
//    CHSLOG(@"%@签名值：%@",signType,sign?:@"签名方式不支持!");
#endif
    return sign;
}

/**验证签名*/
+(BOOL)verifySign:(NSString *)sign withNetData:(NSDictionary *)data withSecret:(NSString *)secret signType:(NSString *)signType blackList:(NSArray<NSString *> *)blackList asymEncryptPublickey:(NSString *)publickey
{
    NSString * sortString = [NSString stringWithFormat:@"%@&key=%@",[data ylz_signSortStringWithBlackList:blackList],secret];

#ifdef DEBUG
//    CHSLOG(@"待验证签名字符串：%s\n",[sortString UTF8String]);
#endif
    if ([@"SM2" isEqualToString:signType]){
        
        BOOL isPass = [[YLZSMEncryption shared] sm2_verifyWithPlainString:sortString withSigned:sign withUID:YLZ_SM2Default_iv withPublicKey:publickey];
        
        return isPass;
        
    }else if ([@"SM3" isEqualToString:signType]) {
        
        NSString *sign_new = [[self sm3Hex:sortString] uppercaseString];
        
        return [sign isEqualToString:sign_new];

    }else if ([@"MD5" isEqualToString:signType]){
        
        NSString * sign_new = [[YLZSecKeyWrapper md5:sortString] uppercaseString];
        
        return [sign isEqualToString:sign_new];
        
    }else if ([@"SHA256" isEqualToString:signType]){
        
        NSString * sign_new = [[[YLZSecKeyWrapper sha256:sortString] dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
        
        return [sign isEqualToString:sign_new];
        
    }else{
        CHSLOG(@"----签名方式[%@]不支持!----",signType);
    }
    return YES;
}

#pragma mark --------------------------:: 读取指定路径的验证授权文件，使用SM4解密，SM3验签。 ::--------------------------
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

#pragma mark --------------------------:: 读取指定路径的验证授权文件，使用SM2验签。 ::--------------------------
+(BOOL)verifySM2AuthFilePath:(NSString *)filePath appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret version:(nullable NSString *)version;
{
    return [self verifySM2AuthFilePath:filePath appId:appId appSecret:appSecret version:version sm2PublicKey:YLZ_SM2Default_PublicKey iv:YLZ_SM2Default_iv];
}
+(BOOL)verifySM2AuthFilePath:(NSString *)filePath appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret version:(nullable NSString *)version sm2PublicKey:(NSString *)sm2PublicKey iv:(NSString *)iv
{
    CHSLOG(@"开始检验授权文件");
    if(!filePath || filePath.length <= 0 || ![[NSFileManager defaultManager] fileExistsAtPath:filePath]){
        CHSLOG(@"校验失败：未找到授权文件");
        return NO;
    }
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    CHSLOG(@"授权文件解码");
    NSString *dataStr = [self removeSpaceAndNewline:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]];
    
    NSDictionary *authFileDic = (NSDictionary *)[self _ylz_dictionaryWithJSON:[NSData ylz_dataFromBase64String:dataStr]];
    CHSLOG(@"授权文件内容：%@", authFileDic);
    
    if (!authFileDic || authFileDic.count <= 0) {
        CHSLOG(@"授权文件校验错误: 授权文件为空");
        return NO;
    }
    
    if (authFileDic[@"app_id"] && appId && ![appId isEqualToString:authFileDic[@"app_id"]]) {
        CHSLOG(@"授权文件校验错误： app_id不匹配");
        return NO;
    }

    // ----------------APP信息----------------------
    NSDictionary *infoDictionary = [[NSBundle mainBundle] infoDictionary];
    NSString *app_name = [infoDictionary objectForKey:@"CFBundleDisplayName"];
    NSString *app_bundle_id = [infoDictionary objectForKey:@"CFBundleIdentifier"];
    NSString *app_version =  version ?: [infoDictionary objectForKey:@"CFBundleShortVersionString"];
    NSString *app_finger_mark = [NSString stringWithFormat:@"%@%@%@%@%@", appId, app_name, app_bundle_id, app_version, appSecret];
    app_finger_mark = [self md5:app_finger_mark];
    
    // ----------------授权文件信息----------------------
    NSString *auth_file_sign = authFileDic[@"sign"] ?: @"";
    NSString *auth_app_method = authFileDic[@"method"] ?: @"";
//    NSString *auth_app_channel = authFileDic[@"app_channel"] ?: @"";
//    NSString *auth_app_finger_mark = authFileDic[@"app_finger_mark"] ?: @"";
    
    NSString *signContent = [NSString stringWithFormat:@"%@%@%@%@", appId, app_name, app_finger_mark , auth_app_method];
    CHSLOG(@"授权码 SM2签名前： %@", signContent);
    
    CHSLOG(@"授权码 SM2验签结果： %d", [[YLZSMEncryption shared] sm2_verifyWithPlainString:signContent withSigned:auth_file_sign withUID:iv withPublicKey:sm2PublicKey]);
    return [[YLZSMEncryption shared] sm2_verifyWithPlainString:signContent withSigned:auth_file_sign withUID:iv withPublicKey:sm2PublicKey];
}



#pragma mark --------------------------:: 读取授权文件二进制数据，使用SM4解密，SM3验签。 ::--------------------------
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
    
    //sm4解密授权文件
    CHSLOG(@"开始校验授权文件");
    NSString *dataStr = [self removeSpaceAndNewline:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]];
    NSData *authFileSM4Data = [NSData ylz_dataFromHexadecimalString:dataStr];
    CHSLOG(@"授权文件内容: %@", dataStr);
    NSData *keyData = [smKey dataUsingEncoding:NSUTF8StringEncoding];
    NSString *keyHexStr = [[keyData ylz_hexadecimalString] uppercaseString];
    CHSLOG(@"授权文件解码");
    NSData *authFileData = [[YLZSMEncryption shared] sm4_decryptData:authFileSM4Data withCipherKey:keyHexStr];
    NSDictionary *authFileDic = (NSDictionary *)[self _ylz_dictionaryWithJSON:authFileData];
    CHSLOG(@"授权文件SM4解密后内容: %@", authFileDic);
    
    if (!authFileDic || authFileDic.count <= 0) {
        CHSLOG(@"授权文件校验错误: 授权文件为空");
        return NO;
    }
    
    if (authFileDic[@"app_id"] && appId && ![appId isEqualToString:authFileDic[@"app_id"]]) {
        CHSLOG(@"授权文件校验错误： app_id不匹配");
        return NO;
    }
    
    if (authFileDic[@"app_secret"] && appSecret && ![appSecret isEqualToString:authFileDic[@"app_secret"]]) {
        CHSLOG(@"授权文件校验错误：app_secret不匹配");
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

    CHSLOG(@"授权码内容 SM3签名前: %@", authCode);
    
    NSString *authCodesm3DataHexStr = [[self sm3Hex:authCode] lowercaseString];
    CHSLOG(@"授权码SM3签名内容: %@", authCodesm3DataHexStr);
    
    CHSLOG(@"签名校验结果: %d", [[auth_file_code lowercaseString] isEqualToString:authCodesm3DataHexStr]);
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
 SM3 加密
 */
+(NSString *)sm3Hex:(NSString *)dataString
{
    NSData *data = [dataString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *sm3Data = [[YLZSMEncryption shared] sm3_hashWithPainData:data];
    NSString *sm3HexString = [sm3Data ylz_hexadecimalString];
    return sm3HexString;
}

/*
 * AES 加密
 * content 待加密字符，使用
 * return 加密后的字符串
 */
+ (NSString *)encryptUseAES:(NSString *)content
{
    NSString *secret = [YLZSecKeyWrapper encryptUseAES:content withKey:[[NSBundle mainBundle] bundleIdentifier] withIv:AES_IV withEncodeType:ENCRYPT_ENCODE_TYPE_HEX];
    return secret;
}

/*
 * AES 解密
 * content 待解密字符
 * return 解密后的字符串
 */
+ (NSString *)decryptUseAES:(NSString *)content
{
    NSString *secret = [YLZSecKeyWrapper decryptAESWrap:content withKey:[[NSBundle mainBundle] bundleIdentifier] withIv:AES_IV withEncodeType:ENCRYPT_ENCODE_TYPE_HEX];
    return secret;
}

@end
