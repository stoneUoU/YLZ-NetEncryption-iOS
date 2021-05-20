//
//  YLZRequestEncryptConfigKeys.h
//  YLZ-NetEncryption-iOS
//
//  Created by stone on 2021/5/20.
//

NS_ASSUME_NONNULL_BEGIN

@interface YLZRequestEncryptConfigKeys : NSObject

/// 应⽤渠道编号key:
@property (nonatomic, copy) NSString *appIdKey;

/// 应⽤渠道秘钥key:
@property (nonatomic, copy) NSString *appSecretKey;

/// 签名算法类型key，支持方式：MD5、SM3、SM2、Plain:
@property (nonatomic, copy) NSString *signTypeKey;

/// 加密算法类型key，支持方式：AES、SM4、Plain:
@property (nonatomic, copy) NSString *encryptTypeKey;

/// 加解密编码类型key:
@property (nonatomic, copy) NSString *encodeTypeKey;

/// 签名key:
@property (nonatomic, copy) NSString *signKey;

/// 验签结果key，验签结果为值1或0:
@property (nonatomic, copy) NSString *verifySignKey;

/// 签名过滤字段数组key:
@property (nonatomic, copy) NSString *signBlackListKey;
/// 加密字段(明文)key，
@property (nonatomic, copy) NSString *decryptKey;
/// 解密字段(密文)key
@property (nonatomic, copy) NSString *encryptKey;
/// 非对称加解密算法公钥key
@property (nonatomic, copy) NSString *asymEncryptPublickeyKey;
/// 非对称加解密算法私钥key
@property (nonatomic, copy) NSString *asymEncryptPrivatekeyKey;
/// 加解密字段映射字典key，多个字段加解密时使用
@property (nonatomic, copy) NSString *encryptMapKey;

@end

/// 默认的请求 body 的 key
static YLZRequestEncryptConfigKeys *ylz_defaultEncryptConfigKeys() {
    YLZRequestEncryptConfigKeys *config = [[YLZRequestEncryptConfigKeys alloc] init];
    config.appIdKey = @"appId";
    config.appSecretKey = @"appSecret";
    config.signTypeKey = @"signType";
    config.encryptTypeKey = @"encType";
    config.encodeTypeKey = @"encodeType";
    config.signKey = @"signData";
    config.verifySignKey = @"isCorrectSign";
    config.signBlackListKey = @"signBlacklist";
    config.decryptKey = @"data";
    config.encryptKey = @"encData";
    config.asymEncryptPublickeyKey = @"asymEncryptPublickey";
    config.asymEncryptPrivatekeyKey = @"asymEncryptPrivatekey";
    config.encryptMapKey = @"encryptMap";
    return config;
}

NS_ASSUME_NONNULL_END
