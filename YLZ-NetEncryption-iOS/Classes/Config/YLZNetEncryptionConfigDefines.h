//
//  YLZNetEncryptionConfigDefines.h
//  YLZ-NetEncryption-iOS
//
//  Created by Jagtu on 2019/10/9.
//

#ifndef YLZNetEncryptionConfigDefines_h
#define YLZNetEncryptionConfigDefines_h

/// 存放请求中的用于加密签名所需的 key 字符串
typedef struct  _YLZRequestEncryptConfigKeys {
    /// 应⽤渠道编号key
    NSString *appIdKey;
    /// 应⽤渠道秘钥key
    NSString *appSecretKey;
    /// 签名算法类型key，支持方式：MD5、SM3、SM2、Plain
    NSString *signTypeKey;
    /// 加密算法类型key，支持方式：AES、SM4、Plain
    NSString *encryptTypeKey;
    /// 加解密编码类型key
    NSString *encodeTypeKey;
    /// 签名key
    NSString *signKey;
    /// 验签结果key，验签结果为值1或0
    NSString *verifySignKey;
    /// 签名过滤字段数组key
    NSString *signBlackListKey;
    /// 加密字段(明文)key，
    NSString *decryptKey;
    /// 解密字段(密文)key
    NSString *encryptKey;
    /// 非对称加解密算法公钥key
    NSString *asymEncryptPublickeyKey;
    /// 非对称加解密算法私钥key
    NSString *asymEncryptPrivatekeyKey;
    /// 加解密字段映射字典key，多个字段加解密时使用
    NSString *encryptMapKey;
    
} YLZRequestEncryptConfigKeys;

/// 默认配置
static YLZRequestEncryptConfigKeys ylz_defaultEncryptConfigKeys = {@"appId", @"appSecret", @"signType", @"encType", @"encodeType", @"signData", @"isCorrectSign", @"signBlacklist", @"data", @"encData", @"asymEncryptPublickey", @"asymEncryptPrivatekey", @"encryptMap"};


#define YLZ_ENCRYPT_ENCODE_TYPE_BASE64 @"base64"
#define YLZ_ENCRYPT_ENCODE_TYPE_HEX @"hex"


#endif /* YLZNetEncryptionConfigDefines_h */
