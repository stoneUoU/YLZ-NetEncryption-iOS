//
//  YLZNetEncryptManager.h
//  YLZ-NetEncryption-iOS
//
//  Created by cy on 2018/12/7.
//

#import <Foundation/Foundation.h>
#import "YLZRequestEncryptConfigKeys.h"

NS_ASSUME_NONNULL_BEGIN

@interface YLZNetEncryptManager : NSObject



/**
 获取默认设置
 */
+ (YLZRequestEncryptConfigKeys *)finalKeyConfigWithConfig:(YLZRequestEncryptConfigKeys *)config;

#pragma mark ----------------------------:: 加密 ::----------------------------

+ (NSMutableDictionary *)encryptNetData:(NSDictionary *)param appId:(NSString *)appId appSecret:(NSString *)appSecret encryptType:(NSString *)encryptType signType:(NSString *)signType signPropertyKey:(NSString *)signKey signBlackList:(NSArray <NSString *> *)signBlackList encryptPropertyMapper:(NSDictionary *)encryptPropertyMapper;

/**
 加密、签名
 
 @Discussion  根据请求数据中对应的参数，加密相关数据并签名
 
 @param param 请求数据
 @param configKeys 加密签名相关参数key说明，以便从请求数据中获取具体值
 @param extraEncryptParam 不包含在请求数据中的加密签名相关参数
 @return 加密后的数据
 */
+ (NSMutableDictionary *)encryptNetData:(NSDictionary *)param withConfigKeys:(YLZRequestEncryptConfigKeys *)configKeys extra:(NSDictionary * _Nullable)extraEncryptParam;

/**
加密、签名
 
 @Discussion  根据请求数据中对应的参数，加密相关数据并签名

@param param 请求数据
@param extraEncryptParam 不包含在请求数据中的加密签名相关参数
@return 加密后的数据
*/
+(NSMutableDictionary *)encryptNetData:(NSDictionary *)param extra:(NSDictionary * _Nullable)extraEncryptParam;

/**
加密、签名

@Discussion  加密相关数据并签名

@param param 请求数据，加密签名相关参数按默认key从请求数据中获取
@return 加密后的数据
*/
+(NSMutableDictionary *)encryptNetData:(NSDictionary *)param;

#pragma mark ----------------------------:: 解密 ::----------------------------

/**
 解密、验签.

 @Discussion 解密数据，根据解密验签相关参数key说明，从数据中获取具体方式进行解密验签
 
 @param encData 数据，Json字符串或字典
 @param configKeys key说明
 @param extraEncryptParam 不包含在数据data中的解密验签相关参数
 @return 加密后的数据
 */
+(NSMutableDictionary *)decryptNetData:(id)encData withConfigKeys:(YLZRequestEncryptConfigKeys *)configKeys extra:(NSDictionary * _Nullable)extraEncryptParam;

/**
 解密、验签.
 
 @Discussion 解密数据，根据解密验签相关参数key说明，从数据中获取具体方式进行解密验签
 
 @param encData 数据，Json字符串或字典
 @param extraEncryptParam 不包含在数据data中的解密验签相关参数
 @return 加密后的数据
 */
+(NSMutableDictionary *)decryptNetData:(id)encData extra:(NSDictionary * _Nullable)extraEncryptParam;

/**
 解密、验签.
 
 @Discussion 解密数据，根据解密验签相关参数key说明，从数据中获取具体方式进行解密验签
 
 @param encData 数据，Json字符串或字典，解密验签相关参数按默认key从数据中获取
 @return 加密后的数据
 */
+(NSMutableDictionary *)decryptNetData:(id)encData;

/**
 解密、验签.

 @Discussion 该方法根据encryptType解密数据，根据signType验证签名。
 
 @return 解密后的数据
 */
+(NSMutableDictionary *)decryptNetData:(id)responseObj appId:(NSString *)appId appSecret:(NSString *)appSecret encryptType:(NSString *)encryptType signType:(NSString *)signType signPropertyKey:(NSString *)signKey signBlackList:(NSArray <NSString *> *)signBlackList decryptPropertyMapper:(NSDictionary *)decryptPropertyMapper;

#pragma mark --------------------------:: 签名 ::--------------------------
/**
对字典数据进行签名

 @param secret 签名私钥
 @param signType 签名类型（MD5/SM3）
 @param blackList 需要剔除key的集合。
 @return 签名后数据，不支持的签名方式默认返回nil
 */
+(NSString *)signNetData:(NSDictionary *)data withSecret:(NSString *)secret signType:(NSString *)signType blackList:(NSArray<NSString *> *)blackList asymEncryptPrivatekey:(NSString *)privatekey;

/**
 * 验证签名
 * @return 返回签名是否正确，不支持的签名方式默认返回YES
 */
+(BOOL)verifySign:(NSString *)sign withNetData:(NSDictionary *)data withSecret:(NSString *)secret signType:(NSString *)signType blackList:(NSArray<NSString *> *)blackList asymEncryptPublickey:(NSString *)publickey;



#pragma mark --------------------------:: 读取指定路径的验证授权文件，使用SM4解密，SM3验签。 ::--------------------------
/**
 验证授权文件，使用SM4解密，SM3验签。
 
 @param filePath 授权文件地址
 @return 是否验证成功
 */
+(BOOL)verifySMAuthFilePath:(NSString *)filePath;

/**
 验证授权文件，使用SM4解密，SM3验签。
 
 @param filePath 授权文件地址
 @param smKey sm4的key值
 @param iv sm4的iv值
 @return 是否验证成功
 */
+(BOOL)verifySMAuthFilePath:(NSString *)filePath smKey:(NSString *)smKey iv:(NSString *)iv;

/**
 验证授权文件，使用SM4解密，SM3验签。

 @param filePath 授权文件地址
 @param appId 授权应用编号
 @param appSecret 授权应用密钥
 @return 是否验证成功
 */
+(BOOL)verifySMAuthFilePath:(NSString *)filePath appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret;

/**
 验证授权文件，使用SM4解密，SM3验签。

 @param filePath 授权文件地址
 @param appId 授权应用编号
 @param appSecret 授权应用密钥
 @param smKey sm4的key值
 @param iv sm4的iv值
 @return 是否验证成功
 */
+(BOOL)verifySMAuthFilePath:(NSString *)filePath appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret smKey:(NSString *)smKey iv:(NSString *)iv;

/**
 验证授权文件，使用SM4解密，SM3验签。
 
 @param filePath 授权文件地址
 @param appId 授权应用编号
 @param appSecret 授权应用密钥
 @param smKey sm4的key值
 @param iv sm4的iv值
 @param version 授权的版本
 @return 是否验证成功
 */
+(BOOL)verifySMAuthFilePath:(NSString *)filePath appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret version:(nullable NSString *)version smKey:(NSString *)smKey iv:(NSString *)iv;

#pragma mark --------------------------:: 读取授权文件二进制数据，使用SM4解密，SM3验签。 ::--------------------------
/**
 验证授权文件，使用SM4解密，SM3验签。
 
 @param data 授权文件二进制数据
 @return 是否验证成功
 */
+(BOOL)verifySMAuthFileData:(NSData *)data;

/**
 验证授权文件，使用SM4解密，SM3验签。
 
 @param data 授权文件二进制数据
 @param smKey sm4的key值
 @param iv sm4的iv值
 @return 是否验证成功
 */
+(BOOL)verifySMAuthFileData:(NSData *)data smKey:(NSString *)smKey iv:(NSString *)iv;

/**
 验证授权文件，使用SM4解密，SM3验签。

 @param data 授权文件二进制数据
 @param appId 授权应用编号
 @param appSecret 授权应用密钥
 @return 是否验证成功
 */
+(BOOL)verifySMAuthFileData:(NSData *)data appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret;


/**
 验证授权文件，使用SM4解密，SM3验签。
 
 @param data 授权文件二进制数据
 @param appId 授权应用编号
 @param appSecret 授权应用密钥
 @param smKey sm4的key值
 @param iv sm4的iv值
 @return 是否验证成功
 */
+(BOOL)verifySMAuthFileData:(NSData *)data appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret smKey:(NSString *)smKey iv:(NSString *)iv;

/**
 验证授权文件，使用SM4解密，SM3验签。

 @param data 授权文件二进制数据
 @param appId 授权应用编号
 @param appSecret 授权应用密钥
 @param version 授权的版本
 @param smKey sm4的key值
 @param iv sm4的iv值
 @return 是否验证成功
 */
+(BOOL)verifySMAuthFileData:(NSData *)data appId:(nullable NSString *)appId appSecret:(nullable NSString *)appSecret version:(nullable NSString *)version smKey:(NSString *)smKey iv:(NSString *)iv;

/**
  加密：   暴露出去给别的APP使用
 @param data 授权文件二进制数据
 @param appId 授权应用编号
 @param appSecret 授权应用密钥
 */
+ (NSString *)encryptData:(id)data appId:(NSString *)appId appSecret:(NSString *)appSecret encryptType:(NSString *)encryptType encodeType:(NSString *)encodeType;

/**
  解密：   暴露出去给别的APP使用
 @param encryptData 授权文件二进制数据
 @param appId 授权应用编号
 @param appSecret 授权应用密钥
 */

+ (id)decryptData:(NSString *)encryptData appId:(NSString *)appId appSecret:(NSString *)appSecret encryptType:(NSString *)encryptType encodeType:(NSString *)encodeType;

/**
 MD3 加密
 */
+(NSString *)md5:(NSString *)dataString;

/**
 SM3 加密
 */
+(NSString *)sm3Hex:(NSString *)dataString;



/*
 * AES 加密
 * content 待加密字符，使用
 * return 加密后的字符串
 */
+ (NSString *)encryptUseAES:(NSString *)content;

/*
 * AES 解密
 * content 待解密字符
 * return 解密后的字符串
 */
+ (NSString *)decryptUseAES:(NSString *)content;

@end

NS_ASSUME_NONNULL_END
