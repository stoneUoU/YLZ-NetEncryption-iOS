//
//  YLZMSEncryptionConfig.h
//  YLZ-NetEncryption-iOS
//
//  Created by stone on 2021/5/20.
//

#import "YLZMSEncryptionConfig.h"
#import "YLZRequestEncryptConfigKeys.h"

NS_ASSUME_NONNULL_BEGIN

@class YLZNetEncryptionConfig;

@interface YLZMSEncryptionConfig : NSObject

+ (instancetype)shareConfig;

+ (void)initRequestConfigWithSecret:(NSString *)secretString;

@property (nonatomic, strong) YLZNetEncryptionConfig *encryptConfig;

@end

@interface YLZNetEncryptionConfig : NSObject

@property (nonatomic, copy) NSString *aesIv;

// 加密的类型:
@property (nonatomic, copy) NSString *encodeType;

@property (nonatomic, copy) NSString *sm2Iv;

@property (nonatomic, copy) NSString *sm2PublicKey;

@property (nonatomic, copy) NSString *sm2PrivateKey;

// 加签的类型:
@property (nonatomic, copy) NSString *signEncodeType;

@end

NS_ASSUME_NONNULL_END

