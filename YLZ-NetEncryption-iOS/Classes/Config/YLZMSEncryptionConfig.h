//
//  YLZMSEncryptionConfig.h
//  YLZ-NetEncryption-iOS
//
//  Created by stone on 2021/5/20.
//

#import "YLZMSEncryptionConfig.h"
#import "YLZNetEncryptionConfigDefines.h"

NS_ASSUME_NONNULL_BEGIN

@class YLZNetEncryptionConfig;

@interface YLZMSEncryptionConfig : NSObject

+ (instancetype)shareConfig;

+ (void)initRequestConfigWithSecret:(NSString *)secretString;

@property (nonatomic, strong) YLZNetEncryptionConfig *encryptConfig;

@end

@interface YLZNetEncryptionConfig : NSObject

@property (nonatomic, copy) NSString *aesIv;

@property (nonatomic, copy) NSString *encodeType;

@end

NS_ASSUME_NONNULL_END
