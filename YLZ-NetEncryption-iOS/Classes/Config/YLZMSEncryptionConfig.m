//
//  YLZMSEncryptionConfig.m
//  YLZ-NetEncryption-iOS
//
//  Created by stone on 2021/5/20.
//

#import "YLZMSEncryptionConfig.h"
#import <YYKit/YYKit.h>

@implementation YLZMSEncryptionConfig

/**
 通用
 */
 static YLZMSEncryptionConfig *_instance = nil;

+ (instancetype)shareConfig {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _instance = [[YLZMSEncryptionConfig alloc] init];
    });
    return _instance;
}

/** 重写单例对象的allocWithZone方法, 防止单例对象被重复创建 */
+ (instancetype)allocWithZone:(struct _NSZone *)zone
{
    if (_instance) {
        return _instance;
    }
    return [super allocWithZone:zone];
}

- (instancetype)init
{
    if (self = [super init]) {
    }
    return self;
}

/**
 * 初始化请求配置，启动APP时调用，SDK也将初步检查当前接入商户APP的合法性
 * @param secretString 应用授权秘钥
 */
+ (void)initRequestConfigWithSecret:(NSString *)secretString {
    YLZNetEncryptionConfig *_encryptConfig = [YLZNetEncryptionConfig modelWithJSON:secretString];
    [[YLZMSEncryptionConfig shareConfig] registerEncryptConfig:_encryptConfig];
}


/**
 *  注册接口参数配置，未设置的属性将使用默认值填充
 *  @param encryptConfig 配置参数
 */
- (void)registerEncryptConfig:(YLZNetEncryptionConfig *)encryptConfig
{
    self.encryptConfig = encryptConfig;
}


@end

@implementation YLZNetEncryptionConfig

@end
