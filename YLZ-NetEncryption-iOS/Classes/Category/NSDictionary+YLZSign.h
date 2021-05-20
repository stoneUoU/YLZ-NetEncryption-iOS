//
//  NSDictionary+YLZSign.h
//  YLZ-NetEncryption-iOS
//
//  Created by ljt on 19/5/14.
//  Copyright (c) 2015年 dev. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSDictionary(YLZSign)

-(NSString *)ylz_sortJsonString;

/**
 字典按参数名升序，对基础数据类型格式化处理，滤空操作，以"参数名=值&参数名=值&...&参数名=值"格式生成，可指定黑名单剔除不需要的数据

 @param blackList 需要剔除key的集合。
 @return 处理后的字符
 */
-(NSString *)ylz_signSortStringWithBlackList:(NSArray<NSString *> *)blackList;

@end

@interface NSArray(YLZSign)

-(NSString *)ylz_sortJsonString;

@end

@interface NSString(YLZSign)

-(NSString *)stringByReplacingEscapeCharacter;

@end
