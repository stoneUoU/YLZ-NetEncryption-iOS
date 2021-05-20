//
//  NSDictionary+YLZSign.m
//  YLZ-NetEncryption-iOS
//
//  Created by ljt on 19/5/14.
//  Copyright (c) 2019年 dev. All rights reserved.
//

#import "NSDictionary+YLZSign.h"
#import "NSData+YLZBase64.h"
#import "NSData+YLZHexadecimal.h"
#import "YLZSMEncryption.h"
#import "YLZSecKeyWrapper.h"

@implementation NSArray(YLZSign)

-(NSString *)ylz_sortJsonString
{
    NSMutableString * jsonString= [NSMutableString stringWithString:@"["];
    NSArray * valueArray = [self copy];
    if ([self count]>0 && [self[0] respondsToSelector:@selector(compare:)]) {
        valueArray = [self sortedArrayUsingSelector:@selector(compare:)];
    }
    for (id value in valueArray) {
        
//        if (value==nil) {
//            continue;//剔除空值字段
//        }
        NSString * valueString;
        if ([value isKindOfClass:[NSString class]]) {
            if ([@"" isEqualToString:value]) {
                continue;//剔除空值字段
            }
            valueString = [NSString stringWithFormat:@"\"%@\"",[value stringByReplacingEscapeCharacter]];
            
        }else if ([value isKindOfClass:[NSDictionary class]]) {
            valueString = [((NSDictionary *)value) ylz_sortJsonString];
        }else if ([value isKindOfClass:[NSArray class]]) {
//            if ([((NSArray *)value) count]==0) {
//                continue;//剔除空数组
//            }
            valueString = [((NSArray *)value) ylz_sortJsonString];
        }else if([value isKindOfClass:NSClassFromString(@"__NSCFBoolean")]){
            valueString = [value boolValue]?@"\"true\"":@"\"false\"";
        }else if([value isKindOfClass:[NSNumber class]]){
            
            double doubleValue = [value doubleValue];
            if (doubleValue - floor(doubleValue) < 0.00001) {
                valueString = [NSString stringWithFormat:@"\"%.f\"", doubleValue];
            }else {
                valueString = [NSString stringWithFormat:@"\"%.2f\"", doubleValue];
            }
            
        }else{
            //NSLog(@"剔除字节流等类型数组");
            continue;//剔除字节流等类型字段
        }
        [jsonString appendString:[NSString stringWithFormat:@"%@,",valueString]];
    }
    if (jsonString.length > 2) {
        [jsonString deleteCharactersInRange:NSMakeRange(jsonString.length-1, 1)];
    }
    [jsonString appendString:@"]"];
    return jsonString;
}


@end

@implementation NSString(YLZSign)

-(NSString *)stringByReplacingEscapeCharacter{
    NSString * selfStr = self;
    selfStr = [selfStr stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];//反斜杠
    selfStr = [selfStr stringByReplacingOccurrencesOfString:@"\r" withString:@"\\r"];//回车
    selfStr = [selfStr stringByReplacingOccurrencesOfString:@"\n" withString:@"\\n"];//换行
    selfStr = [selfStr stringByReplacingOccurrencesOfString:@"\0" withString:@"\\0"];//空字符(NULL)
    selfStr = [selfStr stringByReplacingOccurrencesOfString:@"\f" withString:@"\\f"];//换页
    selfStr = [selfStr stringByReplacingOccurrencesOfString:@"\t" withString:@"\\t"];//水平制表符
    selfStr = [selfStr stringByReplacingOccurrencesOfString:@"\b" withString:@"\\b"];//退格
    selfStr = [selfStr stringByReplacingOccurrencesOfString:@"\a" withString:@"\\a"];//Sound alert
    selfStr = [selfStr stringByReplacingOccurrencesOfString:@"\v" withString:@"\\v"];//垂直制表符
//    selfStr = [selfStr stringByReplacingOccurrencesOfString:@"\?" withString:@"\\?"];//问号
    selfStr = [selfStr stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];//双引号
    selfStr = [selfStr stringByReplacingOccurrencesOfString:@"\'" withString:@"\\'"];//单引号
    return selfStr;
}

@end


@implementation NSDictionary(YLZSign)

-(NSString *)ylz_sortJsonString
{
    NSMutableString * jsonString;
    jsonString = [NSMutableString stringWithString:@"{"];
    if (self) {
        NSArray * keys = [self.allKeys sortedArrayUsingSelector:@selector(compare:)];

        for (NSString * key in keys) {
            
            id value = self[key];

//            if (value==nil) {
//                continue;//剔除空对象
//            }
            NSString * valueString;
            if ([value isKindOfClass:[NSString class]]) {
                if ([@"" isEqualToString:value]) {
                    continue;//剔除空值字段
                }
                valueString = [NSString stringWithFormat:@"\"%@\"",[value stringByReplacingEscapeCharacter]];
                
            }else if ([value isKindOfClass:[NSDictionary class]]) {

                valueString = [((NSDictionary *)value) ylz_sortJsonString];
                
            }else if ([value isKindOfClass:[NSArray class]]) {
//                if ([((NSArray *)value) count]==0) {
//                    continue;//剔除空数组
//                }
                valueString = [((NSArray *)value) ylz_sortJsonString];
            }else if([value isKindOfClass:NSClassFromString(@"__NSCFBoolean")]){
                
                valueString = [value boolValue]?@"\"true\"":@"\"false\"";
                
            }else if([value isKindOfClass:[NSNumber class]]){
                
                double doubleValue = [value doubleValue];
                if (doubleValue - floor(doubleValue) < 0.00001) {
                    valueString = [NSString stringWithFormat:@"\"%.f\"", doubleValue];
                }else {
                    valueString = [NSString stringWithFormat:@"\"%.2f\"", doubleValue];
                }
                
            }else{
                //NSLog(@"剔除字节流：%@",key);
                continue;//剔除字节流等类型字段
            }
            [jsonString appendString:[NSString stringWithFormat:@"\"%@\":%@,",key,valueString]];
        }
        if (jsonString.length > 2) {
            [jsonString deleteCharactersInRange:NSMakeRange(jsonString.length-1, 1)];
        }
    }
    [jsonString appendString:@"}"];
    return jsonString;
}

-(NSString *)ylz_signSortStringWithBlackList:(NSArray<NSString *> *)blackList
{
    NSMutableString * sortStr = nil;
    //按照参数名升序,以"参数名=值&参数名=值&...&参数名=值"格式生成,字符串尾部包含”&”字符,并拼接上key=你的密钥
    if (self && self.count > 0) {
        sortStr = [NSMutableString string];
        NSArray * keys = [self.allKeys sortedArrayUsingSelector:@selector(compare:)];
        for (NSString * key in keys) {
            if ([blackList containsObject:key]) {
                //NSLog(@"剔除需忽略字段:%@",key);
                continue;//剔除忽略字段
            }
            id value = self[key];

//            if (value==nil) {
//                continue;//剔除空对象
//            }
            NSString * valueString;
            if ([value isKindOfClass:[NSString class]]) {
                if ([@"" isEqualToString:value]) {
                    continue;//剔除空值字段
                }
                valueString = (NSString *)[value stringByReplacingEscapeCharacter];//?
                
            }else if ([value isKindOfClass:[NSDictionary class]]) {
                
                valueString = [((NSDictionary *)value) ylz_sortJsonString];
                
            }else if ([value isKindOfClass:[NSArray class]]) {
//                if ([((NSArray *)value) count]==0) {
//                    continue;//剔除空数组
//                }
                valueString = [((NSArray *)value) ylz_sortJsonString];
            }else if([value isKindOfClass:NSClassFromString(@"__NSCFBoolean")]){
                
                valueString = [value boolValue]?@"true":@"false";
                
            }else if([value isKindOfClass:[NSNumber class]]){
                
                double doubleValue = [value doubleValue];
                if (doubleValue - floor(doubleValue) < 0.00001) {
                    valueString = [NSString stringWithFormat:@"%.f", doubleValue];
                }else {
                    valueString = [NSString stringWithFormat:@"%.2f", doubleValue];
                }
                
            }else{
                continue;//剔除字节流等类型字段
            }
            [sortStr appendString:[NSString stringWithFormat:@"%@=%@&",key,valueString]];
        }
        if (sortStr.length > 2) {
            [sortStr deleteCharactersInRange:NSMakeRange(sortStr.length-1, 1)];
        }
    }
    return sortStr;
}

@end

