//
//  NSData+YLZHexadecimal.h
//  YhPaymentAPP
//
//  Created by ljt on 2016/12/5.
//  Copyright © 2016年 jagtu. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (Hexadecimal)

//十六进制字符串转换成NSData
+ (NSData *)ylz_dataFromHexadecimalString:(NSString *)aString;

//NSData的十六进制的字符串
- (NSString *)ylz_hexadecimalString;

@end
