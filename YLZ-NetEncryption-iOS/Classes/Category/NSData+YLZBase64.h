//
//  NSData+YLZBase64.h
//  Base64
//
//  Created by Henry Yu on 2009/06/03.
//  Copyright 2010 Sevensoft Technology Co., Ltd.(http://www.sevenuc.com)
//  All rights reserved.
//
//  Permission is given to use this source code file, free of charge, in any
//  project, commercial or otherwise, entirely at your risk, with the condition
//  that any redistribution (in part or whole) of source code must retain
//  this copyright and permission notice. Attribution in compiled projects is
//  appreciated but not required.
//

#import <Foundation/Foundation.h>

void *YLZ_NewBase64Decode(
	const char *inputBuffer,
	size_t length,
	size_t *outputLength);

char *YLZ_NewBase64Encode(
	const void *inputBuffer,
	size_t length,
	bool separateLines,
	size_t *outputLength);

@interface NSData (Base64)

+ (NSData *)ylz_dataFromBase64String:(NSString *)aString;
- (NSString *)ylz_base64EncodedString;

@end
