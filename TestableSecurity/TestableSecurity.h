//
//  TestableSecurity.h
//  TestableSecurity
//
//  Created by Landon Fuller on 2/22/14.
//  Copyright (c) 2014 Plausible Labs Cooperative, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#import "libsecurity_ssl_bits.h"

OSStatus
SSLVerifySignedServerKeyExchange(SSLContext *ctx, bool isRsa, SSLBuffer signedParams,
                                 uint8_t *signature, UInt16 signatureLen);