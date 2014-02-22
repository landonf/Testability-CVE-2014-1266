//
//  TestableSecurityTests.m
//  TestableSecurityTests
//
//  Created by Landon Fuller on 2/22/14.
//  Copyright (c) 2014 Plausible Labs Cooperative, Inc. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "TestableSecurity.h"

/*
OSStatus
SSLVerifySignedServerKeyExchange(SSLContext *ctx, bool isRsa, SSLBuffer signedParams,
                                 uint8_t *signature, UInt16 signatureLen);
*/

@interface TestableSecurityTests : XCTestCase @end

@implementation TestableSecurityTests {
    SSLContext _ctx;
}

- (void) setUp {
    memset(_ctx.clientRandom, 'A', sizeof(_ctx.clientRandom));
    memset(_ctx.serverRandom, 'B', sizeof(_ctx.serverRandom));
}

- (void) tearDown {
    [super tearDown];
}


/* Verify that a bogus signature does not validate */
- (void) testVerifyRSASignature {
    SSLBuffer signedParams;
    SSLAllocBuffer(&signedParams, 32);
    uint8_t badSignature[128];
    
    memset(badSignature, 0, sizeof(badSignature));
    OSStatus err;
    err = SSLVerifySignedServerKeyExchange(&_ctx, true, signedParams, badSignature, sizeof(badSignature));
    XCTAssertNotEqual(err, 0, @"SSLVerifySignedServerKeyExchange() returned success on a completely bogus signature");
}

@end
