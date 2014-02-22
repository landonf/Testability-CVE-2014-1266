//
//  libsecurity_ssl_bits.h
//  TestableSecurity
//
//  Created by Landon Fuller on 2/22/14.
//  Copyright (c) 2014 Plausible Labs Cooperative, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#define sslErrorLog(args...)        printf(args)

/* The size of of client- and server-generated random numbers in hello messages. */
#define SSL_CLIENT_SRVR_RAND_SIZE		32

/*
 * This is the buffer type used internally.
 */
typedef struct
{   size_t  length;
    uint8_t *data;
} SSLBuffer;

int SSLAllocBuffer(
                   SSLBuffer *buf,
                   size_t length);

int
SSLFreeBuffer(SSLBuffer *buf);

/* Public part of asymmetric key. */
typedef struct SSLPubKey
{
    CSSM_KEY key;
    CSSM_CSP_HANDLE csp;                /* may not be needed, we figure this
                                         * one out by trial&error, right? */
} SSLPubKey;

OSStatus SecKeyRawVerify(
                         SecKeyRef           key,
                         SecPadding          padding,
                         const uint8_t       *signedData,
                         size_t              signedDataLen,
                         const uint8_t       *sig,
                         size_t              sigLen);

typedef struct SSLContext {
    uint8_t             clientRandom[SSL_CLIENT_SRVR_RAND_SIZE];
    uint8_t             serverRandom[SSL_CLIENT_SRVR_RAND_SIZE];
    SSLPubKey           *peerPubKey;
} SSLContext;

OSStatus sslRawVerify(
                      SSLContext			*ctx,
                      SSLPubKey           *pubKey,
                      const uint8_t       *plainText,
                      size_t              plainTextLen,
                      const uint8_t       *sig,
                      size_t              sigLen);

/*
 * These numbers show up all over the place...might as well hard code 'em once.
 */
#define SSL_MD5_DIGEST_LEN      16
#define SSL_SHA1_DIGEST_LEN     20
#define SSL_SHA256_DIGEST_LEN	32
#define SSL_SHA384_DIGEST_LEN	48
#define SSL_MAX_DIGEST_LEN      48 /* >= SSL_MD5_DIGEST_LEN + SSL_SHA1_DIGEST_LEN */

#define MAX_MAC_PADDING         48	/* MD5 MAC padding size = 48 bytes */

extern const uint8_t SSLMACPad1[], SSLMACPad2[];

typedef int (*HashInit)(SSLBuffer *digestCtx);
typedef int (*HashUpdate)(SSLBuffer *digestCtx, const SSLBuffer *data);
/* HashFinal also does HashClose */
typedef int (*HashFinal)(SSLBuffer *digestCtx, SSLBuffer *digest);
typedef int (*HashClose)(SSLBuffer *digestCtx);
typedef int (*HashClone)(const SSLBuffer *src, SSLBuffer *dest);

typedef struct
{
    uint32_t    digestSize;
    uint32_t    macPadSize;
    uint32_t    contextSize;
    HashInit    init;
    HashUpdate  update;
    HashFinal   final;
    HashClose	close;
    HashClone   clone;
} HashReference;

extern const HashReference SSLHashNull;
extern const HashReference SSLHashMD5;
extern const HashReference SSLHashSHA1;
extern const HashReference SSLHashSHA256;
extern const HashReference SSLHashSHA384;

OSStatus
ReadyHash(const HashReference *ref, SSLBuffer *state);