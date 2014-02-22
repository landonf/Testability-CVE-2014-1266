//
//  libsecurity_ssl_bits.m
//  TestableSecurity
//
//  Created by Landon Fuller on 2/22/14.
//  Copyright (c) 2014 Plausible Labs Cooperative, Inc. All rights reserved.
//

#import "libsecurity_ssl_bits.h"

int SSLAllocBuffer(
                   SSLBuffer *buf,
                   size_t length)
{
	buf->data = (uint8_t *)malloc(length);
	if(buf->data == NULL) {
        sslErrorLog("SSLAllocBuffer: NULL buf!\n");
        check(0);
		buf->length = 0;
		return -1;
	}
    buf->length = length;
    return 0;
}

int
SSLFreeBuffer(SSLBuffer *buf)
{
	if(buf == NULL) {
		sslErrorLog("SSLFreeBuffer: NULL buf!\n");
        check(0);
		return -1;
	}
    free(buf->data);
    buf->data = NULL;
    buf->length = 0;
    return 0;
}

/*
 * Wrapper for HashReference.init.
 */
OSStatus
ReadyHash(const HashReference *ref, SSLBuffer *state)
{
	OSStatus      err;
    if ((err = SSLAllocBuffer(state, ref->contextSize)))
        return err;
    return ref->init(state);
}


/*
 * Convert SSLPrivKey/SSLPubKey types to a platform SecKeyRef
 * (currently a no-op)
 */
#define SECKEYREF(sslkey) ((SecKeyRef)sslkey)

OSStatus sslRawVerify(
                      SSLContext			*ctx,
                      SSLPubKey           *pubKey,
                      const uint8_t       *plainText,
                      size_t              plainTextLen,
                      const uint8_t       *sig,
                      size_t              sigLen)         // available
{
#if 0
	RSAStatus rsaStatus;
    
	rsaStatus = RSA_SigVerify(&pubKey->rsaKey,
                              RP_PKCS1,
                              plainText,
                              plainTextLen,
                              sig,
                              sigLen);
    
	return rsaStatus ? rsaStatusToSSL(rsaStatus) : errSecSuccess;
#else
	OSStatus status = SecKeyRawVerify(SECKEYREF(pubKey), kSecPaddingPKCS1,
                                      plainText, plainTextLen, sig, sigLen);
    
	if (status) {
		sslErrorLog("sslRawVerify: SecKeyRawVerify failed (error %d)\n", (int) status);
	}
    
	return status;
#endif
}


#define DIGEST_PRINT		0
#if		DIGEST_PRINT
#define dgprintf(s)	printf s
#else
#define dgprintf(s)
#endif

const uint8_t SSLMACPad1[MAX_MAC_PADDING] =
{
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36
};

const uint8_t SSLMACPad2[MAX_MAC_PADDING] =
{
	0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,
	0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,
	0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,
	0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,
	0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,
	0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C,0x5C
};

/*** NULL ***/
static int HashNullInit(SSLBuffer *digestCtx) {
	return 0;
}
static int HashNullUpdate(SSLBuffer *digestCtx, const SSLBuffer *data) {
	return 0;
}
static int HashNullFinal(SSLBuffer *digestCtx, SSLBuffer *digest) {
	return 0;
}
static int HashNullClose(SSLBuffer *digestCtx) {
	return 0;
}
static int HashNullClone(const SSLBuffer *src, SSLBuffer *dest) {
	return 0;
}

#ifdef KERNEL

// Kernel based implementation
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccmd5.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <AssertMacros.h>

static int ccHashInit(const struct ccdigest_info *di, SSLBuffer *digestCtx)
{
    ccdigest_ctx_t ctx = (ccdigest_ctx_t)(struct ccdigest_ctx *)digestCtx->data;
	check(digestCtx->length >= ccdigest_di_size(di));
    ccdigest_init(di, ctx);
    return 0;
}

static int ccHashUpdate(const struct ccdigest_info *di, SSLBuffer *digestCtx, const SSLBuffer *data)
{
    /* 64 bits cast: safe, SSL records are always smaller than 2^32 bytes */
    ccdigest_ctx_t ctx = (ccdigest_ctx_t)(struct ccdigest_ctx *)digestCtx->data;
	check(digestCtx->length >= ccdigest_di_size(di));
    ccdigest_update(di, ctx, data->length, data->data);
    return 0;
}

static int ccHashFinal(const struct ccdigest_info *di, SSLBuffer *digestCtx, SSLBuffer *digest)
{
    ccdigest_ctx_t ctx = (ccdigest_ctx_t)(struct ccdigest_ctx *)digestCtx->data;
	check(digestCtx->length >= ccdigest_di_size(di));
    check(digest->length >= di->output_size);
    ccdigest_final(di, ctx, digest->data);
    digest->length = di->output_size;
    return 0;
}

static int ccHashClose(const struct ccdigest_info *di, SSLBuffer *digestCtx)
{
	check(digestCtx->length >= ccdigest_di_size(di));
    return 0;
}

static int ccHashClone(const struct ccdigest_info *di, const SSLBuffer *src, SSLBuffer *dst)
{
	check(src->length >= ccdigest_di_size(di));
	check(dst->length >= ccdigest_di_size(di));
	memcpy(dst->data, src->data, ccdigest_di_size(di));
	return 0;
    
}

#define SSL_MD5_DIGEST_LENGTH (CCMD5_OUTPUT_SIZE)
#define SSL_SHA1_DIGEST_LENGTH (CCSHA1_OUTPUT_SIZE)
#define SSL_SHA256_DIGEST_LENGTH (CCSHA256_OUTPUT_SIZE)
#define SSL_SHA384_DIGEST_LENGTH (CCSHA384_OUTPUT_SIZE)

#define SSL_MD5_CONTEXT_SIZE (ccdigest_ctx_size(CCMD5_STATE_SIZE, CCMD5_BLOCK_SIZE))
#define SSL_SHA1_CONTEXT_SIZE (ccdigest_ctx_size(CCSHA1_STATE_SIZE, CCSHA1_BLOCK_SIZE))
#define SSL_SHA256_CONTEXT_SIZE (ccdigest_ctx_size(CCSHA256_STATE_SIZE, CCSHA256_BLOCK_SIZE))
#define SSL_SHA384_CONTEXT_SIZE (ccdigest_ctx_size(CCSHA512_STATE_SIZE, CCSHA512_BLOCK_SIZE))

#define SSL_SHA256_BLOCK_BYTES CCSHA256_BLOCK_SIZE
#define SSL_SHA384_BLOCK_BYTES CCSHA512_BLOCK_SIZE

/*** MD5 ***/
static int HashMD5Init(SSLBuffer *digestCtx)
{
    return ccHashInit(ccmd5_di(), digestCtx);
}

static int HashMD5Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
    return ccHashUpdate(ccmd5_di(), digestCtx, data);
}

static int HashMD5Final(SSLBuffer *digestCtx, SSLBuffer *digest)
{
    return ccHashFinal(ccmd5_di(), digestCtx, digest);
}

static int HashMD5Close(SSLBuffer *digestCtx)
{
    return ccHashClose(ccmd5_di(), digestCtx);
}

static int HashMD5Clone(const SSLBuffer *src, SSLBuffer *dst)
{
	return ccHashClone(ccmd5_di(), src, dst);
}

/*** SHA1 ***/
static int HashSHA1Init(SSLBuffer *digestCtx)
{
    return ccHashInit(ccsha1_di(), digestCtx);
}

static int HashSHA1Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
    return ccHashUpdate(ccsha1_di(), digestCtx, data);
}

static int HashSHA1Final(SSLBuffer *digestCtx, SSLBuffer *digest)
{
    return ccHashFinal(ccsha1_di(), digestCtx, digest);
}

static int HashSHA1Close(SSLBuffer *digestCtx)
{
    return ccHashClose(ccsha1_di(), digestCtx);}

static int HashSHA1Clone(const SSLBuffer *src, SSLBuffer *dst)
{
	return ccHashClone(ccsha1_di(), src, dst);
}

/*** SHA256 ***/
static int HashSHA256Init(SSLBuffer *digestCtx)
{
    return ccHashInit(ccsha256_di(), digestCtx);
}

static int HashSHA256Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
    return ccHashUpdate(ccsha256_di(), digestCtx, data);
}

static int HashSHA256Final(SSLBuffer *digestCtx, SSLBuffer *digest)
{
    return ccHashFinal(ccsha256_di(), digestCtx, digest);
}

static int HashSHA256Close(SSLBuffer *digestCtx)
{
	return ccHashClose(ccsha256_di(), digestCtx);
}

static int HashSHA256Clone(const SSLBuffer *src, SSLBuffer *dst)
{
	return ccHashClone(ccsha256_di(), src, dst);
}

/*** SHA384 ***/
static int HashSHA384Init(SSLBuffer *digestCtx)
{
    return ccHashInit(ccsha384_di(), digestCtx);
}

static int HashSHA384Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
    return ccHashUpdate(ccsha384_di(), digestCtx, data);
}

static int HashSHA384Final(SSLBuffer *digestCtx, SSLBuffer *digest)
{
    return ccHashFinal(ccsha384_di(), digestCtx, digest);
}

static int HashSHA384Close(SSLBuffer *digestCtx)
{
	return ccHashClose(ccsha384_di(), digestCtx);
}

static int HashSHA384Clone(const SSLBuffer *src, SSLBuffer *dst)
{
	return ccHashClone(ccsha384_di(), src, dst);
}

#else

// CommonCrypto based implementation
#include <CommonCrypto/CommonDigest.h>
#include <assert.h>

#define SSL_MD5_DIGEST_LENGTH    CC_MD5_DIGEST_LENGTH
#define SSL_SHA1_DIGEST_LENGTH   CC_SHA1_DIGEST_LENGTH
#define SSL_SHA256_DIGEST_LENGTH CC_SHA256_DIGEST_LENGTH
#define SSL_SHA384_DIGEST_LENGTH CC_SHA384_DIGEST_LENGTH

#define SSL_MD5_CONTEXT_SIZE    (sizeof(CC_MD5_CTX))
#define SSL_SHA1_CONTEXT_SIZE   (sizeof(CC_SHA1_CTX))
#define SSL_SHA256_CONTEXT_SIZE (sizeof(CC_SHA256_CTX))
#define SSL_SHA384_CONTEXT_SIZE (sizeof(CC_SHA512_CTX))

#define SSL_SHA256_BLOCK_BYTES CC_SHA256_BLOCK_BYTES
#define SSL_SHA384_BLOCK_BYTES CC_SHA512_BLOCK_BYTES

/*** MD5 ***/
static int HashMD5Init(SSLBuffer *digestCtx)
{
	assert(digestCtx->length >= sizeof(CC_MD5_CTX));
	CC_MD5_CTX *ctx = (CC_MD5_CTX *)digestCtx->data;
	CC_MD5_Init(ctx);
	dgprintf(("###HashMD5Init  ctx %p\n", ctx));
    return 0;
}

static int HashMD5Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
    /* 64 bits cast: safe, SSL records are always smaller than 2^32 bytes */
	assert(digestCtx->length >= sizeof(CC_MD5_CTX));
	CC_MD5_CTX *ctx = (CC_MD5_CTX *)digestCtx->data;
	CC_MD5_Update(ctx, data->data, (CC_LONG)data->length);
    return 0;
}

static int HashMD5Final(SSLBuffer *digestCtx, SSLBuffer *digest)
{
	assert(digestCtx->length >= sizeof(CC_MD5_CTX));
	CC_MD5_CTX *ctx = (CC_MD5_CTX *)digestCtx->data;
	dgprintf(("###HashMD5Final  ctx %p\n", ctx));
	assert(digest->length >= CC_MD5_DIGEST_LENGTH);
	//if (digest->length < CC_MD5_DIGEST_LENGTH)
	//	return errSSLCrypto;
	CC_MD5_Final(digest->data, ctx);
	digest->length = CC_MD5_DIGEST_LENGTH;
    return 0;
}

static int HashMD5Close(SSLBuffer *digestCtx)
{
	assert(digestCtx->length >= sizeof(CC_MD5_CTX));
    return 0;
}

static int HashMD5Clone(const SSLBuffer *src, SSLBuffer *dst)
{
	CC_MD5_CTX *srcCtx;
	CC_MD5_CTX *dstCtx;
    
	assert(src->length >= sizeof(CC_MD5_CTX));
	assert(dst->length >= sizeof(CC_MD5_CTX));
    
	srcCtx = (CC_MD5_CTX *)src->data;
	dstCtx = (CC_MD5_CTX *)dst->data;
	dgprintf(("###HashMD5Clone  srcCtx %p  dstCtx %p\n", srcCtx, dstCtx));
    
	memcpy(dstCtx, srcCtx, sizeof(CC_MD5_CTX));
	return 0;
}

/*** SHA1 ***/
static int HashSHA1Init(SSLBuffer *digestCtx)
{
	assert(digestCtx->length >= sizeof(CC_SHA1_CTX));
	CC_SHA1_CTX *ctx = (CC_SHA1_CTX *)digestCtx->data;
	CC_SHA1_Init(ctx);
	dgprintf(("###HashSHA1Init  ctx %p\n", ctx));
    return 0;
}

static int HashSHA1Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
    /* 64 bits cast: safe, SSL records are always smaller than 2^32 bytes */
	assert(digestCtx->length >= sizeof(CC_SHA1_CTX));
	CC_SHA1_CTX *ctx = (CC_SHA1_CTX *)digestCtx->data;
	CC_SHA1_Update(ctx, data->data, (CC_LONG)data->length);
    return 0;
}

static int HashSHA1Final(SSLBuffer *digestCtx, SSLBuffer *digest)
{
	assert(digestCtx->length >= sizeof(CC_SHA1_CTX));
	CC_SHA1_CTX *ctx = (CC_SHA1_CTX *)digestCtx->data;
	dgprintf(("###HashSHA1Final  ctx %p\n", ctx));
	assert(digest->length >= CC_SHA1_DIGEST_LENGTH);
	//if (digest->length < CC_SHA1_DIGEST_LENGTH)
	//	return errSSLCrypto;
	CC_SHA1_Final(digest->data, ctx);
	digest->length = CC_SHA1_DIGEST_LENGTH;
    return 0;
}

static int HashSHA1Close(SSLBuffer *digestCtx)
{
	assert(digestCtx->length >= sizeof(CC_SHA1_CTX));
    return 0;
}

static int HashSHA1Clone(const SSLBuffer *src, SSLBuffer *dst)
{
	CC_SHA1_CTX *srcCtx;
	CC_SHA1_CTX *dstCtx;
    
	assert(src->length >= sizeof(CC_SHA1_CTX));
	assert(dst->length >= sizeof(CC_SHA1_CTX));
    
	srcCtx = (CC_SHA1_CTX *)src->data;
	dstCtx = (CC_SHA1_CTX *)dst->data;
	dgprintf(("###HashSHA1Clone  srcCtx %p  dstCtx %p\n", srcCtx, dstCtx));
    
	memcpy(dstCtx, srcCtx, sizeof(CC_SHA1_CTX));
	return 0;
}

/*** SHA256 ***/
static int HashSHA256Init(SSLBuffer *digestCtx)
{
	assert(digestCtx->length >= sizeof(CC_SHA256_CTX));
	CC_SHA256_CTX *ctx = (CC_SHA256_CTX *)digestCtx->data;
	CC_SHA256_Init(ctx);
	dgprintf(("###HashSHA256Init  ctx %p\n", ctx));
    return 0;
}

static int HashSHA256Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
    /* 64 bits cast: safe, SSL records are always smaller than 2^32 bytes */
    assert(digestCtx->length >= sizeof(CC_SHA256_CTX));
	CC_SHA256_CTX *ctx = (CC_SHA256_CTX *)digestCtx->data;
	CC_SHA256_Update(ctx, data->data, (CC_LONG)data->length);
    return 0;
}

static int HashSHA256Final(SSLBuffer *digestCtx, SSLBuffer *digest)
{
	assert(digestCtx->length >= sizeof(CC_SHA256_CTX));
	CC_SHA256_CTX *ctx = (CC_SHA256_CTX *)digestCtx->data;
	dgprintf(("###HashSHA256Final  ctx %p\n", ctx));
	assert(digest->length >= CC_SHA256_DIGEST_LENGTH);
	//if (digest->length < CC_SHA256_DIGEST_LENGTH)
	//	return errSSLCrypto;
	CC_SHA256_Final(digest->data, ctx);
	digest->length = CC_SHA256_DIGEST_LENGTH;
    return 0;
}

static int HashSHA256Close(SSLBuffer *digestCtx)
{
	assert(digestCtx->length >= sizeof(CC_SHA256_CTX));
    return 0;
}

static int HashSHA256Clone(const SSLBuffer *src, SSLBuffer *dst)
{
	CC_SHA256_CTX *srcCtx;
	CC_SHA256_CTX *dstCtx;
    
	assert(src->length >= sizeof(CC_SHA256_CTX));
	assert(dst->length >= sizeof(CC_SHA256_CTX));
    
	srcCtx = (CC_SHA256_CTX *)src->data;
	dstCtx = (CC_SHA256_CTX *)dst->data;
	dgprintf(("###HashSHA256Clone  srcCtx %p  dstCtx %p\n", srcCtx, dstCtx));
    
	memcpy(dstCtx, srcCtx, sizeof(CC_SHA256_CTX));
	return 0;
}

/*** SHA384 ***/
static int HashSHA384Init(SSLBuffer *digestCtx)
{
	assert(digestCtx->length >= sizeof(CC_SHA512_CTX));
	CC_SHA512_CTX *ctx = (CC_SHA512_CTX *)digestCtx->data;
	CC_SHA384_Init(ctx);
	dgprintf(("###HashSHA384Init  ctx %p\n", ctx));
    return 0;
}

static int HashSHA384Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
    /* 64 bits cast: safe, SSL records are always smaller than 2^32 bytes */
    assert(digestCtx->length >= sizeof(CC_SHA512_CTX));
	CC_SHA512_CTX *ctx = (CC_SHA512_CTX *)digestCtx->data;
	CC_SHA384_Update(ctx, data->data, (CC_LONG)data->length);
    return 0;
}

static int HashSHA384Final(SSLBuffer *digestCtx, SSLBuffer *digest)
{
	assert(digestCtx->length >= sizeof(CC_SHA512_CTX));
	CC_SHA512_CTX *ctx = (CC_SHA512_CTX *)digestCtx->data;
	dgprintf(("###HashSHA384Final  ctx %p\n", ctx));
	assert(digest->length >= CC_SHA384_DIGEST_LENGTH);
	//if (digest->length < CC_SHA384_DIGEST_LENGTH)
	//	return errSSLCrypto;
	CC_SHA384_Final(digest->data, ctx);
	digest->length = CC_SHA384_DIGEST_LENGTH;
    return 0;
}

static int HashSHA384Close(SSLBuffer *digestCtx)
{
	assert(digestCtx->length >= sizeof(CC_SHA512_CTX));
    return 0;
}

static int HashSHA384Clone(const SSLBuffer *src, SSLBuffer *dst)
{
	CC_SHA512_CTX *srcCtx;
	CC_SHA512_CTX *dstCtx;
    
	assert(src->length >= sizeof(CC_SHA512_CTX));
	assert(dst->length >= sizeof(CC_SHA512_CTX));
    
	srcCtx = (CC_SHA512_CTX *)src->data;
	dstCtx = (CC_SHA512_CTX *)dst->data;
	dgprintf(("###HashSHA384Clone  srcCtx %p  dstCtx %p\n", srcCtx, dstCtx));
    
	memcpy(dstCtx, srcCtx, sizeof(CC_SHA512_CTX));
	return 0;
}

#endif

/*
 * These are the handles by which the bulk of digesting work
 * is done.
 */
const HashReference SSLHashNull =
{
    0,
    0,
    0,
    HashNullInit,
    HashNullUpdate,
    HashNullFinal,
    HashNullClose,
    HashNullClone
};

const HashReference SSLHashMD5 =
{
    SSL_MD5_DIGEST_LENGTH,
    48,
    SSL_MD5_CONTEXT_SIZE,
    HashMD5Init,
    HashMD5Update,
    HashMD5Final,
    HashMD5Close,
    HashMD5Clone
};

const HashReference SSLHashSHA1 =
{
    SSL_SHA1_DIGEST_LENGTH,
    40,
    SSL_SHA1_CONTEXT_SIZE,
    HashSHA1Init,
    HashSHA1Update,
    HashSHA1Final,
    HashSHA1Close,
    HashSHA1Clone
};

const HashReference SSLHashSHA256 =
{
    SSL_SHA256_DIGEST_LENGTH,
    SSL_SHA256_BLOCK_BYTES,
    SSL_SHA256_CONTEXT_SIZE,
    HashSHA256Init,
    HashSHA256Update,
    HashSHA256Final,
    HashSHA256Close,
    HashSHA256Clone
};

const HashReference SSLHashSHA384 =
{
    SSL_SHA384_DIGEST_LENGTH,
    SSL_SHA384_BLOCK_BYTES,
    SSL_SHA384_CONTEXT_SIZE,
    HashSHA384Init,
    HashSHA384Update,
    HashSHA384Final,
    HashSHA384Close,
    HashSHA384Clone
};