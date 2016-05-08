#ifndef _HMAC_SHA256_H_
#define _HMAC_SHA256_H_

#include "sha256.h"

#ifdef __cplusplus
extern "C" {
#endif


#define HMAC_SHA256_BLOCK_SIZE 64
#define HMAC_SHA256_HASH_SIZE 32

typedef struct hmac_sha256_ctx
{
	sha256_ctx_t outer;
	sha256_ctx_t inner;	
}hmac_sha256_ctx_t;



void hmac_sha256_init(hmac_sha256_ctx_t * ctx, const unsigned char * key, size_t key_len);
void hmac_sha256_update(hmac_sha256_ctx_t * ctx, const unsigned char * data, size_t len);
void hmac_sha256_final(hmac_sha256_ctx_t * ctx, unsigned char to[HMAC_SHA256_HASH_SIZE]);

#ifdef __cplusplus
}
#endif


#endif
