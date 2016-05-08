#ifndef _HMAC_SHA512_H_
#define _HMAC_SHA256_H_

#include "sha512.h"

#ifdef __cplusplus
extern "C" {
#endif


#define HMAC_SHA512_BLOCK_SIZE 128
#define HMAC_SHA512_HASH_SIZE 64

typedef struct hmac_sha512_ctx
{
	sha512_ctx_t outer;
	sha512_ctx_t inner;	
}hmac_sha512_ctx_t;



void hmac_sha512_init(hmac_sha512_ctx_t * ctx, const unsigned char * key, size_t key_len);
void hmac_sha512_update(hmac_sha512_ctx_t * ctx, const unsigned char * data, size_t len);
void hmac_sha512_final(hmac_sha512_ctx_t * ctx, unsigned char to[HMAC_SHA512_HASH_SIZE]);

#ifdef __cplusplus
}
#endif


#endif
