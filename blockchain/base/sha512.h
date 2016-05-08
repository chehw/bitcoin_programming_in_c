#ifndef _SHA512_H_
#define _SHA512_H_

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct sha512_ctx
{
	uint64_t s[8];
	unsigned char buf[128];
	size_t bytes;
}sha512_ctx_t;

void sha512_init(sha512_ctx_t * sha);
void sha512_update(sha512_ctx_t * sha, const void * data, size_t len);
void sha512_final(sha512_ctx_t * sha, unsigned char hash[64]);


#ifdef __cplusplus
}
#endif
#endif
