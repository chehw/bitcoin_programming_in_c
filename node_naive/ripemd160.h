#ifndef _RIPEMD160_H_
#define _RIPEMD160_H_

#include <stdint.h>
#include <stdlib.h>

typedef struct ripemd160_ctx
{
	uint32_t s[5];
	unsigned char buf[64];
	size_t bytes;
}ripemd160_ctx_t;


#ifdef __cplusplus
extern "C" {
#endif

void ripemd160_init(ripemd160_ctx_t * ripemd);
void ripemd160_update(ripemd160_ctx_t * ripemd, const unsigned char * data, size_t len);
void ripemd160_final(ripemd160_ctx_t * ripemd, unsigned char hash[20]);

#ifdef __cplusplus
}
#endif
#endif
