/*
 * hmac_sha256.c
 * 
 * Copyright 2016 Che Hongwei <htc.chehw@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation 
 * files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, 
 * publish, distribute, sublicense, and/or sell copies of the Software, 
 * and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR 
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "hmac_sha512.h"

#define HMAC_I_PADDING_WORD ((uint32_t)0x36363636)
#define HMAC_O_PADDING_WORD ((uint32_t)0x5c5c5c5c)



static inline void sha512(const unsigned char * data, size_t len, unsigned char to[HMAC_SHA512_HASH_SIZE])
{
	sha512_ctx_t ctx;
	sha512_init(&ctx);
	sha512_update(&ctx, data, len);	
	sha512_final(&ctx, to);
}

void hmac_sha512_init(hmac_sha512_ctx_t * ctx, const unsigned char * key, size_t key_len)
{
#define KEY_PADDING_SIZE (HMAC_SHA512_BLOCK_SIZE / sizeof(uint32_t))
	uint32_t key_padding[KEY_PADDING_SIZE];
	unsigned int i;
	sha512_init(&ctx->outer);
	sha512_init(&ctx->inner);
	
	
	if(key_len <= HMAC_SHA512_BLOCK_SIZE)
	{
		memcpy(key_padding, key, key_len);
		if(key_len < HMAC_SHA512_BLOCK_SIZE)
			memset(((unsigned char *)key_padding) + key_len, 0, HMAC_SHA512_BLOCK_SIZE - key_len);
	}else
	{
		sha512(key, key_len, (unsigned char *)&key_padding[0]);
		memset(((unsigned char *)key_padding) + HMAC_SHA512_HASH_SIZE, 0, HMAC_SHA512_BLOCK_SIZE - HMAC_SHA512_HASH_SIZE);
	}
	
	for(i = 0; i < KEY_PADDING_SIZE; ++i)
		key_padding[i] ^= HMAC_O_PADDING_WORD;
	
	sha512_update(&ctx->outer, (unsigned char *)key_padding, HMAC_SHA512_BLOCK_SIZE);
	
	for(i = 0; i < KEY_PADDING_SIZE; ++i)
		key_padding[i] ^= HMAC_O_PADDING_WORD ^ HMAC_I_PADDING_WORD;
	sha512_update(&ctx->inner, (unsigned char *)key_padding, HMAC_SHA512_BLOCK_SIZE);	
#undef KEY_PADDING_SIZE	
}

void hmac_sha512_update(hmac_sha512_ctx_t * ctx, const unsigned char * data, size_t len)
{
	sha512_update(&ctx->inner, data, len);
}

void hmac_sha512_final(hmac_sha512_ctx_t * ctx, unsigned char to[HMAC_SHA512_HASH_SIZE])
{
	unsigned char hash[HMAC_SHA512_HASH_SIZE];
	sha512_final(&ctx->inner, hash);
	sha512_update(&ctx->outer, hash, HMAC_SHA512_HASH_SIZE);
	sha512_final(&ctx->outer, to);
}



#undef HMAC_I_PADDING_WORD // 0x36363636
#undef HMAC_O_PADDING_WORD // 0x5c5c5c5c

