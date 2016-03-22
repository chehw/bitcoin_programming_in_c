/*
 * chutil.c
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


#include "chutil.h"
#include <string.h>
#include <errno.h>

#include <fcntl.h>

#include "common.h"
#include "sha256.h"
#include "ripemd160.h"


static const char _hex[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
static const char _HEX[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

							
static const char _b64[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
							'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
							'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
							'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
							'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
							'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
							'w', 'x', 'y', 'z', '0', '1', '2', '3',
							'4', '5', '6', '7', '8', '9', '+', '/'
							};


static const unsigned char _hex_digits[256] ={ 
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
	-1,0xA,0xB,0xC,0xD,0xE,0xF,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1 
};



static const unsigned char _b64_digits[256] = {
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,    // + , /
	52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,    // 0-9
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
	15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,                   // A-Z
	-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
	41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

void reverse_bytes(void * data, size_t cb)
{
	if(NULL == data || cb < 1) return;
	
	uint8_t * x = (uint8_t *)data;
	uint8_t * x_end = x + cb;
	
	int n = cb / 2;
	int q;
	int r = 0;
	
	uint64_t u64;
	uint32_t u32;
	uint16_t u16;
	
	if(cb < 4)
	{
		uint8_t u8;
		x_end--;
		while(x < x_end)
		{
			u8 =*x;
			*x++ = *x_end;
			*x_end-- = u8;
		}
		return;
	}
	
	
	if((q = n / 8))
	{	
		r = n % 8;
		do
		{
			x_end -= 8;	
			u64 = BSWAP_64(*(uint64_t *)x); 
			*(uint64_t *)x = BSWAP_64(*(uint64_t *)x_end); x += 8;
			*(uint64_t *)x_end = u64; 
		}while(--q);		
	}else if((q = n / 4))
	{		
		r = n % 4;
		x_end -= 4;
		u32 = BSWAP_32(*(uint32_t *)x);
		*(uint32_t *)x = BSWAP_32(*(uint32_t *)x_end); x+= 4;
		*(uint32_t *)x_end = u32;		
	}else if((q = n / 2))
	{
		r = n & 1;
		x_end -= 2;
		u16 = BSWAP_16(*(uint16_t *)x);
		*(uint16_t *)x = BSWAP_16(*(uint16_t *)x_end); x += 2;
		*(uint16_t *)x_end = u16;
	}
	
	if(r == 0) return;
	
	if(r >= 4)
	{
		r -= 4;
		x_end -= 4;
		u32 = BSWAP_32(*(uint32_t *)x);
		*(uint32_t *)x = BSWAP_32(*(uint32_t *)x_end); x+= 4;
		*(uint32_t *)x_end = u32;	
	}
	
	if(r >= 2)
	{
		r -= 2;
		x_end -= 2;
		u16 = BSWAP_16(*(uint16_t *)x);
		*(uint16_t *)x = BSWAP_16(*(uint16_t *)x_end); x += 2;
		*(uint16_t *)x_end = u16;
	}
	
	if(r == 1)
	{
		x_end--;
		uint8_t u8 = *x;
		*x = *x_end;
		*x_end = u8;
	}
}



//~ size_t bin2hex_2(const void * from, size_t cb_from, char * to)
//~ {
	//~ size_t i = 0;
	//~ size_t cb = cb_from * 2;
	//~ const unsigned char * p_from = (const unsigned char *)from;
	//~ unsigned short * p_to = (unsigned short *)to;
	//~ 
	//~ if(NULL == from || cb_from == 0) return 0;
	//~ if(NULL == to) return (cb + 1);	
	//~ 
	//~ while(i < cb_from)
	//~ {
		//~ p_to[i] = MAKE_USHORT_LE(_hex[(p_from[i] >> 4) & 0x0F], _hex[p_from[i] & 0x0F]);
		//~ ++i;
	//~ }
	//~ 
	//~ to[cb] = '\0';
	//~ return cb;
//~ }
//~ 
//~ size_t bin2hex_1(const void * from, size_t cb_from, char * to)
//~ {
	//~ size_t i = 0;
	//~ size_t cb = cb_from * 2;
	//~ const unsigned char * p_from = (const unsigned char *)from;
	//~ 
	//~ if(NULL == from || cb_from == 0) return 0;
	//~ if(NULL == to) return (cb + 1);	
	//~ 
	//~ while(i < cb_from)
	//~ {
		//~ to[i * 2] = _hex[(p_from[i] >> 4) & 0x0F];
		//~ to[i * 2 + 1] = _hex[p_from[i] & 0x0F];
		//~ ++i;
	//~ }
	//~ 
	//~ to[cb] = '\0';
	//~ return cb;
//~ }

size_t bin2hex(const void * from, size_t cb_from, char * to)
{
	size_t i;
	size_t cb = cb_from * 2;
	const unsigned char * p_from = (const unsigned char *)from;
	//~ uint32_t * p_to = (uint32_t *)to;
	
	if(NULL == from || cb_from == 0) return 0;
	if(NULL == to) return (cb + 1);	
	for(i = 0; i < cb_from; ++i)
	{
		to[2 * i] = _hex[(p_from[i] >> 4) & 0x0F];
		to[2 * i + 1] = _hex[(p_from[i] & 0x0F)];
	}
	to[i] = '\0';
	return cb;
	
}

size_t hex2bin(const char * from, size_t cb_from, void * to)
{
	if(NULL == from) return 0;
	if(cb_from == -1) cb_from = strlen(from);
	if(cb_from == 0) return 0;
	size_t cb = cb_from / 2;
	
	if(NULL == to) return cb;
	
	unsigned char * p_to = (unsigned char *)to;
	//~ unsigned char * p_end = p_to + cb;
	
	//~ printf("cb_from = %lu\n", cb_from);
	
	int i = 0;
	unsigned char c1, c2;
	for(i = 0; i < cb; ++i)
	{
		c1 = _hex_digits[(int)from[i * 2]];
		c2 = _hex_digits[(int)from[i * 2 + 1]];
		if(c1 == -1 || c2 == -1)
		{
			errno = EINVAL;
			return -1;
		}
		p_to[i] = (_hex_digits[(int)from[i * 2]] << 4) | (_hex_digits[(int)from[i * 2 + 1]]); 
	}
	return cb;
	
}

void dump2(FILE * fp, const void * data, size_t len)
{
	char buffer[PAGE_SIZE + 1] = "";
	const unsigned char * p = (const unsigned char *)data;
	size_t cb;
	
	while(len > (PAGE_SIZE / 2))
	{
		cb = bin2hex(p, (PAGE_SIZE / 2), buffer);
		if(cb != PAGE_SIZE)
		{
			fprintf(stderr, "dump failed\n");
			errno = EINVAL;
			return;
		}
		p += (PAGE_SIZE / 2);
		len -= (PAGE_SIZE / 2);
		fwrite(buffer, PAGE_SIZE, 1, fp);
	}
	
	if(len)
	{
		cb = bin2hex(p, len, buffer);
		if(cb != (len * 2))
		{
			fprintf(stderr, "dump failed\n");
			errno = EINVAL;
			return;
		}
		fwrite(buffer, cb, 1, fp);
	}
	return;
}

size_t base64_encode(const void * data, size_t data_len, char * to)
{
	if(NULL == data || data_len == 0) return 0;
	size_t cb = (data_len * 4 + 2) / 3;
	if(NULL == to) return cb + 1;
	
	const unsigned char * p_data = (const unsigned char *)data;
	uint32_t * p = (uint32_t *)to;
	size_t i;
	
	size_t len = data_len / 3 * 3;
	size_t cb_left = data_len - len;
	
	for(i = 0; i < len; i += 3)
	{
		*p++ = MAKE_UINT32_LE( _b64[(p_data[i] >> 2) & 0x3F],
						_b64[((p_data[i] &0x03) << 4) | (((p_data[i + 1]) >> 4) & 0x0F)],
						_b64[((p_data[i + 1] & 0x0F) << 2) | ((p_data[i + 2] >> 6) & 0x03)],
						_b64[(p_data[i + 2]) & 0x3F]
						);
	}
	
	if(cb_left == 2)
	{
		*p++ = MAKE_UINT32_LE(_b64[(p_data[i] >> 2) & 0x3F],
							_b64[((p_data[i] &0x03) << 4) | (((p_data[i + 1]) >> 4) & 0x0F)],
							_b64[((p_data[i + 1] & 0x0F) << 2) | 0],
							'=');
		
	}else if(cb_left == 1)
	{
		*p++ = MAKE_UINT32_LE(_b64[(p_data[i] >> 2) & 0x3F],
							_b64[((p_data[i] &0x03) << 4) | 0],
							'=',
							'=');
	}
	
	cb = (char *)p - to;	
	to[cb] = '\0';
	
	return cb;
	
}
//~ 
//~ size_t base64_encode_1(const void * data, size_t data_len, char * to)
//~ {
	//~ if(NULL == data || data_len == 0) return 0;
	//~ size_t cb = (data_len * 4 + 2) / 3;
	//~ if(NULL == to) return cb + 1;
	//~ 
	//~ const unsigned char * p_data = (const unsigned char *)data;
	//~ uint32_t * p = (uint32_t *)to;
	//~ size_t i;
	//~ 
	//~ size_t len = data_len / 3 * 3;
	//~ 
	//~ for(i = 0; i < len; i += 3)
	//~ {		
		//~ p[0] = _b64[(p_data[i] >> 2) & 0x3F];
		//~ p[1] = _b64[((p_data[i] &0x03) << 4) | (((p_data[i + 1]) >> 4) & 0x0F)];
		//~ p[2] = _b64[((p_data[i + 1] & 0x0F) << 2) | ((p_data[i + 2] >> 6) & 0x03)];
		//~ p[3] = _b64[(p_data[i + 2]) & 0x3F];
		//~ p += 4;
	//~ }
	//~ 
	//~ if((data_len - len) == 2)
	//~ {
		//~ p[0] = _b64[(p_data[i] >> 2) & 0x3F];
		//~ p[1] = _b64[((p_data[i] &0x03) << 4) | (((p_data[i + 1]) >> 4) & 0x0F)];
		//~ p[2] = _b64[((p_data[i + 1] & 0x0F) << 2) | 0];
		//~ p[3] = '=';
		//~ p += 4;
	//~ }if((data_len - len) == 1)
	//~ {
		//~ p[0] = _b64[(p_data[i] >> 2) & 0x3F];
		//~ p[1] = _b64[((p_data[i] &0x03) << 4) | 0];
		//~ p[2] = '=';
		//~ p[3] = '=';
		//~ p += 4;
	//~ }
	//~ 
	//~ *p = '\0';
	//~ return (size_t)((char *)p - to);
	//~ 
//~ }


size_t base64_decode(const char * from, size_t cb_from, void * to)
{
	if(NULL == from) return 0;
	if(-1 == cb_from) cb_from = strlen(from);
	if(0 == cb_from) return 0;
	
	if(cb_from % 4) 
	{
		errno = EINVAL;
		return -1;
	}
	
	if(NULL == to) return (cb_from / 4 * 3);
	
	size_t count = cb_from / 4;
	
	const unsigned char * p_from = (const unsigned char *)from;
	const char * p_end = from + cb_from;
	
	unsigned char * p_to = to;
	union
	{
		uint32_t u;
		uint8_t c[4];
	}val;
	
	if(p_end[-1] == '=') count--;
	while(count--)
	{
		//~ val.u = *(uint32_t *)p_from;
		
		val.u = MAKE_UINT32_LE(	_b64_digits[p_from[0]], _b64_digits[p_from[1]],
								_b64_digits[p_from[2]], _b64_digits[p_from[3]]);
		
		if(val.c[0] == 0xff || val.c[1] == 0xff || val.c[2] == 0xff || val.c[3] == 0xff)
		{
			errno = EINVAL;
			return -1;
		}
		
		p_to[0] = (val.c[0] << 2) | ((val.c[1] >> 4) & 0x3);
		p_to[1] = ((val.c[1] & 0x0F) << 4) | ((val.c[2] >> 2) & 0x0F);
		p_to[2] = ((val.c[2] & 0x03) << 6) | (val.c[3] & 0x3F);
		
		p_from += 4;
		p_to += 3;
		
	}
	
	if(p_end[-1] == '=')
	{	
		if(p_end[-2] == '=')	
			val.u = MAKE_UINT32_LE(	_b64_digits[p_from[0]], _b64_digits[p_from[1]], 0, 0);
		else
			val.u = MAKE_UINT32_LE(	_b64_digits[p_from[0]], _b64_digits[p_from[1]], _b64_digits[p_from[2]], 0);
		
		if(val.c[0] == 0xff || val.c[1] == 0xff || val.c[2] == 0xff || val.c[3] == 0xff)
		{
			errno = EINVAL;
			return -1;
		}
		
		p_to[0] = (val.c[0] << 2) | ((val.c[1] >> 4) & 0x3);
		p_to[1] = ((val.c[1] & 0x0F) << 4) | ((val.c[2] >> 2) & 0x0F);
		p_to[2] = ((val.c[2] & 0x03) << 6) | (val.c[3] & 0x3F);
		p_to += 3;
	}
	return (size_t)(p_to - (unsigned char *)to);
}


void hash256(const void * data, size_t data_len, unsigned char out[32])
{
	sha256_ctx_t ctx;	
	unsigned char hash[32];
	sha256_init(&ctx);
	sha256_update(&ctx, (const unsigned char *)data, data_len);
	sha256_final(&ctx, hash);
	
	sha256_init(&ctx);
	sha256_update(&ctx, hash, 32);
	sha256_final(&ctx, out);
	
}

void hash160(const void * data, size_t data_len, unsigned char out[20])
{
	uint8_t hash[32];
	sha256_ctx_t sha;
	ripemd160_ctx_t ctx;	
	sha256_init(&sha);
	sha256_update(&sha, (const unsigned char *)data, data_len);
	sha256_final(&sha, hash);
	
	ripemd160_init(&ctx);
	ripemd160_update(&ctx, hash, 32);
	ripemd160_final(&ctx, out);
}



int chutil_make_non_blocking(int fd)
{
	int rc;
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	if(-1 == flags)
	{
		perror("fcntl");
		return -1;
	}
	
	flags |= O_NONBLOCK;
	rc = fcntl(fd, F_SETFL, flags);
	if(-1 == rc)
	{
		perror("fcntl");
		return -1;
	}
	return 0;
}
