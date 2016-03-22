/*
 * base58.c * 
 * 
 * origin: https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
 * modified by: chehw
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
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const unsigned char b58digits[256] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8, -1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

size_t base58_encode(const unsigned char * src, size_t cb_src, char * to, size_t buffer_size)
{
	size_t cb_dst = cb_src * 138 / 100 + 1;
	if(NULL == to) // query buffer size
		return cb_dst; 
		
	if(cb_dst > buffer_size) return 0;
	int i;
	int zeros = 0;
	int carry;
	
	const unsigned char * p_end = src + cb_src;
	
	unsigned char * dst = (unsigned char *)calloc(1, cb_dst);
	assert(NULL != dst);
	
	// skip leading zeros
	while((src < p_end) && (*src == 0))
	{
		++src;
		++zeros;
	}
	
	while(src < p_end)
	{
		carry = *src;
		for(i = cb_dst - 1; i >= 0; --i)
		{
			carry += 256 * dst[i];
			dst[i] = carry % 58;
			carry /= 58;			
		}
		assert(carry == 0);
		++src;
	}
	
	// skip leading zeros in b58 result
	unsigned char * p_begin = dst;
	p_end = dst + cb_dst;
	while((p_begin < p_end) && (p_begin[0] == 0)) ++p_begin;
	
	cb_dst = (p_end - p_begin);
	
	
	char * iter = to;
	for(i = 0; i < zeros; ++i) 
		iter[i] = '1';	
	iter += zeros;
	for(i = 0; i < cb_dst; ++i) 
		iter[i] = pszBase58[p_begin[i]];
	
	iter[i] = '\0';
	
	free(dst);
	return (cb_dst + zeros);
}

size_t base58_decode(const char * src, size_t cb_src, unsigned char * to, size_t buffer_size)
{
	assert(NULL != src);
	if(-1 == cb_src) cb_src = strlen(src);
	if(0 == cb_src) return 0;
	
	size_t cb_dst = cb_src * 733 / 1000 + 1;
	if(NULL == to) // query buffer size
		return cb_dst;
		
	if(cb_dst > buffer_size) return 0;
	
	unsigned char * b256 = (unsigned char *)calloc(1, cb_dst);
	assert(NULL != b256);
	
	// skip leading b58 zeros ('1')
	int zeros;
	int i;
	for(zeros = 0; zeros < cb_src; ++zeros)
	{
		if(src[zeros] != '1') break;
	}
	src += zeros;
	cb_src -= zeros;
	int carry;
	//~ fprintf(stderr, "src = [%s]\n", src);
	//~ unsigned char ch;
	for(i = 0; i < cb_src; ++i)
	{
		if(isspace(src[i])) break;
		//~ printf("carry = %d\n", carry);
		//~ fprintf(stderr, "src = [%s], src[i] = %.2x\n", src, src[i]);
		
		carry = (int)b58digits[(unsigned char)src[i]];
		
		if(carry == 0xff) 
		{
			
			fprintf(stderr, "Error: ['%s' - '%s'] @ line %d: invalid b58 string format. (zeros = %d, char[%d] = %.2x)\n",
				__FILE__, __func__, __LINE__,
				zeros,
				i, src[i]);
			free(b256);
			return 0;
		}
		
		for(int j = cb_dst - 1; j >= 0; --j)
		{
			carry += 58 * b256[j];
			b256[j] = carry % 256;
			carry >>= 8;
		}
		assert(carry == 0);
		//~ ++src;
	}
	
	// skip trailing spaces
	for(; i < cb_src; ++i)
	{
		if(!isspace(src[i])) break;
	}
	if(i != cb_src)
	{
		free(b256);
		return 0;
	}
	
	unsigned char * p_begin = b256;
	for(i = 0; i < cb_dst; ++i)
		if(b256[i] != 0) break;
		
	p_begin += i;
	cb_dst -= i;
	
	for(i = 0; i < zeros; ++i)
		to[i] = 0;
	
	unsigned char * iter = to + i;
	
	for(i = 0; i < cb_dst; ++i)
	{
		iter[i] = p_begin[i];
	}
	free(b256);
	return (cb_dst + zeros);
}
