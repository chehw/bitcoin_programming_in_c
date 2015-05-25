/*
 * util.c
 * 
 * Copyright 2015 Che Hongwei <htc.chehw@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */

#include "util.h"

#include <assert.h>
#include <sys/uio.h>
#include "satoshi-protocol.h"

static const char ch_util_hex[]="0123456789abcdef";
static const char ch_util_HEX[]="0123456789ABCDEF";
static const signed char ch_util_hexdigit[256] =
{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
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
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1 };




static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t b58digits[] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

static const char pszBase64[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static const unsigned b64Digits[256] = {
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


void fatal(const char * fmt, ...)
{
	FILE * fp = stderr;
	va_list ap;
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	exit(1);
}

void error_handler(int err_no, int fExit, const char * fmt, ...)
{
	FILE * fp = stderr;
	fprintf(fp, "errno = %d: ", err_no);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	if(fExit) exit(fExit);
}

BOOL bin2hex(const unsigned char * from, uint32_t cbFrom, char * to, uint32_t * p_cbTo, BOOL fLowercase)
{	
	uint32_t cbTo = (cbFrom * 2);
	if(NULL == from || cbFrom == 0 || NULL == p_cbTo) return FALSE;	
	if(NULL == to) return (cbTo + 1); // output buffer size
	
	
	if(cbTo >= * p_cbTo)
	{
		*p_cbTo = cbTo + 1;
		return FALSE;
	}
	
	const char * hex = fLowercase?ch_util_HEX:ch_util_hex;
	const unsigned char * begin = from;
	const unsigned char * p_end = from + cbFrom;
	
	unsigned char c;
	char * p = to;
	
	while(begin < p_end)
	{
		c = *begin++;
		*p++ = hex[((c >> 4) & 0x0f)];
		*p++ = hex[(c & 0x0f)];
	}
	*p = '\0';
	*p_cbTo = cbTo;
	return TRUE;
}

BOOL hex2bin(const char * from, uint32_t cbFrom, unsigned char * to, uint32_t * p_cbTo)
{
	if(NULL == from || NULL == p_cbTo) return FALSE;
	if(-1 == cbFrom) cbFrom = strlen(from);	
	if(NULL == to) return FALSE;
	if(cbFrom % 2) return FALSE; // invalid format
	
	uint32_t cbTo = cbFrom / 2;
	if(NULL == to || cbTo > *p_cbTo)
	{
		*p_cbTo = cbTo;
		return FALSE;
	}
	
	const char * begin = from;
	const char * p_end = from + cbFrom;
	unsigned char * p = to;
	unsigned char c1, c2;
	
	while(begin < p_end)
	{
		c1 = ch_util_hexdigit[(int)(*begin++)];
		c2 = ch_util_hexdigit[(int)(*begin++)];
		if(-1 == c1 || -1 == c2) return FALSE; // invalid format
		*p++ = (c1 << 4) | c2; 
	}
	*p_cbTo = cbTo;
	return TRUE;
}

void dump2(FILE * fp, const unsigned char * data, size_t data_len)
{
	const unsigned char * p = data;
	
	char buffer[256 + 1];
	uint32_t cb;
	while(data_len >= 128)
	{
		cb = 256 + 1;
		if(bin2hex(p, 128, buffer, &cb, 0))
		{
			fwrite(buffer, cb, 1, fp);
			p += 128;
			data_len -= 128;
		}else
			return;
	}
	
	if(data_len)
	{
		cb = 256 + 1;
		if(bin2hex(p, data_len, buffer, &cb, 0))
		{
			fwrite(buffer, cb, 1, fp);
			p += data_len;
			data_len -= data_len;
		}
	}
}

BOOL base64_encode(const unsigned char * from, uint32_t cbFrom, char * to , uint32_t * p_cbTo)
{
	uint32_t cbTo = (cbFrom + 2) /3 * 4;
	if(NULL == from || cbFrom == 0 || NULL == p_cbTo) return FALSE;
	if(NULL == to || cbTo >= * p_cbTo)
	{
		* p_cbTo = cbTo + 1;
		return FALSE;
	}
	
	const unsigned char * begin = from;
	const unsigned char * p_end = from + ((cbFrom / 3) * 3) ;
	char * p = to;
	
	
	while(begin < p_end)
	{
		*p++ = pszBase64[(begin[0] >> 2) & 0x3f];
        *p++ = pszBase64[((begin[0] & 0x03) << 4) | ((begin[1] >> 4) & 0x0f)];
        *p++ = pszBase64[((begin[1] & 0x0f) << 2) | ((begin[2] >> 6) & 0x03)];
        *p++ = pszBase64[(begin[2] & 0x3f)];
        begin += 3;
	}
	
	switch((from + cbFrom - p_end))
	{
	case 0:
		break;
	case 1:
		*p++ = pszBase64[(begin[0] >> 2) & 0x3f];
        *p++ = pszBase64[((begin[0] & 0x03) << 4) | 0];
        *p++ = '=';
        *p++ = '=';
		break;
	case 2:
		*p++ = pszBase64[(begin[0] >> 2) & 0x3f];
        *p++ = pszBase64[((begin[0] & 0x03) << 4) | ((begin[1] >> 4) & 0x0f)];
        *p++ = pszBase64[((begin[1] & 0x0f) << 2) | 0];
        *p++ = '=';
		break;
	default:
		return FALSE;
	}
	
	*p = '\0';
	*p_cbTo = cbTo;
	
	return TRUE;	
}
BOOL base64_decode(const char * from, uint32_t cbFrom, unsigned char * to, uint32_t * p_cbTo)
{
	if(NULL == from || NULL == p_cbTo || (cbFrom % 4)) return FALSE;
	uint32_t cbTo = cbFrom / 4 * 3;
	uint32_t cbTail = 0;
	
	if(0 == cbFrom) 
	{
		*p_cbTo = 0;
		return FALSE;
	}
		
	while(cbFrom && (from[cbFrom -1] == '='))
	{	
		cbTail++;	
		cbFrom--;
	}
	if(cbTail > 2) // invalid format
	{
		*p_cbTo = 0;
		printf("invalid format 1\n");
		return FALSE;
	}
	
	cbTo -= cbTail;
	if(NULL == to || cbTo > * p_cbTo)
	{
		*p_cbTo = cbTo;
		printf("invalid format 1\n");
		return FALSE;
	}	
	
	const char * begin = from;
	const char * p_end = from + ((cbFrom / 4) * 4);
	unsigned char * p = to;
	unsigned char c0, c1, c2, c3;
	
	*p_cbTo = 0;
	
	while(begin < p_end)
	{
		c0 = b64Digits[(int)begin[0]];
        c1 = b64Digits[(int)begin[1]];
        c2 = b64Digits[(int)begin[2]];
        c3 = b64Digits[(int)begin[3]];
        if(c0 == -1 || c1 == -1 || c2 == -1 || c3 == -1)
        {
        //    fprintf(stderr, "base64 string format error at position %d.\n", begin - from);
            return FALSE;
        }
        *p++ = ((c0 & 0x3f) << 2) | ((c1 >> 4) & 0x03);
        *p++ = ((c1 & 0x0f) << 4) | ((c2 >> 2) & 0x0f);
        *p++ = ((c2 & 0x03) << 6) | (c3 & 0x3f);
        begin += 4;
	}
	
	switch((from + cbFrom - p_end))
	{
	case 0: case 1: break;
	case 2:
		c0 = b64Digits[(int)begin[0]]; c1 = b64Digits[(int)begin[1]];
        *p++ = ((c0 & 0x3f) << 2) | ((c1 >> 4) & 0x03);
		break;
	case 3:
		c0 = b64Digits[(int)begin[0]]; c1 = b64Digits[(int)begin[1]]; c2 = b64Digits[(int)begin[2]];
        *p++ = ((c0 & 0x3f) << 2) | ((c1 >> 4) & 0x03);
        *p++ = ((c1 & 0x0f) << 4) | ((c2 >> 2) & 0x0f);
		break;
	default:
		printf("invalid format 3\n");
		return FALSE;
	}
	*p_cbTo = cbTo;
	return TRUE;
	
}



static BOOL isWhite(char ch)
{
	switch(ch)
	{
	case ' ': case '\t': case '\r': case '\n': 
		return TRUE;
	default:
		break;		
	}
	return FALSE;
}

void trim_left(char * string)
{
	if(NULL == string) return;
	char * p = string;
	while(*p && isWhite(*p)) p++;
	
	if(p == string) return; // no need to trim
	
	while(*p)
	{
		*string++ = *p++;
	}
	*string = '\0';	
}

void trim_right(char * string)
{
	if(NULL == string) return;
	char * p = string + strlen(string) -1;
	
	while(p > string && isWhite(*p)) p--;	
	*(p + 1) = '\0';
}



#define AES256_IV_SIZE (16)



static const struct AES256_CTX aes256_ctx_default = 
{
	NULL,
	{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,  0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 
	 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,  0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70
	},
	{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,  0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F}
};



AES256_CTX_t * AES256_CTX_new()
{
	AES256_CTX_t * ctx = (AES256_CTX_t *)malloc(sizeof(AES256_CTX_t));
	if(NULL == ctx) return NULL;
	
	
	if(NULL == ctx->evp)
	{
		free(ctx);
		return NULL;
	}
	
	memcpy(ctx, &aes256_ctx_default, sizeof(AES256_CTX_t));
	ctx->evp = EVP_CIPHER_CTX_new();
	
	return ctx;
}

int AES256_CTX_init(AES256_CTX_t * ctx, const unsigned char key[32], const unsigned char iv[16])
{
	if(NULL == ctx) return -1;
	if(NULL == ctx->evp) 
	{
		ctx->evp = EVP_CIPHER_CTX_new();
		if(NULL == ctx->evp) return -1;
	}
	
	if(ctx->key != key) 	memcpy(ctx->key, key, 32);
	if(ctx->iv != iv)	memcpy(ctx->iv, iv, 16);
	return 0;
}

void AES256_CTX_free(AES256_CTX_t * ctx)
{
	if(ctx) 
	{
		if(ctx->evp) EVP_CIPHER_CTX_free(ctx->evp);
		ctx->evp = NULL;
		free(ctx);
	}
}

AES256_CTX_t * AES256_encrypt_start(AES256_CTX_t * ctx)
{
	AES256_CTX_t * c = ctx;
	if(NULL == c) 
	{
		c = AES256_CTX_new();
		if(0 != AES256_CTX_init(c, c->key, c->iv)) 
		{
			free(c);
			return NULL;
		}
	}
	
	if(1 != EVP_EncryptInit_ex(c->evp, EVP_aes_256_cbc(), NULL, c->key, c->iv))
	{
		EVP_CIPHER_CTX_free(c->evp);
		c->evp = NULL;
		if(NULL == ctx) free(c);
		return NULL;
	}
	
	return c;
}

int AES256_encrypt_update(AES256_CTX_t * ctx, const void * data, size_t data_len, unsigned char * to, int * p_cbTo)
{
	EVP_CIPHER_CTX * evp = ctx->evp;
	int cb = 0;
	if( 1 != EVP_EncryptUpdate(evp, to, &cb, (unsigned char *)data, (int)data_len))
	{
		return -1;
	}
	
	if(p_cbTo) *p_cbTo = cb;
	return 0;
}

int AES256_encrypt_final(AES256_CTX_t * ctx, unsigned char * to, int * p_cbTo)
{
	EVP_CIPHER_CTX * evp = ctx->evp;
	int cb = 0;
	if( 1 != EVP_EncryptFinal(evp, to, &cb))
	{
		return -1;
	}
	if(p_cbTo) *p_cbTo = cb;
	return 0;
}

AES256_CTX_t * AES256_decrypt_start(AES256_CTX_t * ctx)
{
	AES256_CTX_t * c = ctx;
	if(NULL == c) 
	{
		c = AES256_CTX_new();
		if(0 != AES256_CTX_init(c, c->key, c->iv)) 
		{
			free(c);
			return NULL;
		}
	}
	
	if(1 != EVP_DecryptInit_ex(c->evp, EVP_aes_256_cbc(), NULL, c->key, c->iv))
	{
		EVP_CIPHER_CTX_free(c->evp);
		c->evp = NULL;
		if(NULL == ctx) free(c);
		return NULL;
	}
	
	return c;
}

int AES256_decrypt_update(AES256_CTX_t * ctx, const void * data, size_t data_len, unsigned char * to, int * p_cbTo)
{
	EVP_CIPHER_CTX * evp = ctx->evp;
	int cb = 0;
	if( 1 != EVP_DecryptUpdate(evp, to, &cb, (unsigned char *)data, (int)data_len))
	{
		return -1;
	}
	
	if(p_cbTo) *p_cbTo = cb;
	return 0;
}

int AES256_decrypt_final(AES256_CTX_t * ctx, unsigned char * to, int * p_cbTo)
{
	EVP_CIPHER_CTX * evp = ctx->evp;
	int cb = 0;
	if( 1 != EVP_DecryptFinal(evp, to, &cb))
	{
		return -1;
	}
	if(p_cbTo) *p_cbTo = cb;
	return 0;
}



uint32_t hash256(const void * data, size_t data_len, unsigned char output[32])
{
	unsigned char vch[32] = {0};
	SHA256_CTX ctx;
	
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data, data_len);
	SHA256_Final(vch, &ctx);
	
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, vch, 32);
	SHA256_Final(output, &ctx);
	
	return 32;
}

uint32_t hash160(const void * data, size_t data_len, unsigned char output[20])
{
	unsigned char vch[32] = {0};
	SHA256_CTX	 ctx;
	RIPEMD160_CTX ctx_160;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data, data_len);
	SHA256_Final(vch, &ctx);
	
	RIPEMD160_Init(&ctx_160);
	RIPEMD160_Update(&ctx_160, data, data_len);
	RIPEMD160_Final(output, &ctx_160);
	return 20;
}


static void ReverseBytes(unsigned char *begin, size_t size)
{
    if (begin == NULL ||  size == 0) return;
    unsigned char c;
    unsigned char * end = begin + size - 1;
    while(begin < end)
    {
        c = *begin;
        *(begin++) = *end;
        *(end--) = c;
    }
}

size_t base58_encode(const unsigned char *begin, size_t size, char *to)
{
    size_t cb = 0;
	BN_CTX * ctx = NULL;

    unsigned char c;
    unsigned char *pzero = (unsigned char *)begin;
	unsigned char *pend = (unsigned char *)(begin + size);

	char *p = to;

	BIGNUM *bn = NULL, *dv = NULL, *rem = NULL, *bn58 = NULL, *bn0 = NULL;
	if((NULL == begin) || (size == 0)) return 0; // invalid parameter

	cb = size * 138 /100+1;	// sizeof output  less than (138/100 * sizeof(src))

	//** output buffer should be allocated enough memory
	if(NULL == to) return cb;


	ctx = BN_CTX_new();
	if(NULL==ctx) return 0;

	bn58 = BN_new();
	bn0 = BN_new();
	bn = BN_new();
	dv = BN_new();
	rem = BN_new();
	if(NULL == bn58 || NULL == bn0 || NULL == bn || NULL == dv || NULL == rem) goto label_exit;

//    BN_init(&bn58); BN_init(&bn0);
	BN_set_word(bn58, 58);
	BN_zero(bn0);
//	BN_init(&bn); BN_init(&dv); BN_init(&rem);

	BN_bin2bn(begin, size, bn);

	while(BN_cmp(bn, bn0) > 0)
	{
		if(!BN_div(dv, rem, bn, bn58, ctx)) break;
		BN_copy(bn, dv);
		c = BN_get_word(rem);
		*(p++) = pszBase58[c];
	}


	while(*(pzero++)==0)
	{
		*(p++) = pszBase58[0];
		if(pzero > pend) break;
	}
	*p = '\0';
	cb = p - to;

	ReverseBytes((unsigned char *)to, cb);
	
label_exit:
    

	if(NULL!= bn) BN_clear_free(bn);
	if(NULL!= dv) BN_clear_free(dv);
	if(NULL!= rem) BN_clear_free(rem);
	if(NULL!= bn58) BN_clear_free(bn58);
	if(NULL!= bn0) BN_clear_free(bn0);
	if(NULL != ctx) BN_CTX_free(ctx);
	return cb;
}

size_t base58_decode(const char *begin, size_t size, unsigned char *to)
{
	unsigned char c;
	unsigned char *p = (unsigned char *)begin;
	unsigned char *pend = p + size;
	size_t cb;
	BIGNUM bn, bnchar;
	BIGNUM bn58, bn0;

	cb = size;
	if(NULL == to) return cb;


	BN_CTX *ctx = BN_CTX_new();
	if(NULL == ctx) return 0;

    BN_init(&bn58);
    BN_init(&bn0);
    BN_init(&bn); BN_init(&bnchar);

	BN_set_word(&bn58, 58);
	BN_zero(&bn0);


	while(p < pend)
	{
		c = *p;
		if(c & 0x80) goto label_errexit;
		if(-1 == b58digits[c]) goto label_errexit;
		BN_set_word(&bnchar, b58digits[c]);
		if(!BN_mul(&bn, &bn, &bn58, ctx)) goto label_errexit;

		BN_add(&bn, &bn, &bnchar);
		p++;
	}

	cb = BN_num_bytes(&bn);


	BN_bn2bin(&bn, to);
	
	BN_clear_free(&bn58);
    BN_clear_free(&bn0);
    BN_clear_free(&bn); BN_clear_free(&bnchar);
    BN_CTX_free(ctx);

	return cb;

label_errexit:
	if(NULL != ctx) BN_CTX_free(ctx);
	return 0;
}




/**************************
 * IEEE-754 format
 * copy from: http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html#simpleserver
 * Here's some code that encodes floats and doubles into IEEE-754 format. (Mostly—it doesn't encode NaN or Infinity, but it could be modified to do that.)
 */
uint64_t pack754(long double f, unsigned bits, unsigned expbits)
{
    long double fnorm;
    int shift;
    long long sign, exp, significand;
    unsigned significandbits = bits - expbits - 1; // -1 for sign bit

    if (f == 0.0) return 0; // get this special case out of the way

    // check sign and begin normalization
    if (f < 0) { sign = 1; fnorm = -f; }
    else { sign = 0; fnorm = f; }

    // get the normalized form of f and track the exponent
    shift = 0;
    while(fnorm >= 2.0) { fnorm /= 2.0; shift++; }
    while(fnorm < 1.0) { fnorm *= 2.0; shift--; }
    fnorm = fnorm - 1.0;

    // calculate the binary form (non-float) of the significand data
    significand = fnorm * ((1LL<<significandbits) + 0.5f);

    // get the biased exponent
    exp = shift + ((1<<(expbits-1)) - 1); // shift + bias

    // return the final answer
    return (sign<<(bits-1)) | (exp<<(bits-expbits-1)) | significand;
}

long double unpack754(uint64_t i, unsigned bits, unsigned expbits)
{
    long double result;
    long long shift;
    unsigned bias;
    unsigned significandbits = bits - expbits - 1; // -1 for sign bit

    if (i == 0) return 0.0;

    // pull the significand
    result = (i&((1LL<<significandbits)-1)); // mask
    result /= (1LL<<significandbits); // convert back to float
    result += 1.0f; // add the one back on

    // deal with the exponent
    bias = (1<<(expbits-1)) - 1;
    shift = ((i>>significandbits)&((1LL<<expbits)-1)) - bias;
    while(shift > 0) { result *= 2.0; shift--; }
    while(shift < 0) { result /= 2.0; shift++; }

    // sign it
    result *= (i>>(bits-1))&1? -1.0: 1.0;

    return result;
}
