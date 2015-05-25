#ifndef _UTIL_H_
#define _UTIL_H_


#include <stdint.h>


#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <error.h>
#include <errno.h>
#include <sys/socket.h>

#include <sys/time.h>

#include <sys/uio.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#ifndef BOOL
#define BOOL int32_t
#define FALSE (0)
#define TRUE (!FALSE)
#endif



#ifdef __cplusplus
extern "C" {
#endif


void fatal(const char * fmt, ...);
void error_handler(int err_no, int fExit, const char * fmt, ...);


BOOL bin2hex(const unsigned char * from, uint32_t cbFrom, char * to, uint32_t * p_cbTo, BOOL fLowercase);
BOOL hex2bin(const char * from, uint32_t cbFrom, unsigned char * to, uint32_t * p_cbTo);

void dump2(FILE * fp, const unsigned char * data, size_t data_len);
#define dump(data, data_len) dump2(stdout, data, data_len)
#define dump_line(title, data, data_len) if(title) printf("[%s]: ", title); dump2(stdout, data, data_len); printf("\n");

BOOL base64_encode(const unsigned char * from, uint32_t cbFrom, char * to , uint32_t * p_cbTo);
BOOL base64_decode(const char * from, uint32_t cbFrom, unsigned char * to, uint32_t * p_cbTo);

void trim_left(char * string);
void trim_right(char * string);


typedef struct AES256_CTX
{
	EVP_CIPHER_CTX * evp;
	unsigned char key[32];
	unsigned char iv[16];
} AES256_CTX_t;
AES256_CTX_t * AES256_CTX_new();
int AES256_CTX_init(AES256_CTX_t * ctx, const unsigned char key[32], const unsigned char iv[16]);
void AES256_CTX_free(AES256_CTX_t * ctx);

AES256_CTX_t * AES256_encrypt_start(AES256_CTX_t * ctx);
int AES256_encrypt_update(AES256_CTX_t * ctx, const void * data, size_t data_len, unsigned char * to, int * p_cbTo);
int AES256_encrypt_final(AES256_CTX_t * ctx, unsigned char * to, int * p_cbTo);

AES256_CTX_t * AES256_decrypt_start(AES256_CTX_t * ctx);
int AES256_decrypt_update(AES256_CTX_t * ctx, const void * data, size_t data_len, unsigned char * to, int * p_cbTo);
int AES256_decrypt_final(AES256_CTX_t * ctx, unsigned char * to, int * p_cbTo);



uint32_t hash256(const void * data, size_t data_len, unsigned char output[32]);
uint32_t hash160(const void * data, size_t data_len, unsigned char output[20]); 

size_t base58_encode(const unsigned char *begin, size_t size, char *to);
size_t base58_decode(const char *begin, size_t size, unsigned char *to);

uint32_t PubkeyToAddr(const unsigned char * pubkey, size_t size, char *to);
uint32_t PrivkeyToWIF(const unsigned char vch[32], char *to, BOOL fCompressed);

uint32_t AddrToHash160(const char * addr, unsigned char output[20]);
uint32_t WIFToPrivkey(const char * wif, unsigned char output[32]);


#define pack754_32(f) (pack754((f), 32, 8))
#define pack754_64(f) (pack754((f), 64, 11))
#define unpack754_32(i) (unpack754((i), 32, 8))
#define unpack754_64(i) (unpack754((i), 64, 11))
uint64_t pack754(long double f, unsigned bits, unsigned expbits);
long double unpack754(uint64_t i, unsigned bits, unsigned expbits);

#ifdef __cplusplus
}
#endif


#endif
