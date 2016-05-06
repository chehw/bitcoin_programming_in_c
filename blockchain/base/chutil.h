#ifndef _CHUTIL_H_
#define _CHUTIL_H_

#include <stdio.h>
#include <stdlib.h>

#include <stdint.h>
#include <inttypes.h>
#include <endian.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE (4096)
#endif



#define BSWAP_16(x) ( 	((uint16_t)(x)  <<  8) | ((uint16_t)(x) >> 8) )
#define BSWAP_32(x) ( 	((uint32_t)(x)  << 24) | \
						(((uint32_t)(x) <<  8) & 0x00ff0000) | \
						(((uint32_t)(x) >>  8) & 0x0000ff00) | \
						((uint32_t)(x)  >> 24) )

#define	BSWAP_64(x) ( 	((uint64_t)(x)  << 56) | \
						(((uint64_t)(x) << 40) & 0xff000000000000ULL) | \
						(((uint64_t)(x) << 24) & 0x00ff0000000000ULL) | \
						(((uint64_t)(x) <<  8) & 0x0000ff00000000ULL) | \
						(((uint64_t)(x) >>  8) & 0x000000ff000000ULL) | \
						(((uint64_t)(x) >> 24) & 0x00000000ff0000ULL) | \
						(((uint64_t)(x) >> 40) & 0x0000000000ff00ULL) | \
						((uint64_t)(x)  >> 56))
                        
static inline void BSWAP_256(uint8_t b[32])
{
	uint64_t * u = (uint64_t *)b;
	uint64_t temp;
	temp = BSWAP_64(u[0]); 	u[0] = BSWAP_64(u[3]); u[3] = temp;
	temp = BSWAP_64(u[1]); 	u[1] = BSWAP_64(u[2]); u[2] = temp;
}


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define SER_UINT16(u16) BSWAP_16(u16)
#define SER_UINT32(u32) BSWAP_32(u32)
#define SER_UINT64(u64) BSWAP_64(u64)
#else
#define SER_UINT16(u16) (u16)
#define SER_UINT32(u32) (u32)
#define SER_UINT64(u64) (u64)
#error "big endian"
#endif

#define MAKE_USHORT_LE(c1, c2) (((unsigned short)(c1) & 0xFF) | (((unsigned short)(c2) & 0xFF) << 8))
#define MAKE_UINT32_LE(c1, c2, c3, c4) (((uint32_t)(c1)  & 0xFF ) | (((uint32_t)(c2) & 0xFF) << 8) \
										| (((uint32_t)(c3) & 0xFF) << 16)| (((uint32_t)(c4) & 0xFF) << 24) \
										)
										
    

#ifdef __cplusplus
extern "C" {
#endif
void reverse_bytes(void * data, size_t cb);

size_t bin2hex(const void * from, size_t cb_from, char * to);
size_t hex2bin(const char * from, size_t cb_from, void * to);
void dump2(FILE * fp, const void * data, size_t len);

#define dump_line(fp, title, data, len) do {if(title) fprintf(fp, "[%s]: \n", title); \
										dump2(fp, data, len); \
										fprintf(fp, "\n");}while(0)
										
#define dump(data, len) do {dump2(stdout, data, len); printf("\n");} while(0)

size_t base64_encode(const void * data, size_t data_len, char * to);
size_t base64_decode(const char * from, size_t cb_from, void * to);



void hash256(const void * data, size_t data_len, unsigned char out[32]);
void hash160(const void * data, size_t data_len, unsigned char out[20]);

int chutil_make_non_blocking(int fd);




#ifdef _DEBUG
#define debug_printf(fmt, ...)  do { \
		char buf[4096] = ""; \
		int cb = 0; \
		cb = snprintf(buf, sizeof(buf), "DEBUG: (" __FILE__ " - %s @line %d): " fmt "\n", \
				__FUNCTION__, __LINE__, ##__VA_ARGS__); \
		write(STDERR_FILENO, buf, cb); \
	}while(0)
#define log_printf(fmt, ...) do { \
		char buf[4096] = ""; \
		int cb = 0; \
		cb = snprintf(buf, sizeof(buf), "LOG: ("__FILE__ " - %s @line %d: )" fmt "\n", \
				__FUNCTION__, __LINE__, ##__VA_ARGS__); \
		write(STDOUT_FILENO, buf, cb); \
	}while(0)
#else
#define debug_printf(fmt, ...) 
#define log_printf(fmt, ...)
#endif


#ifdef __cplusplus
}
#endif
#endif
