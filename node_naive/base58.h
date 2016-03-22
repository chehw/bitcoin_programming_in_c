#ifndef _BASE58_H_
#define _BASE58_H_


#ifdef __cplusplus
extern "C" {
#endif

size_t base58_encode(const unsigned char * src, size_t cb_src, char * to, size_t buffer_size);
size_t base58_decode(const char * src, size_t cb_src, unsigned char * to, size_t buffer_size);


#ifdef __cplusplus
}
#endif
#endif
