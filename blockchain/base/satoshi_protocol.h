#ifndef _SATOSHI_PROTOCOL_H_
#define _SATOSHI_PROTOCOL_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

#include <netinet/in.h>
#include "chutil.h"
#include <arpa/inet.h>

#ifndef SATOSHI_PROTOCOL_VERSION
#define SATOSHI_PROTOCOL_VERSION (70002) // currently supported protocol version
#endif

#define SATOSHI_MAGIC_MAIN 		(0xD9B4BEF9)
#define SATOSHI_MAGIC_TESTNET3 	(0x0709110B)

extern uint32_t SATOSHI_MAGIC;

#define HASH256_NULL_CHECKSUM (0xE2E0F65D)

typedef uint8_t uint256_t[32];

union compact_int
{
	uint32_t u32;
	struct
	{
		uint8_t mantissa[3];
		uint8_t exp;
	}__attribute__((packed));
};
typedef union compact_int compact_int_t;

static inline int compact_int_set_uint256(compact_int_t * ci, const uint8_t hash[32])
{
	// calc tailing zero bytes
	assert(NULL != ci);
	ci->u32 = 0;
	
	int zeroes = 0;
	for(zeroes = 0; zeroes < sizeof(uint256_t); ++zeroes)
	{
		if(hash[31- zeroes]) break;
	}
	
	if(zeroes == 32)
	{		
		ci->exp = 32;
		return 0;
	}
	
	ci->exp = 32 - zeroes;
	if((hash[ci->exp - 1] & 0x80) && (ci->exp != 32)) ++ci->exp;
	
	int cb = (int)ci->exp;
	int i = 0;
	//~ if(cb > 3) cb = 3;
	// convert [big-endian hash] to [little-endian compact_int mantissa]
	printf("cb = %d\n", cb);
	while((cb > 0) && (i < 3))
	{
		printf("%.2x ", hash[cb - 1]);
		ci->mantissa[2 - i] = hash[--cb];
		++i;
	}
	printf("ci = 0x%.8x\n", ci->u32);
	
	return 0;
}

static inline int compact_int_get_uint256(compact_int_t * ci, uint8_t hash[32])
{
	assert(NULL != ci && NULL != hash);
	memset(hash, 0, 32);
	
	// convert [little-endian compact_int mantissa] tp [big-endian hash]
	int cb = (int)ci->exp;
	int i = 0;
	
	while((cb > 0) && (i < 3))
	{
		hash[--cb] = ci->mantissa[2 - i];
		++i;
	}
	return 0;
}


typedef struct varint
{
	uint8_t vch[1];
}varint_t;

static inline size_t varint_calc_size(uint64_t value)
{
	if(value < 0xFD) return 1;
	else if(value <= 0xFFFF) return 3;
	else if(value <= 0xFFFFFFFF) return 5;
	
	return 9;
}

static inline varint_t * varint_init(uint64_t value)
{
	size_t size = varint_calc_size(value);
	varint_t * vi = (varint_t *)calloc(size, 1);
	assert(NULL != vi);
	
	switch(size)
	{
		case 1: vi->vch[0] = (uint8_t)value; break;
		case 3: vi->vch[0] = 0xFD; *(uint16_t *)(&vi->vch[1]) = (uint16_t)value; break;
		case 5: vi->vch[0] = 0xFE; *(uint32_t *)(&vi->vch[1]) = (uint32_t)value; break;
		case 9: vi->vch[0] = 0xFF; *(uint64_t *)(&vi->vch[1]) = (uint64_t)value; break;
	}
	return vi;
}

static inline void varint_destroy(varint_t * vi)
{
	free(vi);
}

static inline varint_t * varint_set_value(varint_t * vi, uint64_t value)
{
	// if NULL != vi, then vi should already been allocated enough memory
	size_t size = varint_calc_size(value);
	if(NULL == vi)
	{
		vi = (varint_t *)calloc(size, 1);	
	}
	assert(NULL != vi);
	switch(size)
	{
		case 1: vi->vch[0] = (uint8_t)value; break;
		case 3: vi->vch[0] = 0xFD; *(uint16_t *)(&vi->vch[1]) = (uint16_t)value; break;
		case 5: vi->vch[0] = 0xFE; *(uint32_t *)(&vi->vch[1]) = (uint32_t)value; break;
		case 9: vi->vch[0] = 0xFF; *(uint64_t *)(&vi->vch[1]) = (uint64_t)value; break;
	}
	return vi;
}

static inline size_t varint_size(const varint_t * vi)
{
	assert(NULL != vi);
	if(vi->vch[0] < 0xFD) return 1;
	switch(vi->vch[0])
	{
		case 0xFD: return 3;
		case 0xFE: return 5;
		default: break;
	}
	return 9;
}

static inline uint64_t varint_get_value(const varint_t * vi)
{
	if(vi->vch[0] < 0xFD) return (uint64_t)vi->vch[0];
	switch(vi->vch[0])
	{
		case 0xFD: return *(uint16_t *)(&vi->vch[1]);
		case 0xFE: return *(uint32_t *)(&vi->vch[1]);
		default: break;
	}
	return *(uint64_t *)(&vi->vch[1]);
}


typedef union varstr
{
	varint_t length;
	uint8_t vch[1];
}varstr_t;

static inline varstr_t * varstr_init(const char * str, size_t cb)
{
	if(NULL == str) cb = 0;
	else if(-1 == cb) cb = strlen(str);
	
	size_t cb_vint = varint_calc_size(cb);
	size_t size = cb_vint + cb;
	
	varstr_t * vs = (varstr_t *)calloc(size, 1);
	assert(NULL != vs);
	
	varint_set_value(&vs->length, cb);
	if(0 != cb)
	{
		memcpy(&vs->vch[cb_vint], str, cb);
	}
	return vs;
}

static inline void varstr_destroy(varstr_t * vs)
{
	free(vs);
}

static inline size_t varstr_size(const varstr_t * vs)
{
	assert(NULL != vs);
	size_t cb_vint = varint_size(&vs->length);
	size_t cb = (size_t)varint_get_value(&vs->length);
	return (cb_vint + cb);
}

static inline size_t varstr_strlen(const varstr_t * vs)
{
	assert(NULL != vs);
	size_t cb = (size_t)varint_get_value(&vs->length);
	return cb;
}

static inline varstr_t * varstr_set_data(varstr_t * vs, const char * data, size_t cb)
{
	// if(NULL != vs), then vs should alreay been allocate enough memory to copy the data
	if(NULL == data) cb = 0;
	if(-1 == cb) cb = strlen(data);
	
	varint_set_value(&vs->length, cb);
	size_t cb_vint = varint_size(&vs->length);
	if(cb)
	{
		memcpy(&vs->vch[cb_vint], data, cb);
	}
	return vs;
}

static inline const char * varstr_get_ptr(const varstr_t * vs)
{
	assert(NULL != vs);
	size_t cb_vint = varint_size(&vs->length);
	return (const char *)(&vs->vch[cb_vint]);
}


typedef struct satoshi_msg_header
{
	uint32_t magic;
	char command[12];
	uint32_t length;
	uint32_t checksum;
}satoshi_msg_header_t;

typedef struct satoshi_msg
{
	satoshi_msg_header_t hdr;
	unsigned char payload[1];
}satoshi_msg_t;


struct satoshi_addr_legacy
{
	uint64_t services;
	char ip[16];
	uint16_t port;
}__attribute__((packed));
typedef struct satoshi_addr_legacy satoshi_addr_legacy_t;

static inline int satoshi_addr_legacy_set_ip(satoshi_addr_legacy_t * addr, const struct sockaddr * sa)
{	
	if(sa->sa_family == AF_INET)
	{
		struct sockaddr_in * sin = (struct sockaddr_in *)sa;
		memset(addr->ip, 0, 10);
		addr->ip[10] = 0xFF;
		addr->ip[11] = 0xFF;
		*(uint32_t *)&addr->ip[12] = sin->sin_addr.s_addr;
		addr->port = sin->sin_port;		
		return 0;
	}else if(sa->sa_family == AF_INET6)
	{
		struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *)sa;
		memcpy(addr->ip, &sin6->sin6_addr, 16);
		addr->port = sin6->sin6_port;
		return 0;
	}
	
	return -1;
}

struct satoshi_addr
{
#if SATOSHI_PROTOCOL_VERSION >= 31402
	uint32_t time;
#endif
	satoshi_addr_legacy_t addr;
}__attribute__((packed));
typedef struct satoshi_addr satoshi_addr_t;

#define MAX_SATOSHI_USER_AGENT_LENGTH (1024)
struct satoshi_msg_version
{
	int32_t protocol_version; // protocol version
	uint64_t services;
	int64_t timestamp; // standard UNIX timestamp in seconds
	satoshi_addr_legacy_t addr_recv;
#if SATOSHI_PROTOCOL_VERSION >= 106
	satoshi_addr_legacy_t addr_from;
	uint64_t nonce;
	varstr_t user_agent;  // variable length array
	// int32_t start_height;  
#endif

#if SATOSHI_PROTOCOL_VERSION >= 70001
	// bool relay;
#endif
	
}__attribute__((packed));
typedef struct satoshi_msg_version satoshi_msg_version_t;

satoshi_msg_version_t * satoshi_msg_version_init(
	satoshi_msg_version_t * p_ver,
	uint32_t protocol_version,
	uint64_t services,
	struct sockaddr * addr_recv, 
	struct sockaddr * addr_from,
	const char * user_agent, size_t cb_user_agent, 
	int start_height, bool relay);
	

	
static inline void satoshi_msg_version_destroy(satoshi_msg_version_t * p_ver)
{
	free(p_ver);
}

static inline size_t satoshi_msg_version_size(const satoshi_msg_version_t * p_ver)
{
	if(p_ver->protocol_version < 106)
	{
		return 46;
	}
	size_t size = (unsigned char *)&p_ver->user_agent - (unsigned char *)p_ver;
	size += varstr_size(&p_ver->user_agent);
	size += sizeof(int);
	if(p_ver->protocol_version >= 70001)
	{
		size += sizeof(bool);
	}
	return size;
}

void satoshi_msg_version_dump(const satoshi_msg_version_t * p_ver);
	


#ifdef __cplusplus
extern "C" {
#endif



#ifdef __cplusplus
}
#endif

#endif
