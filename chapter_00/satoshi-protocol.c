/*
 * satoshi-protocol.c
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

#include "satoshi-protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/time.h>
#include <assert.h>

const uint32_t satoshi_magic_main = 0xD9B4BEF9;
const uint32_t satoshi_magic_testnet = 0xDAB5BFFA;
const uint32_t satoshi_magic_testnet3 = 0x0709110B;
const uint32_t satoshi_magic_namecoin = 0xFEB4BEF9;

const uint32_t hash256_checksum_null = 0xE2E0F65D; // 0x5d, 0xf6, 0xe0, 0xe2


const char SATOSHI_MESSAGE_COMMANDS[SATOSHI_MESSAGE_COMMAND_COUNT][12] = {
	"version",
	"verack",
	"addr",
	"inv",
	"getdata",
	"notfound",
	"getblocks",
	"getheaders",
	"tx",
	"block",
	"headers",
	"getaddr",
	"mempool",
	"checkorder",
	"submitorder",
	"reply",
	"ping",
	"pong",
	"reject",
	"filterload",
	"filteradd",
	"filterclear",
	"merkleblock",
	"alert"
};

void SATOSHI_MESSAGE_HEADER_dump(const SATOSHI_MESSAGE_HEADER_t *p_hdr)
{
	char sz[100] = "";
	
	if(p_hdr->magic == satoshi_magic_main)	strncpy(sz, "bitcoin", 100);
	else if(p_hdr->magic == satoshi_magic_testnet) strncpy(sz, "testnet", 100); 
	else if(p_hdr->magic == satoshi_magic_testnet3) strncpy(sz, "testnet3", 100); 
	else if(p_hdr->magic == satoshi_magic_namecoin) strncpy(sz, "namecoin", 100); 
	else strncpy(sz, "unknown network", 100); 		
	
	printf("network: %s\n", sz);
	strncpy(sz, p_hdr->command, 12);
	printf("command: %s\n", sz);
	
	printf("payload length: %u\n", p_hdr->length);
	printf("payload checksum: 0x%.8x\n", p_hdr->checksum);	
}

//***********************************//
//** VARINT

varint_t * VARINT_new()
{
	varint_t * p_var = (varint_t *)malloc(9);
	if(NULL == p_var) return NULL;
	memset(p_var, 0, 9);
	return p_var;
}

void VARINT_free(varint_t * p_var)
{
	free(p_var);
}


static uint32_t VARINT_calc_length(uint64_t value)
{
	uint32_t length = 9;
	if (value < 0xfd) length = 1;
	else if (value <= 0xffff) length = 3;
	else if (value <= 0xffffffff) length =5;
	
	return length;
}

// p_var should have enough space to store the value
varint_t * VARINT_setdata(varint_t * p_var, uint64_t value)
{
	uint32_t length;
	if (value < 0xfd) length = 1;
	else if (value <= 0xffff) length = 3;
	else if (value <= 0xffffffff) length =5;
	else length = 9;
	
	if(NULL == p_var) p_var = VARINT_new();
	
	switch(length)
	{
		case 1: p_var->vch[0] = (unsigned char)value; break;
		case 3: p_var->vch[0] = 0xfd; memcpy(&p_var->vch[1], &value, 2); break;
		case 5: p_var->vch[0] = 0xfe; memcpy(&p_var->vch[1], &value, 4); break;
		case 9: p_var->vch[0] = 0xff; memcpy(&p_var->vch[1], &value, 8); break;
	}	
	return p_var;
}

uint64_t VARINT_getdata(const varint_t * p_var)
{
	uint64_t value = 0;
	assert(p_var != NULL);
	if(p_var->vch[0] < 0xfd)
	{
		value = p_var->vch[0];
		return value;
	}
	switch(p_var->vch[0])
	{
		case 0xfd: value = *((uint16_t *)(&p_var->vch[1]));
		case 0xfe: value = *((uint32_t *)(&p_var->vch[1]));
		case 0xff: value = *((uint64_t *)(&p_var->vch[1]));
	}
	return value;
}


uint32_t VARINT_length(const varint_t * p_var)
{
	if(p_var->vch[0] < 0xfd)
	{
		return 1;
	}
	switch(p_var->vch[0])
	{
		case 0xfd: return 3;
		case 0xfe: return 5;
	default:
		break;
	}
	return 9;
}

uint32_t VARINT_write(const varint_t * p_var, int handle)
{
	uint32_t cb;
	assert(NULL != p_var);
	
	uint32_t length = VARINT_length(p_var);
	cb = (uint32_t)write(handle, &p_var->vch[0], length);
	return cb;
}

uint32_t VARINT_fwrite(const varint_t * p_var, FILE * fp)
{
	uint32_t cb;
	assert(NULL != p_var);
	
	uint32_t length = VARINT_length(p_var);
	cb = (uint32_t)fwrite(&p_var->vch[0], length, 1, fp);
	return cb;
}




//***********************************//
//** VARSTR
VARSTR_t * VARSTR_new(uint64_t length)
{
	VARSTR_t * p_var = NULL;
	uint64_t size;
	uint32_t vint_len = VARINT_calc_length(length);
	
	size = vint_len + length + 1;
	
	p_var = (VARSTR_t *)malloc(size);
	if(NULL == p_var) return NULL;	
	
	
	
	VARINT_setdata(&p_var->length, length);
	return p_var;
}

void VARSTR_free(VARSTR_t * p_var)
{
	free(p_var);
}

VARSTR_t * VARSTR_setdata(VARSTR_t * p_var, const char * string, uint64_t cbString)
{
	if(cbString == -1) cbString = strlen(string);	
	if(NULL == p_var) p_var = VARSTR_new(cbString);
	
	if(NULL == p_var) return NULL;
	
	char * p = (char *)p_var;
	
	if(cbString)
	{
		VARINT_setdata(&p_var->length, cbString);
		uint32_t vint_len = VARINT_length(&p_var->length);
		
		p += vint_len;
		memcpy(p, string, cbString);		
	}
	*(p + cbString) = '\0';
	return p_var;
}

const char * VARSTR_getdata(const VARSTR_t * p_var)
{
	const char * p = (const char *)p_var;
	uint32_t vint_len = VARINT_length(&p_var->length);
	return (p + vint_len);
}

uint64_t VARSTR_get_size(const VARSTR_t * p_var)
{
	uint32_t vint_len = VARINT_length(&p_var->length);
	uint64_t data_len = VARINT_getdata(&p_var->length);
	return (data_len + vint_len);
}

uint64_t VARSTR_write(const VARSTR_t * p_var, int handle)
{
	uint64_t length = VARSTR_get_size(p_var);
	return write(handle, p_var, length);
}

uint64_t VARSTR_fwrite(const VARSTR_t * p_var, FILE * fp)
{
	uint64_t length = VARSTR_get_size(p_var);
	return fwrite(p_var, length, 1, fp);
}

/*********************************
 * SATOSHI_MESSAGE_VERSION
 *  uint32_t version;
	uint64_t services;
	uint64_t timestamp;
	SATOSHI_NETADDR_LEGACY_t addr_recv;
	#if (SATOSHI_PROTOCOL_VERSION  >= 106)
	SATOSHI_NETADDR_LEGACY_t addr_from;
	uint64_t nonce;

	varstr_t user_agent;
	// int32_t start_height;
	// int8_t relay;
	#endif
 *********************************/

SATOSHI_MESSAGE_VERSION_t * SATOSHI_MESSAGE_VERSION_new(const unsigned char * user_agent, uint32_t cbUserAgent, int32_t start_height, int8_t relay)
{
	uint32_t cb_vint = 0;
	uint32_t cbTotalSize = 0;
	SATOSHI_MESSAGE_VERSION_t * p_ver = NULL;
	
	struct timeval tv = {0};
	
	if(NULL == user_agent) cbUserAgent = 0;	
	if(cbUserAgent > SATOSHI_MESSAGE_VERSION_USER_AGENT_MAX_SIZE) cbUserAgent = SATOSHI_MESSAGE_VERSION_USER_AGENT_MAX_SIZE;
	cb_vint = VARINT_calc_length(cbUserAgent);
	
	cbTotalSize = sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(SATOSHI_NETADDR_LEGACY_t);
#if (SATOSHI_PROTOCOL_VERSION  >= 106)
	cbTotalSize += sizeof(SATOSHI_NETADDR_LEGACY_t) + sizeof(uint64_t) + cb_vint + cbUserAgent + sizeof(int32_t) + sizeof(int8_t);
#endif

//	printf("cbTotalSize = %u\n", cbTotalSize);
	p_ver = (SATOSHI_MESSAGE_VERSION_t *)malloc(cbTotalSize);
	if(NULL == p_ver) return NULL;
	memset(p_ver, 0, cbTotalSize);
	
	p_ver->version = SATOSHI_PROTOCOL_VERSION;
	p_ver->services = SATOSHI_SERVICE_TYPE_NODE_NETWORK;
	
	gettimeofday(&tv, NULL);
	p_ver->timestamp = tv.tv_sec;
	
	p_ver->nonce = tv.tv_sec * 1000 + tv.tv_usec / 1000;
	
	
	
	VARSTR_t * p_useragent = & (p_ver->user_agent);
	VARSTR_setdata(p_useragent, (char * )user_agent, cbUserAgent);
//	dump_line("p_useragent", p_useragent, cbUserAgent);
	
	unsigned char * p = ((unsigned char *)p_useragent);
	p += cb_vint + cbUserAgent;	
	
	
	*(int32_t *)p = start_height;
	p += sizeof(int32_t);
	
	*(int8_t *)p = relay;
	
//	printf("version len: %ld\n", p - ((unsigned char *)p_ver) +1);
	return p_ver;
}
void SATOSHI_MESSAGE_VERSION_free(SATOSHI_MESSAGE_VERSION_t * p_ver)
{
	free(p_ver);
}
uint32_t SATOSHI_MESSAGE_VERSION_calc_size(const SATOSHI_MESSAGE_VERSION_t * p_ver)
{
	uint32_t cbTotalSize = 0;
	cbTotalSize = sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(SATOSHI_NETADDR_LEGACY_t);

	uint32_t cbUserAgent = 0;
	if(p_ver->version >= 106)
	{
		cbUserAgent = VARSTR_get_size(&(p_ver->user_agent));
		cbTotalSize += sizeof(SATOSHI_NETADDR_LEGACY_t) + sizeof(uint64_t) + cbUserAgent + sizeof(int32_t) + sizeof(int8_t);
	}
//	printf("cbTotalSize = %u\n", cbTotalSize);
	return cbTotalSize;
}

BOOL SATOSHI_MESSAGE_VERSION_set_start_height(SATOSHI_MESSAGE_VERSION_t * p_ver, int32_t height)
{
	assert(NULL != p_ver);
	unsigned char * p = NULL;
	if(p_ver->version < 106) return FALSE;
	
	uint32_t cbUserAgent = VARSTR_get_size(&p_ver->user_agent);	
	p = (unsigned char *)(&p_ver->user_agent) + cbUserAgent;
	
	*((int32_t *)p) = height;
	return TRUE;
}

int32_t SATOSHI_MESSAGE_VERSION_get_start_height(const SATOSHI_MESSAGE_VERSION_t * p_ver)
{
	assert(NULL != p_ver);
	unsigned char * p = NULL;
	if(p_ver->version < 106) return -1;
	
	uint32_t cbUserAgent = VARSTR_get_size(&p_ver->user_agent);	
	p = (unsigned char *)(&p_ver->user_agent) + cbUserAgent;
	
	return *((int32_t *)p);
}

BOOL SATOSHI_MESSAGE_VERSION_set_relay(SATOSHI_MESSAGE_VERSION_t * p_ver, int8_t relay)
{
	assert(NULL != p_ver);
	unsigned char * p = NULL;
	if(p_ver->version < 106) return FALSE;
	
	uint32_t cbUserAgent = VARSTR_get_size(&p_ver->user_agent);	
	p = (unsigned char *)(&p_ver->user_agent) + cbUserAgent + sizeof(int32_t);
	
	*((int8_t *)p) = relay;
	return TRUE;
}

int8_t SATOSHI_MESSAGE_VERSION_get_relay(const SATOSHI_MESSAGE_VERSION_t * p_ver)
{
	assert(NULL != p_ver);
	unsigned char * p = NULL;
	if(p_ver->version < 106) return FALSE;
	
	uint32_t cbUserAgent = VARSTR_get_size(&p_ver->user_agent);	
	p = (unsigned char *)(&p_ver->user_agent) + cbUserAgent + sizeof(int8_t);
	
	return *((int8_t *)p);
}

BOOL SATOSHI_MESSAGE_VERSION_get_user_agent(const SATOSHI_MESSAGE_VERSION_t * p_ver, unsigned char * user_agent, uint32_t * p_cbUserAgent)
{
	assert(NULL != p_ver && NULL != p_cbUserAgent);
	if(p_ver->version < 106) return FALSE;
	
	uint32_t cbUserAgent = VARINT_getdata(& p_ver->user_agent.length);
	if(cbUserAgent > *p_cbUserAgent)
	{
		fprintf(stderr, "Insufficient buffer!\n");
		return FALSE;
	}
	
	*p_cbUserAgent = cbUserAgent;
	if(NULL == user_agent)
	{
		return FALSE;
	}
	
	memcpy(user_agent, VARSTR_getdata(& p_ver->user_agent), cbUserAgent);
	return TRUE;
}



