/*
 * satoshi_protocol.c
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
#include "satoshi_protocol.h"
#include <time.h>
#include <sys/time.h>

#include <inttypes.h>

#include <sys/socket.h>
#include <netdb.h>



satoshi_msg_version_t * satoshi_msg_version_init(
	satoshi_msg_version_t * p_ver,
	uint32_t protocol_version,
	uint64_t services,
	struct sockaddr * addr_recv, 
	struct sockaddr * addr_from,
	const char * user_agent, size_t cb_user_agent, 
	int start_height, bool relay)
{
	unsigned char * p;
	if(NULL == p_ver)
	{
		if((-1 == cb_user_agent) && (NULL != user_agent)) cb_user_agent = strlen(user_agent);
		if(cb_user_agent > MAX_SATOSHI_USER_AGENT_LENGTH) return NULL;
		
		size_t size = (size_t)&((satoshi_msg_version_t *)NULL)->user_agent;
		printf("size without user_agent = %lu\n", size);
		size_t cb_vint = varint_calc_size(cb_user_agent);
		size += cb_vint + cb_user_agent + sizeof(int32_t); // start_height
	#if SATOSHI_PROTOCOL_VERSION >= 70001
		size += sizeof(bool);
	#endif
		
		p_ver = (satoshi_msg_version_t *)calloc(size, 1);
		assert(NULL != p_ver);
	}
	
	p_ver->protocol_version = protocol_version;
	p_ver->services = services;
	p_ver->timestamp = time(NULL);
	if(NULL != addr_recv)
	{
		p_ver->addr_recv.services = services;
		satoshi_addr_legacy_set_ip(&p_ver->addr_recv, addr_recv);
	}
	
	if(NULL != addr_from)
	{
		p_ver->addr_from.services = services;
		satoshi_addr_legacy_set_ip(&p_ver->addr_from, addr_from);
	}
	struct timeval tv = {0};
	gettimeofday(&tv, NULL);
	p_ver->nonce = (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec; 
	
	p = (unsigned char *)&p_ver->user_agent;
	varstr_set_data(&p_ver->user_agent, user_agent, cb_user_agent);
	
	p += varstr_size(&p_ver->user_agent);
	*(int32_t *)p = start_height;
#if SATOSHI_PROTOCOL_VERSION >= 70001
	p += sizeof(int32_t);
	*(bool *)p = relay;
#endif
	return p_ver;
}

void satoshi_msg_version_dump(const satoshi_msg_version_t * p_ver)
{
	struct tm * t;
	printf("protocol_version: %u\n", p_ver->protocol_version);
	printf("service: 0x%"PRIx64"\n", p_ver->services);
	time_t timestamp = p_ver->timestamp;
	t = localtime(&timestamp);
	
	printf("timestamp: %lu (%.4d-%.2d-%.2d %.2d:%.2d:%.2d GMT+8)\n", 
		p_ver->timestamp,
		t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
		t->tm_hour, t->tm_min, t->tm_sec);
	dump_line(stdout, "addr recv", p_ver->addr_recv.ip, 16);
	
	
	
	struct sockaddr_in6 in6;
	memset(&in6, 0, sizeof(in6));
	in6.sin6_family = AF_INET6;
	in6.sin6_port = p_ver->addr_recv.port;
	memcpy(&in6.sin6_addr, p_ver->addr_recv.ip, 16);
	
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	int rc = getnameinfo((struct sockaddr *)&in6, sizeof(in6),
		hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
		NI_NUMERICHOST | NI_NUMERICSERV);
	if(0 == rc)
	{
		printf("addr_recv: %s:%s\n", hbuf, sbuf);
	}
	
	memset(&in6, 0, sizeof(in6));
	in6.sin6_family = AF_INET6;
	in6.sin6_port = p_ver->addr_from.port;
	memcpy(&in6.sin6_addr, p_ver->addr_from.ip, 16);
	
	
	rc = getnameinfo((struct sockaddr *)&in6, sizeof(in6),
		hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
		NI_NUMERICHOST | NI_NUMERICSERV);
	if(0 == rc)
	{
		printf("addr_from: %s:%s\n", hbuf, sbuf);
	}
	
	size_t cb_vstr = varstr_size(&p_ver->user_agent);
	printf("nonce: %"PRIu64"\n", p_ver->nonce);
	printf("user_agent: (size = %lu), ", cb_vstr);
	fwrite(varstr_get_ptr(&p_ver->user_agent),  1, varstr_strlen(&p_ver->user_agent), stdout);
	printf("\n");
	
	unsigned char * p = (unsigned char *)&p_ver->user_agent;
	p += cb_vstr;
	printf("start_height = %d\n", *(uint32_t *)p);
	p += 4;
	printf("relay: %d\n", (int)*(bool *)p);
	
}
