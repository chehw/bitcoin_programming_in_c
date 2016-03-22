/*
 * main.c
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
#include <stdlib.h>
#include <pthread.h>


#include "global.h"
#include "sig_handler.h"

#include "chutil.h"
#include "base58.h"


#include "init.impl.h"

#include "merkle_tree.h"

#include "node.h"
#include "satoshi_protocol.h"

global_param_t global = {
		PTHREAD_MUTEX_INITIALIZER,
		SATOSHI_MAGIC_TESTNET3,
		"127.0.0.1",
		"43690",
		"data",
		0,
		0
};

volatile int quit;
uint32_t SATOSHI_MAGIC = SATOSHI_MAGIC_TESTNET3;
static int msg_handler(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload);


static void * server_thread(void * user_data)
{
	int rc;
	rc = node_run(NULL, NULL, msg_handler);
	if(!quit) quit = 1;
	pthread_exit((void *)(long)rc);
}

static void * client_thread(void * user_data)
{
	int rc;
	const char * serv_name = "127.0.0.1";
	const char * port = "18333";
	
	rc = satoshi_client_connect2(serv_name, port, NULL, msg_handler);
	if(-1 == rc)
	{
		debug_printf("ERROR: satoshi_client_connect2.\n");
	}
	
	pthread_exit((void *)(long)rc);
}


int main(int argc, char **argv)
{
	register_sig_handler(NULL, 0, NULL, NULL);	
	parse_args(&argc, &argv);
	
	pthread_t th[2];
	int rc;
	
	rc = pthread_create(&th[0], NULL, server_thread, NULL);
	if(0 != rc)
	{
		perror("pthread_create server_thread");
		exit(1);
	}
	
	rc = pthread_create(&th[1], NULL, client_thread, NULL);
	if(0 != rc)
	{
		perror("pthread_create client_thread");
		exit(1);
	}
	
	
	
	poll_stdin("");
	
	pthread_join(th[0], NULL);
	pthread_join(th[1], NULL);
	
	pthread_mutex_destroy(&global.mutex);
	return 0;
	
	return 0;
}



static int on_msg_version(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_version: (length = %u)\n", p_hdr->length);


	if(p_hdr->length == 0) {
		// send reject msg
		// ...
		
		return -1;
	}
	
	
	
	// copy peer's verion info
	satoshi_msg_version_t * p_ver;
	p_ver = (satoshi_msg_version_t *)malloc(p_hdr->length);
	assert(NULL != p_ver);
	
	memcpy(p_ver, payload, p_hdr->length);
	
	if(NULL != peer->p_version)
	{
		satoshi_msg_version_destroy(peer->p_version);
	}
	peer->p_version = p_ver;
	
#ifdef _DEBUG
	satoshi_msg_version_dump(peer->p_version);
#endif
	return 0;
}
static int on_msg_verack(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_verack: (length = %u)\n", p_hdr->length);
	//~ static const uint32_t null_checksum = 0xE2E0F65D;
	//~ if(p_hdr->checksum != null_checksum)
	//~ {
		//~ // checksum error
		//~ debug_printf("ERROR: checksum error on '%s'\n", p_hdr->command);
	//~ }
	return 0;
}

static int on_msg_addr(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_addr: (length = %u)\n", p_hdr->length);
	return 0;
}

static int on_msg_inv(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_inv: (length = %u)\n", p_hdr->length);
	return 0;
}

static int on_msg_getdata(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_getdata: (length = %u)\n", p_hdr->length);
	return 0;
}

static int on_msg_notfound(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_notfound: (length = %u)\n", p_hdr->length);
	return 0;
}

static int on_msg_getblocks(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_getblocks: (length = %u)\n", p_hdr->length);
	return 0;
}

static int on_msg_getheaders(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_getheaders: (length = %u)\n", p_hdr->length);
	return 0;
}

static int on_msg_tx(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_tx: (length = %u)\n", p_hdr->length);
	return 0;
}

static int on_msg_block(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_block: (length = %u)\n", p_hdr->length);
	return 0;
}
static int on_msg_headers(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_headers: (length = %u)\n", p_hdr->length);
	return 0;
}
static int on_msg_getaddr(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_getaddr: (length = %u)\n", p_hdr->length);
	return 0;
}
static int on_msg_mempool(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_mempool: (length = %u)\n", p_hdr->length);
	return 0;
}
static int on_msg_ping(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_ping: (length = %u)\n", p_hdr->length);
	
	if(p_hdr->length != 8)
	{
		debug_printf("ERROR: invalid msg length on [fd = %d], command = '%s', length = %u\n",
			peer->fd,
			p_hdr->command, 
			p_hdr->length);
		return -1;
	}
	
	peer->ping = *(uint64_t *)payload;
	// send 'pong'
	
	log_printf("send pong.\n");
	pthread_mutex_lock(&peer->send_mutex);
	
	int n;
	struct pollfd pfd;
	struct timespec timeout = {0, 500000000}; // 500 ms
	memset(&pfd, 0, sizeof(pfd));
	
	pfd.fd = peer->fd;
	pfd.events = POLLOUT;
	
	int rc = -1;
	
	n = ppoll(&pfd, 1, &timeout, &sig_masks);
	if(n < 0)
	{
		perror("ppoll");		
	}
	else if(0 == n) // timeout
	{
		
	}else
	{
		ssize_t cb = write(peer->fd, &peer->ping, 8);
		if(cb == 8) rc = 0;
	}
	
	pthread_mutex_unlock(&peer->send_mutex);
	return rc;
}
static int on_msg_pong(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_pong: (length = %u)\n", p_hdr->length);
	return 0;
}
static int on_msg_reject(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_reject: (length = %u)\n", p_hdr->length);
	return 0;
}
static int on_msg_filterload(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_filterload: (length = %u)\n", p_hdr->length);
	return 0;
}
static int on_msg_filteradd(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_filteradd: (length = %u)\n", p_hdr->length);
	return 0;
}
static int on_msg_filterclear(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_filterclear: (length = %u)\n", p_hdr->length);
	return 0;
}
static int on_msg_merkleblock(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_merkleblock: (length = %u)\n", p_hdr->length);
	return 0;
}
static int on_msg_alert(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_alert: (length = %u)\n", p_hdr->length);
	return 0;
}

static int on_msg_sendheaders(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert((NULL != p_hdr) && (NULL != peer));
	log_printf("on_msg_sendheaders: (length = %u)\n", p_hdr->length);
	return 0;
}


static int msg_handler(peer_info_t * peer, satoshi_msg_header_t * p_hdr, void * payload)
{
	assert(NULL != p_hdr && NULL != peer);
	
	log_printf("magic = 0x%.8x, command = %12s, length = %d, checksum = 0x%.8x\n", 
		p_hdr->magic, p_hdr->command, p_hdr->length, p_hdr->checksum);
		
	if(strncmp(p_hdr->command, "version", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_version(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "verack", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_verack(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "addr", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_addr(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "inv", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_inv(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "getdata", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_getdata(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "notfound", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_notfound(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "getblocks", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_getblocks(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "getheaders", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_getheaders(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "tx", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_tx(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "block", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_block(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "headers", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_headers(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "getaddr", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_getaddr(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "mempool", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_mempool(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "ping", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_ping(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "pong", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_pong(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "reject", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_reject(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "filterload", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_filterload(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "filteradd", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_filteradd(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "filterclear", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_filterclear(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "merkleblock", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_merkleblock(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "alert", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_alert(peer, p_hdr, payload);
	}else if(strncmp(p_hdr->command, "sendheaders", sizeof(p_hdr->command)) == 0)
	{
		return on_msg_sendheaders(peer, p_hdr, payload);
	}
	else
	{
		log_printf("unsupported command (%.12s).\n", p_hdr->command);
		return 0;
	}
	return 0;
}
