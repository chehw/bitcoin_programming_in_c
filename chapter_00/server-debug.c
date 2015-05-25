/*
* server-debug.c
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

/*************************************************
 * origin:  beej's simpleserver example
 * url: http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html#simpleserver
 *
 * modified by htc.chehw@gmail.com * 
 * */

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <error.h>
#include <string.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <wait.h>
#include <signal.h>

#include <sys/uio.h>

#include "util.h"
#include "satoshi-protocol.h"

#define SERVER_DEBUG_PORT ("58333")
#define BACKLOG (10)

typedef int RETCODE;

#define MSG_DEBUG ("debug")
#define SERVER_DEBUG_USER_AGENT "/satoshi-0.9.2/debug_server/"

char err_msg[256] = "";

int socket_bind(const char * ip, const char * port)
{
	int sockfd = -1;
	struct addrinfo hints, *servinfo, * p;

	// socklen_t sin_len;
	int yes = 1;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;


	ret = getaddrinfo(ip, port, &hints, &servinfo);
	if (0 != ret)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
		return -1;
	}

	for (p = servinfo; NULL != p; p = p->ai_next)
	{
		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if(-1 == sockfd)
		{
			perror("server: socket");
			continue;
		}
		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
		{
			perror("setsockopt");
			exit(1);
		}

		if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
		{
			close(sockfd);
			perror("server: bind");
			continue;
		}
		break;
	}
	if(NULL == p)
	{

	}
	freeaddrinfo(servinfo);
	return sockfd;
}

void sigchld_handler(int s)
{
	while(waitpid(-1, NULL, WNOHANG) > 0)
	{
		/* UNSAFE: This handler uses non-async-signal-safe functions printf()
		 * just for debug
		 */
		printf("child process terminated (%d).\n", s);
	}
}

void * get_in_addr(struct sockaddr * sa)
{
	switch(sa->sa_family)
	{
	case AF_INET:
		return &(((struct sockaddr_in *)sa)->sin_addr);
	case AF_INET6:
		return &(((struct sockaddr_in6 *)sa)->sin6_addr);
	default:
		break;
	}
	return NULL;
}

int  start_debug(int new_fd, struct sockaddr_storage * peer_addr);

int main(int argc, char ** argv)
{
	int sockfd, new_fd;
	socklen_t sin_len;
	struct sockaddr_storage peer_addr;
	struct sigaction sa;
	pid_t cpid;
	int ret;
	char ip[INET6_ADDRSTRLEN] = "";
	

	const char * serv_ip = "localhost";
	const char * port = SERVER_DEBUG_PORT;
	if(argc > 1) serv_ip = argv[1];
	if(argc > 2) port = argv[2];


	sockfd = socket_bind(serv_ip, port);
	if(-1 == sockfd) return 1;


	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	if(sigaction(SIGCHLD, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(1);
	}

	if(listen(sockfd, BACKLOG) == -1)
	{
		perror("listen");
		exit(EXIT_FAILURE);
	}

	printf("server-debug: (%d) waiting for connectings...\n", sockfd);

	while(1)
	{
		sin_len = sizeof(peer_addr);
		new_fd = accept(sockfd, (struct sockaddr *)&peer_addr, &sin_len);
		if(-1 == new_fd)
		{
			perror("accept");
			continue;
		}

		if(NULL == inet_ntop(peer_addr.ss_family, get_in_addr((struct sockaddr *)&peer_addr), ip, sizeof(ip)))
		{
			perror("inet_ntop");
			close(new_fd);
			continue;
		}

		

		printf("peer ip: %s\n", ip);

		// use a child process to process the connected client's commication
		cpid = fork();
		if(-1 == cpid) 
		{
			// can not fork any child process
			perror("fork");
			close(new_fd);
			exit(EXIT_FAILURE);
		}

		if(0 == cpid) // This is the child process
		{
			printf("Child PID is %ld\n", (long)getpid());
			close(sockfd); // child process doesn't need this

			ret = start_debug(new_fd, &peer_addr);
			printf("end debug.\n");
			close(new_fd);
			
			exit(ret);
		}

		// This is the parent process
		close(new_fd); // do not need the newfd;
	}

	close(sockfd);

	return 0;
	//** 

}


ssize_t send_message(int sockfd, SATOSHI_MESSAGE_HEADER_t * p_hdr, const void * payload, uint32_t cbPayload)
{
	struct iovec msgdata[2] = {{0}};
	hash256_t h_checksum;
	ssize_t cb_sent = 0;
	
	assert(NULL != p_hdr);
	
	err_msg[0] = '\0';
	
	if(NULL == payload)
	{
		cbPayload = 0;
	}
	
	msgdata[0].iov_base = p_hdr;
	msgdata[0].iov_len = sizeof(SATOSHI_MESSAGE_HEADER_t);
	msgdata[1].iov_base = (unsigned char *)payload;
	msgdata[1].iov_len = cbPayload;
	
	p_hdr->length = cbPayload;
	
	if(0 == cbPayload)
	{
		p_hdr->checksum = hash256_checksum_null;
	}else
	{	
		if(hash256(payload, cbPayload, h_checksum.vch) != sizeof(hash256_t))
		{
			strncpy(err_msg, "hash256 error.\n", sizeof(err_msg));
			perror("hash256");
			return -1;
		}
		memcpy(&p_hdr->checksum_b[0], &h_checksum.vch[0], 4);
	}
	
	cb_sent = writev(sockfd, msgdata, 2);
	return cb_sent;
}


ssize_t recv_message(int sockfd, SATOSHI_MESSAGE_HEADER_t * p_hdr, unsigned char ** pp_payload, uint32_t * p_cbPayload, hash256_t * p_hash)
{
	assert(NULL != p_hdr && NULL != pp_payload && NULL != p_cbPayload);
	int cb;
//	hash256_t h_checksum;
	unsigned char * payload = NULL;
	uint32_t cbPayload = 0;
	
	err_msg[0] = '\0';
	
	cb = read(sockfd, p_hdr, sizeof(SATOSHI_MESSAGE_HEADER_t));
	if(cb <= 0)
	{
		perror("socket");
		return -1;
	}
	
	if(cb != sizeof(SATOSHI_MESSAGE_HEADER_t))
	{
		strncpy(err_msg, "Invalid Message Header.\n", sizeof(err_msg));
		fprintf(stderr, "Invalid Message Header.\n");		
		return 0;
	}
	
	cb = 0;
	if(p_hdr->length)
	{
		payload = (unsigned char *)malloc(p_hdr->length);
		if(NULL == payload)
		{
			perror("malloc");
			return -1;
		}
		
		cbPayload = read(sockfd, payload, p_hdr->length);
		if(cbPayload < 0)
		{
			perror("socket");
			free(payload);
			return -1;
		}
		
		if(cbPayload != p_hdr->length)
		{
			sprintf(err_msg, "Data length Incorrect. need: %u, recv: %u.\n", 
				p_hdr->length, cbPayload);
			fprintf(stderr, "%s", err_msg);
			free(payload);
			return 0;
		}
		
		
		
		
	}
	
	hash256(payload, cbPayload, p_hash->vch);
	// verify checksum 
	if(0 != memcmp(&p_hash->vch[0], &p_hdr->checksum, 4))
	{
		sprintf(err_msg, "checksum error.\n");
		fprintf(stderr, "%s", err_msg);
		free(payload);
		return 0;
	}
	
	*pp_payload = payload;
	*p_cbPayload = cbPayload;
	
	return (ssize_t)(cbPayload + sizeof(SATOSHI_MESSAGE_HEADER_t));
}

//** dump_msg_hdr
//** if (unknown type) RETCODE = -1;
static RETCODE dump_msg_hdr(const SATOSHI_MESSAGE_HEADER_t * p_hdr)
{
	const char * p = "known type";
	RETCODE ret = 0;
	if(satoshi_magic_main == p_hdr->magic) p = "bitcoin";
	else if(satoshi_magic_testnet == p_hdr->magic) p = "testnet";
	else if(satoshi_magic_testnet3 == p_hdr->magic) p = "testnet3";
	else if(satoshi_magic_namecoin == p_hdr->magic) p = "namecoin";
	else 
	{
		ret = -1;
	}
	printf("%s\n", p);
	return ret;
}

ssize_t send_error_msg(int sockfd, SATOSHI_MESSAGE_HEADER_t * p_hdr, const char * errText)
{
	assert(NULL != p_hdr);
	ssize_t cb = 0;
	char json[4096] = "";
	char * p = json;
	uint32_t cbJson;	
	hash256_t h_checksum;
	char szHash[65];
	uint32_t cbHash;
	const char * status = "error";
	
	p_hdr->command[sizeof(p_hdr->command) - 1] = '\0';	
	cbHash = sizeof(szHash);
	bin2hex(&h_checksum.vch[0], 32, szHash, &cbHash, 0);
	
	p += sprintf(p, "[\"status\": \"%s\","
					" \"command\": \"[%s] - %s\","
					" \"hash\": \"%s\"]",
					status,
					p_hdr->command, err_msg, 
					szHash
					);
	*p++ = '\0';
	cbJson = p - json;				
	
	uint32_t magic = p_hdr->magic;
	
	memset(p_hdr, 0, sizeof(SATOSHI_MESSAGE_HEADER_t));	
	p_hdr->magic = magic;
	
	strncpy(p_hdr->command, MSG_DEBUG, sizeof(p_hdr->command));
	
	cb = send_message(sockfd, p_hdr, json, cbJson);
	return cb;
}

int  start_debug(int sockfd, struct sockaddr_storage * client_addr)
{	
	printf("start debug...\n");	
	// Todo: dump client addr info
	// ...
		
	ssize_t cb;
	unsigned char * payload;
	uint32_t cbPayload;
	SATOSHI_MESSAGE_HEADER_t msg_hdr;
	
	#define STATUS_JSON_MAX_SIZE (4096)
	char * json = NULL;
	uint32_t cbJson;
	char * p;
	const char * status = "ok";
	
	hash256_t h_checksum;
	char szHash[65] = "";
	uint32_t cbHash;
	
	json = (char *)malloc(STATUS_JSON_MAX_SIZE);
	assert(NULL != json);
		
	
	while(1)
	{
		payload = NULL;
		cbPayload = 0;
		memset(&msg_hdr, 0, sizeof(msg_hdr));
		memset(&h_checksum, 0, sizeof(h_checksum));
		
		// recv the request from the client
		cb = recv_message(sockfd, &msg_hdr, &payload, &cbPayload, &h_checksum);
		if(cb <= 0)
		{	
			if(0 == cb) // maybe a data format error
			{
				send_error_msg(sockfd, &msg_hdr, err_msg);
			}
			break;
		}
		
		msg_hdr.command[11] = '\0';
		printf("==== recv command: [%s], %d bytes received.\n", msg_hdr.command, (int)cb);
		
		// parse message header
		if(-1 == dump_msg_hdr(&msg_hdr))
		{
			send_error_msg(sockfd, &msg_hdr, "unknown network type");
			continue;
		}
		
		// send response to the client		
		printf("==== send response ...\n");
		if(strncmp(msg_hdr.command, SATOSHI_MESSAGE_COMMAND_VERSION, sizeof(msg_hdr.command)) == 0)
		{
			// response on "version" command
			// should send "version" command and "verack" command
			uint32_t magic = msg_hdr.magic;
			const char * user_agent = SERVER_DEBUG_USER_AGENT;
			uint32_t cbUserAgent = strlen(user_agent) + 1; // include terminated '\0'
			SATOSHI_MESSAGE_VERSION_t * p_ver = SATOSHI_MESSAGE_VERSION_new((unsigned char *)user_agent, cbUserAgent, 1, 1);
			uint32_t cbVer = 0;
			assert(NULL != p_ver);
			
			cbVer = SATOSHI_MESSAGE_VERSION_calc_size(p_ver);
			
			memset(&msg_hdr, 0, sizeof(msg_hdr));
			msg_hdr.magic = magic;
			strncpy(msg_hdr.command, SATOSHI_MESSAGE_COMMAND_VERSION, sizeof(msg_hdr.command));
			
			
			// send "version" command
			printf("send version: %p(%u bytes)...\n", p_ver, cbVer);
			cb = send_message(sockfd, &msg_hdr, p_ver, cbVer);
			if(cb <= 0)
			{
				// an error occured
				SATOSHI_MESSAGE_VERSION_free(p_ver);
				break;
			}
			SATOSHI_MESSAGE_VERSION_free(p_ver);
			printf("======== send version: %d bytes\n", (int)cb);
			
			
			
			// send "verack" command
			memset(&msg_hdr, 0, sizeof(msg_hdr));
			msg_hdr.magic = magic;
			strncpy(msg_hdr.command, SATOSHI_MESSAGE_COMMAND_VERACK, sizeof(msg_hdr.command));
			
			cb = send_message(sockfd, &msg_hdr, NULL, 0);
			if(cb <= 0)
			{
				// an error occured
				fprintf(stderr, "send_message verack error.\n");
				break;
			}
			
			printf("======== send verack: %d bytes\n", (int)cb);
			
		}else
		{
			// send debug status
			p = json;
			status = "ok";
			msg_hdr.command[sizeof(msg_hdr.command) - 1] = '\0';
			
			cbHash = sizeof(szHash);
			bin2hex(&h_checksum.vch[0], 32, szHash, &cbHash, 0);
			
			p += sprintf(p, "[\"status\": \"%s\","
							" \"command\": \"[%s]\","
							" \"hash\": \"%s\"]",
							status,
							msg_hdr.command,  
							szHash
							);
			*p++ = '\0';	
			cbJson = p - json;
			
			uint32_t magic = msg_hdr.magic;
			memset(&msg_hdr, 0, sizeof(msg_hdr));
			
			msg_hdr.magic = magic;
			strncpy(msg_hdr.command, MSG_DEBUG, sizeof(msg_hdr.command));
			
			cb = send_message(sockfd, &msg_hdr, json, cbJson);
			
			printf("send status: %d bytes sent.\n", (int)cb);			
		}
	}
	free(json);
	return 0;
}
