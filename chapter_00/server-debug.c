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

#define SERVER_DEBUG_PORT ("58333")
#define BACKLOG (10)

int socket_bind(const char * ip, const char * port)
{
	int sockfd = -1;
	struct addrinfo hints, *servinfo, * p;

	socklen_t sin_len;
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

int  start_debug(int new_fd, struct sockaddr_storage * peer_addr)
{
	int ret = 0;
	printf("start debug...\n");
	
	ssize_t cb;
	unsigned char buffer[4096 + 1];
	char json[4096] = "";
	char * p = json;
	
	int cbWrite = 0;
	while(1)
	{
		cb = recv(new_fd, buffer, sizeof(buffer) - 1, 0);
		if(cb < 0 || 0 == cb) 
		{
			printf("cb = %d, disconnected.\n", cb);
			break;
		}
		
	//	buffer[4096] = 0;
		printf("cb = %d\n", cb);
		if(cb) 
		{
			buffer[cb] = 0;
			printf("msg(%d): %s\n", cb, (char *)buffer);
			if(strcmp((char *)buffer, "debug_exit") == 0)
			{
				break;
			}
			cbWrite = sprintf(p, "[\"status\": \"ok\", \"message\": \"debug\"]");
			p += cbWrite;
			
			cb = send(new_fd, json, cbWrite, 0);
			if(cb != cbWrite) break;
		}
	}
	
	return 0;
}
