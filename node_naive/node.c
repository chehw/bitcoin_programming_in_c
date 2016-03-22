/*
 * node.c
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
#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <poll.h>

#include <time.h>
#include <sys/time.h>


#include <pthread.h>
#include <search.h>
#include <unistd.h>
#include <fcntl.h>

#include <assert.h>
#include <errno.h>

#include "chutil.h"

#include "global.h"
#include "node.h"



static int default_msg_handler(peer_info_t * peer, satoshi_msg_header_t * msg_hdr, void * payload)
{
	int rc = 0;
	// verify checksum
	unsigned char hash[32];
	log_printf("default_msg_handler: length = %u, payload = %p\n", 
		msg_hdr->length, payload);
	
	hash256(payload, msg_hdr->length, hash);
	if(memcmp(&msg_hdr->checksum, hash, 4) != 0)
	{
		// checksum failed.
		debug_printf("ERROR: checksum error on [fd = %d], command = '%s'\n",
			peer->fd, 
			msg_hdr->command);
		return -1;
	}
	
	
	if( (peer->msg_handler != NULL) && (peer->msg_handler != default_msg_handler) )
	{
		// user defined callback
		rc = peer->msg_handler(peer, msg_hdr, payload);
	}
	
	// do cleanup:
	//     reset peer's payload buffer
	peer->bytes_read = -1;
	if(NULL != peer->payload)
	{
		free(peer->payload);
		peer->payload = NULL;
	}
	
	return rc;
}

peer_info_t * peer_info_init(peer_info_t * peer, int fd, MSG_HANDLER_PROC _msg_handler)
{
	peer_info_t * pi = peer;
	if(NULL == pi) pi = (peer_info_t *)malloc(sizeof(peer_info_t));
	assert(NULL != pi);
	memset(pi, 0, sizeof(peer_info_t));
	
	if(0 != pthread_mutex_init(&pi->send_mutex, NULL))
	{
		perror("pthread_mutex_init");
		if(NULL == peer) free(pi);
		return NULL;
	}
	
	pi->fd = fd;
	
	pi->stime = time(NULL);
	pi->ltime = pi->stime;
	
	pi->bytes_read = -1;
	pi->bytes_written = -1;
	
	//~ if(NULL == _msg_handler) _msg_handler = default_msg_handler;
	pi->msg_handler = _msg_handler;
	
	return pi;
}

void peer_info_destroy(peer_info_t * peer)
{
	if(NULL == peer) return;
	pthread_mutex_lock(&peer->send_mutex);
	if(-1 != peer->fd) 
	{
		shutdown(peer->fd, SHUT_RDWR);
		close(peer->fd);
		peer->fd = -1;
	}
	
	if(NULL != peer->p_version)
	{
		satoshi_msg_version_destroy(peer->p_version);
		peer->p_version = NULL;
	}
	
	if(NULL != peer->payload) 
	{
		free(peer->payload);
		peer->payload = NULL;
		peer->bytes_read = -1;
	}
	if(NULL != peer->send_data) 
	{
		free(peer->send_data);
		peer->send_data = NULL;
		peer->bytes_written = -1;
	}
	
	pthread_mutex_unlock(&peer->send_mutex);
	pthread_mutex_destroy(&peer->send_mutex);
	free(peer);
}

static void on_error(int efd, struct epoll_event * p_event)
{
	assert(NULL != p_event);
	peer_info_t * peer = (peer_info_t *)p_event->data.ptr;
	assert(NULL != peer);
	peer_info_destroy(peer);
}

static int on_accept(int efd, struct epoll_event * p_event, MSG_HANDLER_PROC _msg_handler)
{
	int rc;
	int fd;
	
	struct sockaddr_storage ss;
	socklen_t len;
	
	int sfd = p_event->data.fd;
	
	while(1)
	{
		rc = 0;
		len = sizeof(ss);
		fd = accept(sfd, (struct sockaddr *)&ss, &len);
		if(-1 == fd)
		{
			rc = errno;
			if(EAGAIN == errno || EWOULDBLOCK == errno)
			{
				// all incomming connections have been processed
				break;
			}
			perror("accept");
			break;
		}
		
		rc = chutil_make_non_blocking(fd);
		if(0 != rc) 
		{
			fprintf(stderr, "ERROR: chutil_make_non_blocking failed.\n");
			close(fd);
			break;
		}
		
		// display connection info
		char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
		rc = getnameinfo((struct sockaddr *)&ss, len, 
			hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), 
			NI_NUMERICHOST | NI_NUMERICSERV);
		if(0 == rc)
		{
			log_printf("Accepted connection on: [%s:%s] ...\n", hbuf, sbuf);
		}
		
		struct epoll_event event;
		memset(&event, 0, sizeof(event));
		peer_info_t * peer = peer_info_init(NULL, fd, _msg_handler);
		assert(NULL != peer);
		
		memcpy(&peer->ss, &ss, sizeof(ss));		
		event.data.ptr = peer;
		event.events = EPOLLIN | EPOLLET;
		rc = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
		if(0 != rc)
		{
			peer_info_destroy(peer);			
			perror("epoll_ctl");
			continue;
		}
	}
	
	return rc;
}

static const char * peer_info_parse_header(peer_info_t * peer, const char * p_begin, const char * p_end)
{	
	int rc;
	assert((NULL != peer) && (NULL != p_begin) && (p_begin < p_end));	
	const char * p = p_begin;
	satoshi_msg_t * p_msg = (satoshi_msg_t * )p_begin;
	
	memcpy(&peer->msg_hdr, &p_msg->hdr, sizeof(satoshi_msg_header_t));	
	
	p += sizeof(satoshi_msg_header_t);
	
	peer->bytes_read = 0;
	
	if(p_msg->hdr.length == 0)
	{
		rc = default_msg_handler(peer, &p_msg->hdr, p_msg->payload);
		if(0 != rc) return NULL;
			
	}else
	{
		satoshi_msg_header_t * p_hdr = &p_msg->hdr;
		if(p_msg->hdr.length > MAX_SATOSHI_MSG_PAYLOAD_LENGTH)
		{
			debug_printf("ERROR: invalid payload length.\n");
			return NULL;
		}
		
		// allocate memory and copy payload data
		size_t cb = p_end - p;
		if(cb > p_hdr->length) cb = p_hdr->length;
		
		unsigned char * payload = (unsigned char *)malloc(p_hdr->length);
		if(NULL == payload)
		{
			debug_printf("ERROR: insufficient memory.\n");
			return NULL;
		}
		peer->payload = payload;
		memcpy(payload, p, cb);
		p += cb;
		peer->bytes_read = cb;
		if(cb == p_hdr->length)
		{
			rc = default_msg_handler(peer, p_hdr, payload);
			if(0 != rc) return NULL;
		}
	}
	return p;
}

static const char * peer_info_append_payload(peer_info_t * peer, const char * p_begin, const char * p_end)
{
	assert(NULL != peer && NULL != p_begin && (p_begin < p_end));	
	assert(NULL != peer->payload);
	
	size_t cb = p_end - p_begin;
	if((peer->bytes_read + cb) > peer->msg_hdr.length) cb = peer->msg_hdr.length - peer->bytes_read;
	
	memcpy(peer->payload + peer->bytes_read, p_begin, cb);	
	peer->bytes_read += cb;
	
	if(peer->bytes_read == peer->msg_hdr.length)
	{
		int rc = default_msg_handler(peer, &peer->msg_hdr, peer->payload);
		if(0 != rc) return NULL;
	}	
	p_begin += cb;
	
	return (p_begin);
	
}

static int on_read(int efd, struct epoll_event * p_event)
{
	log_printf("on_read: %p\n", p_event->data.ptr);
	int done = 0;
	
	assert(NULL != p_event);
	peer_info_t * peer = (peer_info_t *)p_event->data.ptr;
	assert(NULL != peer);
	
	char * buf;
	size_t size;
	int fd = peer->fd;
	
	while(1)
	{
		ssize_t len;
		buf = &peer->rbuf[peer->cb_rbuf];
		size = sizeof(peer->rbuf) - peer->cb_rbuf;
		
		len = read(fd, buf, size);
		log_printf("bytes read: %d\n", (int)len);
		if(len < 0)
		{
			if(EAGAIN != errno)
			{
				perror("read");
				done = 1;				
			}
			break;
		}
		else if(0 == len) // remote closed
		{
			done = 1;
			break;
		}
		
		peer->cb_rbuf += len;
		const char * p = buf;
		const char * p_end = p + len;
		
		while(p && (p < p_end))
		{
			size_t cb_avail = p_end - p;
			//~ log_printf("p = %p, p_end = %p, cb_avail = %lu\n", p, p_end, cb_avail);
			if(-1 == peer->bytes_read)
			{
				if(cb_avail < sizeof(satoshi_msg_header_t))
				{
					break; 
				}
				p = peer_info_parse_header(peer, p, p_end);
			}else
			{
				p = peer_info_append_payload(peer, p, p_end);
			}
			
			if(NULL == p) // error
			{
				done = 1;
				goto label_exit;
			}
		}
		
		peer->cb_rbuf = p_end - p;
		if(peer->cb_rbuf)
		{
			memmove(peer->rbuf, p, peer->cb_rbuf);
			break;
		}
	}

label_exit:
	if(done)
	{
		struct epoll_event event;
		event.data.ptr = peer;
		event.events = 0;
		epoll_ctl(efd, EPOLL_CTL_DEL, fd, &event);
		
		debug_printf("Connection closed on [fd = %d]\n", fd);
		
		peer_info_destroy(peer);
		return 1;
	}
	log_printf("on_read finished.\n");
	return 0;
}


int node_run(const char * serv_name, const char * port, MSG_HANDLER_PROC _msg_handler)
{
	int rc;
	int sfd;
	struct addrinfo hints, * serv_info, * p;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	
	if(NULL == serv_name) serv_name = global.serv_name;
	if(NULL == port) port = global.port;
	
	rc = getaddrinfo(serv_name, port, &hints, &serv_info);
	if(0 != rc)
	{
		debug_printf("ERROR: getaddrinfo: %s\n", gai_strerror(rc));
		return rc;
	}
	for(p = serv_info; NULL != p; p = p->ai_next)
	{
		sfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if(-1 == sfd) continue;
		rc = bind(sfd, p->ai_addr, p->ai_addrlen);
		if(0 == rc) break;
		close(sfd);
	}
	if(NULL == p)
	{
		debug_printf("Could not bind to [%s:%s]\n", serv_name, port);
		freeaddrinfo(serv_info);
		close(sfd);
		return -1;
	}
	
	// display bind status
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	rc = getnameinfo((struct sockaddr *)p->ai_addr, p->ai_addrlen, 
		hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), 
		NI_NUMERICHOST | NI_NUMERICSERV);
	
	freeaddrinfo(serv_info);
	if(0 == rc)
	{
		log_printf("Listening on: [%s:%s] ...\n", hbuf, sbuf);
	}
	
	rc = chutil_make_non_blocking(sfd);
	if(0 != rc)
	{
		debug_printf("ERROR: chutil_make_non_blocking failed.\n");
		close(sfd);
		return -1;
	}
	
	// listen and wait for incomming connections
	rc = listen(sfd, SOMAXCONN);
	if(0 != rc)
	{
		perror("listen");
		close(sfd);
		return -1;
	}
	
	int efd;
#define MAX_EVENTS 64
	struct epoll_event event, events[MAX_EVENTS];
	memset(&event, 0, sizeof(event));
	memset(events, 0, sizeof(events));
	
	event.data.fd = sfd;
	event.events = EPOLLIN | EPOLLET;
	
	efd = epoll_create1(0);
	if(-1 == efd)
	{
		perror("epoll_create");
		close(sfd);
		return -1;
	}
	
	rc = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
	if(0 != rc)
	{
		perror("epoll_ctl add");
		close(sfd);
		return -1;
	}
	
	int timeout = 1000; // 1000 ms
	int err_code = 0;
	while(!quit)
	{
		int n, i;
		n = epoll_pwait(efd, events, MAX_EVENTS, timeout, &sig_masks);
		if(n < 0)
		{
			perror("epoll_pwait");
			break;
		}else if(n == 0)
		{
			// timeout
			// do some cleanup
			continue;
		}
		
		for(i = 0; (i < n) && (!quit); ++i)
		{
			if( (events[i].events & EPOLLERR) 	|| (events[i].events & EPOLLHUP) ||
				(events[i].events & EPOLLRDHUP) ||
				!(events[i].events & EPOLLIN) )
			{
				err_code = errno;
				debug_printf("WARNING: epoll_wait on (fd = %d): %s\n", 
					events[i].data.fd,
					strerror(err_code));
				if(events[i].data.fd == sfd)
				{
					close(sfd);
					quit = 1;
					break;
				}
				
				on_error(efd, &events[i]);
				continue;
			}else if(events[i].data.fd == sfd) // incomming connections
			{
				if(0 != on_accept(efd, &events[i], _msg_handler))
				{
					// error handler
				}
				continue;
			}else // data received 
			{
				if(0 != on_read(efd, &events[i]))
				{
					// error handler
				}
				continue;
			}
		}
	}
	
	close(efd);
	close(sfd);
	
#undef MAX_EVENTS

	return err_code;
}

int satoshi_client_connect2(const char * serv_name, const char * port, const satoshi_msg_version_t * p_ver, MSG_HANDLER_PROC _msg_handler)
{
	int fd;
	int rc;
	if(NULL == serv_name) serv_name = global.serv_name;
	if(NULL == port) port = global.port;
	
	if(SATOSHI_MAGIC == SATOSHI_MAGIC_MAIN) port = "8333";
	
	struct addrinfo hints, * serv_info = NULL, * pi;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	rc = getaddrinfo(serv_name, port, &hints, &serv_info);
	if(0 != rc)
	{
		fprintf(stderr, "ERROR: getaddrinfo: %s\n", gai_strerror(rc));
		return -1;
	}
	int connected = 1;
	int efd;

#define MAX_EVENTS 16
	efd = epoll_create1(0);
	struct epoll_event event, events[MAX_EVENTS];
	memset(&event, 0, sizeof(event));
	memset(events, 0, sizeof(events));
	
	int timeout = 1000;
	unsigned char hash[32];
	
	int ver_send = 0;
	const int max_payload_size = 4096;
	satoshi_msg_t * p_msg = (satoshi_msg_t *)calloc(
			sizeof(satoshi_msg_header_t) + max_payload_size, 1);
	assert(NULL != p_msg);
	p_msg->hdr.magic = SATOSHI_MAGIC;
	strcpy(p_msg->hdr.command, "version");
	int height = 1;
	bool relay = 1;
	
	char user_agent[] = "/bitcoin-c:0.1.99/";
	size_t cb_user_agent = strlen(user_agent);// + 1;
	
	
	
	for(pi = serv_info; pi != NULL; pi = pi->ai_next)
	{
		fd = socket(pi->ai_family, pi->ai_socktype, pi->ai_protocol);
		if(-1 == fd) continue;
		
		rc = chutil_make_non_blocking(fd);
		if(0 != rc)
		{
			close(fd);
			continue;
		}
		rc = connect(fd, pi->ai_addr, pi->ai_addrlen);
		if(0 != rc)
		{
			if(errno != EINPROGRESS) 
			{
				close(fd);
				continue;
			}
			connected = 0;
		}
		
		
		event.data.fd = fd;
		event.events = EPOLLOUT;
		
		rc = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
		if(0 != rc)
		{
			perror("epoll_ctl");
			close(fd);
			continue;
		}
		int conn_tries = 0;
		
		while(!connected)
		{
			int n, i;
			n = epoll_pwait(efd, events, MAX_EVENTS, timeout, &sig_masks);
			if(n < 0)
			{
				perror("epoll_pwait");
				close(fd);
				break;
			}
			if(n == 0)
			{
				++conn_tries;
				if(conn_tries >= 3)
				{
					debug_printf("ERROR: connection timeout\n");
					close(fd);
					break;
				}
				continue;
			}
			
			for(i = 0; i < n; ++i)
			{
				if((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP))
				{
					debug_printf("ERROR: epoll_wait error.\n");
					close(fd);
					fd = -1;
					break;
				}
				
				if(events[i].events & EPOLLOUT)
				{
					if(!connected)
					{
						int err_code = 0;
						socklen_t len = sizeof(int);
						rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err_code, &len);
						if(-1 != rc)
						{
							if(0 == err_code)
							{
								connected = 1;
								// display connection info
								char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
								rc = getnameinfo(pi->ai_addr, pi->ai_addrlen, 
									hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
									NI_NUMERICHOST | NI_NUMERICSERV);
									
								if(0 == rc)
								{
									log_printf("Connected to [%s:%s]\n", hbuf, sbuf);
								}
							}
						}
					}else
					{
						// send version info
						log_printf("connect and send version\n");
						if(NULL == p_ver)
						{
							p_ver = satoshi_msg_version_init(
								(satoshi_msg_version_t *)p_msg->payload,
								SATOSHI_PROTOCOL_VERSION,
								1,
								pi->ai_addr,
								NULL,
								user_agent, 
								cb_user_agent,
								height,
								relay);
							assert(NULL != p_ver);
						}else
						{
							memcpy(p_msg->payload, p_ver, satoshi_msg_version_size(p_ver));
						}
						p_msg->hdr.length = (uint32_t)satoshi_msg_version_size(p_ver);
						hash256(p_ver, p_msg->hdr.length, hash);
						p_msg->hdr.checksum = *(uint32_t *)hash;
						
						ssize_t cb = write(fd, p_msg, sizeof(satoshi_msg_header_t) + p_msg->hdr.length);
						if(cb != sizeof(satoshi_msg_header_t) + p_msg->hdr.length)
						{
							perror("write");
							close(fd);
							fd = -1;
							connected = 0;
							break;
							
						}
						ver_send = 1;
					}
				}
				
			}
			if(-1 == fd) break;
		} // while not connected
		if(!connected) 
		{
			//~ close(fd);
			if(-1 != fd) close(fd);
			printf("not connected\n");
			continue;
		}
		
		break;
		
	}
	
	if(NULL == pi)
	{
		debug_printf("Could not connect to [%s:%s]\n", serv_name, port);
		freeaddrinfo(serv_info);
		close(efd);
		if(NULL != p_msg) free(p_msg);
		return -1;
	}
	
	
	// send version info
	if(!ver_send)
	{
		if(NULL == p_ver)
		{
			p_ver = satoshi_msg_version_init(
				(satoshi_msg_version_t *)p_msg->payload,
				SATOSHI_PROTOCOL_VERSION,
				1,
				pi->ai_addr,
				NULL,
				user_agent, 
				cb_user_agent,
				height,
				relay);
			assert(NULL != p_ver);
		}else
		{
			memcpy(p_msg->payload, p_ver, satoshi_msg_version_size(p_ver));
		}
		p_msg->hdr.length = (uint32_t)satoshi_msg_version_size(p_ver);
		hash256(p_ver, p_msg->hdr.length, hash);
		p_msg->hdr.checksum = *(uint32_t *)hash;
		
		int n, i;
		n = epoll_pwait(efd, events, MAX_EVENTS, timeout, &sig_masks);
		if(n < 0)
		{
			perror("epoll_pwait");
			exit(1);
		}else if(n == 0)
		{
			// timeout
			debug_printf("send version timeout.\n");
			exit(1);
		}
		for(i = 0; i < n; ++i)
		{
			if((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP))
			{
				debug_printf("ERROR: epoll_wait error.\n");
				exit(1);
			}
			if(events[i].events & EPOLLOUT && events[i].data.fd == fd)
			{
				// send version info
				ssize_t cb = write(fd, p_msg, sizeof(satoshi_msg_header_t) + p_msg->hdr.length);
				if(cb != sizeof(satoshi_msg_header_t) + p_msg->hdr.length)
				{
					perror("write");
					close(fd);
					connected = 0;
					break;
					
				}
				ver_send = 1;
				log_printf("sended\n");
				break;
			}
		}
	}
	
	
	
	// waiting for imcomming data
	
	peer_info_t * peer = NULL;
	peer = peer_info_init(NULL, fd, _msg_handler);
	assert(NULL != peer);
	memcpy(&peer->ss, pi->ai_addr, pi->ai_addrlen);
	freeaddrinfo(serv_info);
	
	log_printf("peer = %p\n", peer);
	
	memset(&event, 0, sizeof(event));
	memset(events, 0, sizeof(events));
	event.events = EPOLLIN | EPOLLET;
	event.data.ptr= peer;
	rc = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
	if(0 != rc)
	{
		perror("epoll_ctl mod");
		close(fd);
		close(efd);
		peer_info_destroy(peer);
		return -1;
	}
	
	while(!quit)
	{
		int n, i;
		n = epoll_pwait(efd, events, MAX_EVENTS, timeout, &sig_masks);
		if(n < 0)
		{
			perror("epoll_pwait");
			break;
		}else if(n == 0)
		{
			// timeout
			continue;
		}
		
		for(i = 0; i < n; ++i)
		{
			if((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) ||
				(events[i].events & EPOLLRDHUP))
			{
				debug_printf("ERROR: epoll_wait.\n");
				continue;
			}
			if((events[i].events & EPOLLIN) && (events[i].data.ptr == peer))
			{
				rc = on_read(efd, &events[i]);
				if(0 != rc)
				{
					debug_printf("ERROR: read error.\n");
					break;
				}
			}
		}
	}
	
	close(efd);
	close(fd);
	
	if(NULL != p_msg)
	{
		free(p_msg);
	}
	
	log_printf("disconnected\n");
	
#undef MAX_EVENTS
	return 0;
}






