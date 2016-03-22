#ifndef _NODE_H_
#define _NODE_H_

#include "satoshi_protocol.h"

#define MAX_SATOSHI_MSG_PAYLOAD_LENGTH (1 << 28) // 256 MB
//~ 
//~ typedef struct satoshi_msg_header
//~ {
	//~ uint32_t magic;
	//~ char command[12];
	//~ uint32_t length;
	//~ uint32_t checksum;
//~ }satoshi_msg_header_t;


typedef struct peer_info peer_info_t;

typedef int (MSG_HANDLER_PROC)(peer_info_t * peer, satoshi_msg_header_t * msg_hdr, void * payload);

struct peer_info
{
	int fd;
	struct sockaddr_storage ss;
	uint64_t stime; // start time
	uint64_t ltime; // last access time
	
	satoshi_msg_version_t * p_version;
	uint64_t ping;
	
	satoshi_msg_header_t msg_hdr;
	char rbuf[1024]; // recv buffer
	size_t cb_rbuf;
	unsigned char *payload; 
	size_t bytes_read; // payload data received bytes
	
	pthread_mutex_t send_mutex; 
	satoshi_msg_header_t send_hdr;
	unsigned char * send_data;
	size_t bytes_written;
	
	MSG_HANDLER_PROC * msg_handler; // callback	
};


#ifdef __cplusplus
extern "C" {
#endif

int node_run(const char * serv_name, const char * port, MSG_HANDLER_PROC _msg_handler);
int satoshi_client_connect2(const char * serv_name, const char * port, 
			const satoshi_msg_version_t * p_ver, MSG_HANDLER_PROC _msg_handler);

#ifdef __cplusplus
}
#endif
#endif
