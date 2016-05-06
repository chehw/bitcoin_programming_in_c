#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "satoshi_protocol.h"


typedef struct global_param
{
	pthread_mutex_t mutex;
	uint32_t network_magic;
	char serv_name[NI_MAXHOST];
	char port[NI_MAXSERV];	
	char data_path[200];
	int level;
	int verbose;
	
	uint64_t services;
	struct sockaddr_storage ss;
	
	char user_agent[64];
	size_t cb_user_agent;
	
	int start_height;
	bool relay;
	
	
}global_param_t;

extern global_param_t global;
extern sigset_t sig_masks;
extern volatile int quit;



#ifdef __cplusplus
extern "C" {
#endif

static inline void global_param_dump(const global_param_t * param)
{
	printf("magic = 0x%.8x\n", param->network_magic);
	printf("serv_name = %s\n", param->serv_name);
	printf("port = %s\n", param->port);
	printf("data_ptah = %s\n", param->data_path);
	printf("level = %d\n", param->level);
	printf("verbose = %s\n", param->verbose?"true":"false");
}



#ifdef __cplusplus
}
#endif

#endif
