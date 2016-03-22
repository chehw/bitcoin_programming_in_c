#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

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


//~ #ifdef _DEBUG
#define debug_printf(fmt, ...)  do { \
		char buf[512] = ""; \
		int cb = 0; \
		cb = snprintf(buf, sizeof(buf), fmt, ##__VA_ARGS__); \
		write(STDERR_FILENO, buf, cb); \
	}while(0)
#define log_printf(fmt, ...) do { \
		char buf[512] = ""; \
		int cb = 0; \
		cb = snprintf(buf, sizeof(buf), fmt, ##__VA_ARGS__); \
		write(STDOUT_FILENO, buf, cb); \
	}while(0)
//~ #else
//~ #define debug_printf(fmt, ...) 
//~ #define log_printf(fmt, ...)
//~ #endif


#ifdef __cplusplus
}
#endif

#endif
