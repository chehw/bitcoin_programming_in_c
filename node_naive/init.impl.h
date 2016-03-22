/*
 * init.impl.h
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

#ifndef _INIT_IMPL_H_
#define _INIT_IMPL_H_

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <poll.h>
#include <unistd.h>

#include "global.h"

extern global_param_t global;
extern sigset_t sig_masks;

//**************************************************
//** parse_args: 
//**     use getopt_long to parse commandline args
//** 
static int parse_args(int * p_argc, char *** p_argv)
{
	int argc = *p_argc;
	char ** argv = * p_argv;
	int c;
	int digit_optind = 0;
	static struct option long_options[] = {
		{"host", required_argument, NULL, 's'},
		{"port", required_argument, NULL, 'p'},
		{"testnet", no_argument, NULL, 't'},
		{"verbose", no_argument, NULL, 'v'},
		{"data_path", required_argument, NULL, 'd'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	
	while(1)
	{
		int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		c = getopt_long(argc, argv, ":s:pvh012t", long_options, &option_index);
		if(-1 == c) break;
		
		switch(c)
		{
		case 0:
			printf("option %s", long_options[option_index].name);
			if(optarg)
			{
				printf("with arg %s\n", optarg);
			}else printf("\n");
			break;
		case '0': case '1': case '2':
			if(digit_optind != 0 && digit_optind != this_option_optind)
			{
				fprintf(stderr, "invalid digits args\n");
				return -1;
			}
			digit_optind = this_option_optind;
			global.level = c - '0';
			printf("option %c\n", c);
			break;
		case 't':
			global.network_magic = SATOSHI_MAGIC_TESTNET3;
			break;
		case 'h':
			printf("USUAGE: %s "
						"[--host=hostname] [--port=port] [--data_path=data_path] "
						"[--verbose] [--help] [-012]\n", 
						argv[0]);
			return 1;
		case 's':
			strncpy(global.serv_name, optarg, sizeof(global.serv_name));
			break;
		case 'p':
			strncpy(global.port, optarg, sizeof(global.port));
			break;
		case 'd':
			strncpy(global.data_path, optarg, sizeof(global.data_path));
			break;
		case 'v':
			global.verbose = 1;
			break;
		
		default:
			fprintf(stderr, "?? getopt returned char code 0%o ??\n", c);
			return -1;
		}
		
	}
	
	return 0;
}


//**************************************************
//** poll_stdin: 
//** 
//** 
static void poll_stdin(const char * stop_command)
{
	// ppoll stdin with sig_masks
	int n;
	struct pollfd pfd[1];
	memset(pfd, 0, sizeof(pfd));
	pfd[0].fd = STDIN_FILENO;
	pfd[0].events = POLLIN | POLLPRI;
	
	struct timespec timeout = {0, 500000000}; // 500 ms
	
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	if(NULL == stop_command) stop_command = "";
	
	while(!quit)
	{
		int i;
		n = ppoll(pfd, 1, &timeout, &sig_masks);
		if(n < 0)
		{
			perror("poll");
			break;
		}
		if(0 == n) continue;
		for(i = 0; i < n; ++i)
		{
			if(pfd[i].fd == STDIN_FILENO)
			{
				if(pfd[i].revents & POLLIN)
				{
					char * line = NULL;
					size_t len = 0;
					ssize_t cb;
					cb = getline(&line, &len, stdin);
					if(cb > 0)
					{
						if(line[cb - 1] == '\n') line[--cb] = '\0';
						//~ if(NULL == stop_command)
						//~ {				
							//~ if( (strcasecmp(line, "quit") == 0) ||
								//~ (strcasecmp(line, "exit") == 0) )
							//~ {
								//~ quit = 1;
							//~ }
						//~ }else
						{
							
							if(strcasecmp(line, stop_command) == 0) quit = 1;
						}
					}
					free(line);
					if(quit) goto label_exit;
				}
			}
		}
	}
	
label_exit:	
	if(!quit) quit = 1;
}

#endif
