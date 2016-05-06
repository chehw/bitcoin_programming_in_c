/*
 * sig_handler.c
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
#include <string.h>
#include <errno.h>

#include "sig_handler.h"

sigset_t sig_masks;

extern volatile int quit;

static void sig_handler(int sig, siginfo_t * si, void * user_data)
{
	switch(sig)
	{
	case SIGINT: case SIGHUP:
		printf("sig = %d\n", sig);
		quit = sig;
		break;
	case SIGUSR1:
		printf("sig = %d\n", sig);
		break;
	case SIGUSR2:
		printf("sig = %d\n", sig);
		break;
	}
}


void register_sig_handler(int sigs[], int count, SIGPROC _sig_handler, void * user_data)
{
#define NUM_SIGS 4
	static int _sigs[NUM_SIGS] = {
			SIGINT,
			SIGHUP,
			SIGUSR1,
			SIGUSR2
		};
	
	int i;
	struct sigaction sa;
	
	sigemptyset(&sig_masks);
	if(NULL == sigs) 
	{
		sigs = _sigs;
		count = NUM_SIGS;
	}
	
	
	for(i = 0; i < count; ++i)
	{
		sigaddset(&sig_masks, sigs[i]);
	}	
	
	if(NULL == _sig_handler) _sig_handler = sig_handler;
	
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = _sig_handler;
	
	for(i = 0; i < count; ++i)
	{
		if(-1 == sigaction(sigs[i], &sa, user_data))
		{
			fprintf(stderr, "ERROR: sigaction(%d,...): %s\n",
				sigs[i], strerror(errno));
			exit(1);
		}
	}
#undef NUM_SIGS
}
