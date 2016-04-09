/*
 * tx_parser.c
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
#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include "chutil.h"
#include "sha256.h"
#include "satoshi_protocol.h"
#include "satoshi_block.h"

//~ #include "blockchain.h"


int main(int argc, char **argv)
{
	int file_index = 0;
	char full_name[512];
	const char * path = "./data";
	int cb;
	
	if(argc > 1)
	{
		cb = snprintf(full_name, sizeof(full_name), "%s", argv[1]);		
	}else
	{
		cb = snprintf(full_name, sizeof(full_name), "%s/blk%.5d.dat", path, file_index);
	}
	
	if(cb < 0 || cb >= 512)
	{
		perror("snprintf");
		exit(1);
	}
	full_name[cb] = '\0';
	
	//~ db_test();
	//~ chain_test(NULL, NULL);
	//~ return 0;
	
	
	
	FILE * fp = fopen(full_name, "r");
	if(NULL == fp)
	{
		fprintf(stderr, "fopen [%s] failed: (%d) %s\n", full_name, errno, strerror(errno));
		printf("Usage: $ %s [/path/blkxxxxx.dat]\n", argv[0]); 
		exit(1);
	}
	//~ assert(NULL != fp);
	
	fseek(fp, 0, SEEK_END);
	ssize_t file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	
	unsigned char * buffer = (unsigned char *)malloc(file_size);
	assert(NULL != buffer);
	
	size_t cb_read = fread(buffer, 1, file_size, fp);
	if(0 == cb_read)
	{
		perror("fread");
		fclose(fp);
		exit(1);
	}
	fclose(fp);
	
	const unsigned char * p = buffer;
	const unsigned char * p_end = p + file_size;
	
	block_parser_t bp;
	block_file_header_t * p_hdr;
	int blocks_count = 0;
	while(p < p_end)
	{
		p_hdr = (block_file_header_t *)p;		
		p += sizeof(block_file_header_t);
		
		memset(&bp, 0, sizeof(bp));
		p = block_parser_attach(&bp, p, p_hdr->length);
		if(NULL == p) break;
		
		printf("==============  block %d ===============\n", blocks_count);
		block_parser_dump(&bp);
		block_parser_detach(&bp);
		
		++blocks_count;
		if((blocks_count % 100) == 0) 
		{
			printf("press enter to continue ('q' to quit): ");
			int c = getchar();
			if(c == '\n') continue;
			else if((c == 'q') || (c == 'Q')) break;
			
			while(c != '\n' && c != EOF)
			{
				c = getchar();				
			}
			
			if(c == EOF) break;
		}
		
		
	}
	
	free(buffer);	
	return 0;	
}

