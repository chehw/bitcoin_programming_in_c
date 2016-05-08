/*
 * test.c
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

#include <string.h>


#include "sig_handler.h"
#include "sha256.h"
#include "ripemd160.h"


#include <search.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "block_chain.h"
#include "chutil.h"

#include "satoshi_block.h"
#include "hmac_sha256.h"
#include "sha512.h"
#include "hmac_sha512.h"

int quit;

//~ block_chain_t main_chain;

#define AUTO_FREE __attribute__((cleanup(my_free)))
static inline void my_free(void * nodep)
{
	//~ log_printf("free: nodep = %p, p = %p", nodep, nodep?*(void **)nodep:NULL);
	if(NULL == nodep) return;
	free(*(void **)nodep);
}

int verify_crai()
{
	const char block_hash_hex[] = "00000000fb5b44edc7a1aa105075564a179d65506e2bd25f55f1629251d0f6b0";
	unsigned char block_hash[32];
	const char hash_hex[] = "828ef3b079f9c23829c56fe86e85b4a69d9e06e5b54ea597eef5fb3ffef509fe";
	unsigned char tx_hash[32];
	
	hex2bin(block_hash_hex, 64, block_hash);
	BSWAP_256(block_hash);
	dump_line(stdout, "to find: ", block_hash, 32);
	//~ return 0;
	
	hex2bin(hash_hex, 64, tx_hash);
	
	
	const char data_path[] = "blocks";
	char fullname[1024];
	size_t cb;
	cb = snprintf(fullname, sizeof(fullname), "%s/blk%.5d.dat", data_path, 0);
	printf("cb = %d, fullname = %s\n", (int)cb, fullname);
	
	FILE * fp;
	fp = fopen(fullname, "rb");
	if(NULL == fp) return -1;	
	
	ssize_t cb_file;
	fseek(fp, 0, SEEK_END);
	cb_file = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	AUTO_FREE unsigned char * buf = (unsigned char *)malloc(cb_file);
	
	cb = fread(buf, 1, cb_file, fp);
	if(0 == cb)
	{
		perror("fread");
		fclose(fp);
		return -1;
	}
	fclose(fp);	
	
	block_parser_t bp;	
	//~ block_file_header_t * p_filehdr;
	
	memset(&bp, 0, sizeof(bp));
	const unsigned char * p = buf;
	const unsigned char * p_end = p + cb;
	const unsigned char * p_next;
	
	int height = 0;
	while(p < p_end)
	{
		//~ p_filehdr = (block_file_header_t *)p;
		//~ if(p_filehdr->magic != SATOSHI_MAGIC_MAIN) return -1;
		//~ 
		//~ p += sizeof(block_file_header_t);		
		p_next = block_parser_parse_raw(&bp, p, p_end);
		if(NULL == p_next)
		{
			printf("end of file\n");
			break;
		}
		
		if(memcmp(block_hash, bp.hash, 32) == 0)
		{
			printf("============== height: %d ===============\n", height);
			block_parser_dump(&bp);
			block_parser_detach(&bp);
			break;
		}
		block_parser_detach(&bp);
		p = p_next;	
		if(quit) break;
		++height;
		if(height == 251) break;
	}
	
	
	char b64str[] = "MEUCIQDBKn1Uly8m0UyzETObUSL4wYdBfd4ejvtoQfVcNCIK4AIgZmMsXNQWHvo6KDd2Tu6euEl13VTC3ihl6XUlhcU+fM4=";
	unsigned char data[200];
	cb = base64_decode(b64str, strlen(b64str), data);
	printf("data: "); dump(data, cb);
	
	return 0;
}

static inline int get_blkdata_filename(char * filename, size_t bufsize, const char * path, int file_index)
{
	int cb = snprintf(filename, bufsize, "%s/blk%.5d.dat", path, file_index);
	if(cb <= 0)
	{
		perror("snprintf");		
		return cb;
	}
	filename[cb] = '\0';
	return cb;
}


#define AUTO_FCLOSE __attribute__((cleanup(my_fclose)))
static void my_fclose(void * p)
{
	if(NULL == p) return;
	FILE * fp = *(FILE **)p;
	if(fp) fclose(fp);
}


#define AUTO_DETACH_BLOCK_PARSER  __attribute__((cleanup(block_parser_auto_detach)))
static inline void block_parser_auto_detach(void * p)
{	
	//~ printf("p = %p\n", p);
	if(NULL == p) return;
	
	block_parser_t * bp = (block_parser_t *)p;
	//~ printf("bp = %p\n", bp);
	if(NULL != bp) block_parser_detach(bp);
}

static const unsigned char * parse_block(block_chain_t * bc, 
	const unsigned char * p_begin, const unsigned char * p_end,
	int32_t file_index, int64_t offset)
{
	//~ block_parser_t bp[1];	
	
	
	const unsigned char * p = p_begin;
	const unsigned char * p_next;
	while(p < p_end)
	{
		AUTO_DETACH_BLOCK_PARSER block_parser_t bp[1];
		memset(bp, 0, sizeof(bp));
		//~ printf("bp = %p\n", bp);
		
		
		p_next = block_parser_parse_raw(bp, p, p_end);
		if(NULL == p_next)
		{
			bc->err_code = bp->err_code;
			if(bc->err_code == BLOCK_PARSER_ERROR_NEED_DATA)
			{
				return p;
			}
			printf("file_index: %d, file_pos: %d, ", bp->file_index, (int)bp->file_pos);
			printf("raw data: "); dump(p, 300);
			//~ block_parser_detach(bp);			
			return NULL;
		}
		
		bp->file_index = file_index;
		bp->file_pos = offset + (p - p_begin);
		
		if(bc->on_parse_block) 
		{
			int rc = bc->on_parse_block(bc, bp);
			if(!rc)
			{
				fprintf(stderr, "user interupt\n");
				bc->err_code = BLOCK_PARSER_ERROR_SUCCESS;
				//~ block_parser_detach(bp);
				return NULL;
			}
			
		}
		//~ block_parser_detach(bp);
		p = p_next;
	}
	
	return p;
}

static bool on_parse_block(block_chain_t * bc, block_parser_t * bp)
{
	//~ static int height = 0;
	//~ log_printf("bc = %p, bp = %p\n", bc, bp);
	chain_node_t * node = NULL;
	if(bc->blocks[0] == NULL)
	{
		node = block_chain_set_genesis_block(bc, (satoshi_block_header_t *)bp->block);
	}else
	{
		node = block_chain_add(bc, (satoshi_block_header_t *)bp->block);
	}
	assert(NULL != node);
	
	//~ block_parser_dump(bp);
	
	 
	node->file_index = bp->file_index;
	node->file_pos = bp->file_pos;
	
	//~ ++height;
	//~ if(height > 10000) 
	//~ {
		//~ return false;
	//~ }
	return true;
}



int parse_blocks(block_chain_t * bc, const char * data_path, int file_index)
{
#define BUFFER_SIZE (32 * 1024 * 1024)
	char filename[1024];
	ssize_t cb;
	ssize_t file_size;
	
	
	// AUTO_### : auto cleanup	 
	AUTO_FCLOSE FILE * fp = NULL;	
	AUTO_FREE unsigned char * buffer = malloc(BUFFER_SIZE);
	assert(NULL != buffer);
	
	unsigned char * p = buffer;
	unsigned char * p_end = p + BUFFER_SIZE;
	
	cb = get_blkdata_filename(filename, sizeof(filename), data_path, file_index);
	if(cb <= 0) return -1;
	printf("filename: %s\n", filename);
	
	fp = fopen(filename, "rb");
	if(NULL == fp) return -1;
	
	fseeko64(fp, 0, SEEK_END);
	file_size = ftello(fp);
	fseeko64(fp, 0, SEEK_SET);
	
	if(file_size <= 0) return -1;
	int64_t offset = 0;
	p = buffer;
	while(1)
	{		
		cb = fread(p, 1, p_end - p, fp);
		if(cb <= 0)
		{
			perror("fread");
			break;
		}
			
		p = (unsigned char *)parse_block(bc, buffer, p_end, file_index, offset);
		if(NULL == p) 
		{
			if(bc->err_code != BLOCK_PARSER_ERROR_SUCCESS)
			{
				debug_printf("Error(%d): invalid block format @ %s-%d(%x)\n", bc->err_code, filename, (int)offset, (int)offset);
				return -1;
			}
		}
		offset += p - buffer;
		
		if(p < p_end)
		{
			if(bc->err_code != BLOCK_PARSER_ERROR_NEED_DATA)
			{
				debug_printf("invalid block format\n");
				return -1;
			}
			size_t cb_left = p_end - p;
			memmove(buffer, p, cb_left);
			p = buffer + cb_left;
		}else
		{
			p = buffer;
		}
	}
	
	
	return 0;
#undef BUFFER_SIZE
}

block_chain_t main_chain[1];

void test_hmac()
{
	hmac_sha256_ctx_t ctx;
	unsigned char hash[32];
	const char key[] = "key";
	const char msg[] = "The quick brown fox jumps over the lazy dog";
	
	hmac_sha256_init(&ctx, (unsigned char *)key, strlen(key));
	hmac_sha256_update(&ctx, (unsigned char *)msg, strlen(msg));
	hmac_sha256_final(&ctx, hash);
	
	dump(hash, 32);
	
	hmac_sha256_init(&ctx, (unsigned char *)NULL, 0);
	hmac_sha256_update(&ctx, (unsigned char *)NULL, 0);
	hmac_sha256_final(&ctx, hash);
	
	dump(hash, 32);
	
	unsigned char h512[64];
	sha512_ctx_t sha512;
	sha512_init(&sha512);
	sha512_update(&sha512, (unsigned char *)msg, strlen(msg));
	//~ sha512_update(&sha512, (unsigned char *)NULL, 0);
	sha512_final(&sha512, h512);
	dump(h512, 64);
	
	
	hmac_sha512_ctx_t ctx5;
	hmac_sha512_init(&ctx5, (unsigned char *)key, strlen(key));
	hmac_sha512_update(&ctx5, (unsigned char *)msg, strlen(msg));
	hmac_sha512_final(&ctx5, h512);
	dump(h512, 64);
}

int main(int argc, char **argv)
{
	test_hmac();
	//~ return 0;
	//~ register_sig_handler(NULL, 0, NULL, NULL);
	
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	
	memset(main_chain, 0, sizeof(main_chain));
	
	main_chain->on_parse_block = on_parse_block;
	
	int i;
	for(i = 0; i < 3; ++i)
	{
		parse_blocks(main_chain, "blocks", i);
	}
	//~ parse_blocks(main_chain, "blocks", 1);
	//~ parse_blocks(main_chain, "blocks", 2);
	
	int32_t height = main_chain->height;
	printf("height = %d, blocks_count = %d, on_chain = %d, pending_blocks: %d\n", 
			height, 
			(int)main_chain->blocks_count,
			(int)main_chain->chain_blocks_count, 
			(int)main_chain->pending_blocks_count);
	
	
	
	for(i = 0; i < 2; ++i)
	{
		chain_node_list list = main_chain->blocks[i];
		if(NULL != list)
		{
			chain_node_t * node = list;
			while(NULL != node)
			{
				printf("%.5d: file_pos: %ld(%.8x), hash: ", i, node->file_pos, (int)node->file_pos); dump(node->hash, 32);
				node = node->next;
			}
		}
	}
	
	printf("======================\n");
	{
		i = height;
		chain_node_list list = main_chain->blocks[height];
		if(NULL != list)
		{
			chain_node_t * node = list;
			while(NULL != node)
			{
				printf("%.5d: file_index: %d, file_pos: %ld(%.8x), hash: ", 
						i, 
						node->file_index, node->file_pos, 
						(int)node->file_pos); dump(node->hash, 32);
				node = node->next;
			}
		}
	}
	
	
	//~ {
		//~ i = 0;
		//~ chain_node_list list = main_chain->blocks[i];
		//~ if(NULL != list)
		//~ {
			//~ chain_node_t * node = list;
			//~ while(NULL != node)
			//~ {
				//~ printf("%.5d: file_index: %d, file_pos: %ld(%.8x), hash: ", 
						//~ i, 
						//~ node->file_index, node->file_pos, 
						//~ (int)node->file_pos); dump(node->hash, 32);
				//~ node = node->next;
			//~ }
			//~ 
			//~ FILE * fp = fopen("blocks/blk00000.dat", "rb");
			//~ assert(NULL != fp);
			//~ 
			//~ unsigned char buffer[4096];
			//~ unsigned char * p = buffer;
			// unsigned char * p_end = buffer + sizeof(buffer);
			//~ ssize_t cb = fread(buffer, 1, sizeof(buffer), fp);
			//~ assert(cb == sizeof(buffer));
			//~ block_file_header_t * p_filehdr = (block_file_header_t *)p;
			//~ p += sizeof(block_file_header_t);
			//~ 
			//~ for(i = 0; i < p_filehdr->length; ++i)
			//~ {
				//~ printf("0x%.2x, ", p[i]);
			//~ }
			//~ 
			//~ 
			//~ fclose(fp);
		//~ }
	//~ }
	//~ 
	
	
	block_chain_release(main_chain);
	
	
	return 0;
}

