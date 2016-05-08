/*
 * block_chain.c
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



#include <search.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>

#include "block_chain.h"
#include "chutil.h"


static int chain_nodes_compare(const void * l, const void * r);

chain_node_t * chain_node_new(const satoshi_block_header_t * hdr)
{
	if(NULL == hdr) return NULL;
	chain_node_t * node = malloc(sizeof(chain_node_t));
	assert(NULL != node);
	//~ log_printf("node = %p\n", node);
	//~ memset(node, 0, sizeof(chain_node_t));
	
	hash256(hdr, sizeof(satoshi_block_header_t), node->hash);
	memcpy(&node->hdr, hdr, sizeof(satoshi_block_header_t));
	node->height = -1;
	node->file_index = -1;
	node->file_pos = -1;
	node->next = NULL;
	return node;
}

static void chain_node_free(chain_node_t * node)
{
	//~ printf("free node %p\n", node);
	free(node);
}

static int chain_node_list_append(chain_node_t ** list, chain_node_t * node)
{
	chain_node_t * tail = *list;
	if(NULL == tail)
	{
		*list = node;
		return 0;
	}else
	{
		while(tail->next) tail = tail->next;
		tail->next = node;
		return 0;
	}
}




static void node_cleanup(void * p)
{
	//~ printf("on_chain: p = %p\n", p);
}

static void pending_cleanup(void * p)
{
	//~ printf("on_pending p = %p\n", p);
	chain_node_free(p);
}


void block_chain_release(block_chain_t * bc)
{
	int i;
	chain_node_t * node;
	for(i = 0; i <= bc->height; ++i)
	{
		node = bc->blocks[i];
		if(node) 
		{
			chain_node_free(node);
			bc->blocks[i] = NULL;
		}
	}
	tdestroy(bc->root, node_cleanup);
	tdestroy(bc->chain_root, node_cleanup);
	tdestroy(bc->pending_root, pending_cleanup);
}



chain_node_t * block_chain_set_genesis_block(block_chain_t * bc, const satoshi_block_header_t * hdr)
{
	chain_node_t * node = chain_node_new(hdr);
	assert(NULL != node);
	node->height = 0;
	bc->blocks[0] = node;
	
	
	tsearch(node, &bc->chain_root, chain_nodes_compare);
	return node;
}


static int chain_nodes_compare(const void * l, const void * r)
{
	return memcmp(((chain_node_t *)l)->hash, ((chain_node_t *)r)->hash, 32);
}
static int pending_nodes_compare(const void * l, const void * r)
{
	return memcmp(((chain_node_t *)l)->hdr.prev_hash, ((chain_node_t *)r)->hdr.prev_hash, 32);
}

static int pending_queue_check(block_chain_t * bc, const chain_node_t * node)
{
	int32_t height = node->height;
	chain_node_t to_find;
	chain_node_t ** p_found;
	chain_node_t * list;
	chain_node_t * head;
	++height;
	
	while(node)
	{
		memset(&to_find, 0, sizeof(to_find));
		memcpy(to_find.hdr.prev_hash, node->hash, 32);		
		p_found = (chain_node_t **)tfind(&to_find, &bc->pending_root, pending_nodes_compare);
		
		int nodes_count = 0;
		if(p_found)
		{			
			list = * p_found;
			head = list;
			while(head)
			{
				head->height = height;
				if(tsearch(head, &bc->chain_root, chain_nodes_compare))
				{
					++bc->chain_blocks_count;
				}
				++nodes_count;				
				head = head->next;
			}
			chain_node_list_append(&bc->blocks[height], list);
			
			if(height > bc->height) bc->height = height;
			
			tdelete(list, &bc->pending_root, pending_nodes_compare);			
			if(bc->pending_blocks_count >= nodes_count)
			{
				bc->pending_blocks_count -= nodes_count;
			}else bc->pending_blocks_count = 0;
			
			pending_queue_check(bc, list);
		}		
		node = node->next;
	}
	return 0;
}

chain_node_t * block_chain_add(block_chain_t * bc, const satoshi_block_header_t * hdr)
{
	chain_node_t * node = chain_node_new(hdr);
	chain_node_t ** p_prev_node;
	chain_node_t ** p_node;
	chain_node_t ** p_pending;
	assert(NULL != node);
	
	chain_node_t ** p_find;
	chain_node_t to_find;
	
	//~ printf("block0_hash: "); dump(bc->blocks[0]->hash, 32);
	//~ printf("to_find_hash: "); dump(to_find.hash, 32);
	
	int32_t height;
	// check whether or not the node has already been added to the root
	p_find = tsearch(node, &bc->root, chain_nodes_compare);
	if(NULL == p_find) 
	{
		debug_printf("tsearch failed: %s\n", strerror(errno));
		bc->err_code = BLOCK_PARSER_ERROR_INVALID_PARAMETERS;
		chain_node_free(node);
		return NULL;
	}
	
	
	if((*p_find) != node)
	{
		chain_node_free(node);
		node = * p_find;		
	}else
	{
		++bc->blocks_count;
	}
	
	// check whether or not the node has already been added to the chain_root	
	p_find = tfind(node, &bc->chain_root, chain_nodes_compare);
	if(p_find)
	{
		//~ printf("already added: "); dump((*p_find)->hash, 32);
		bc->err_code = BLOCK_PARSER_ERROR_SUCCESS;
		chain_node_free(node);		
		return NULL;
	}
	
	memset(&to_find, 0, sizeof(to_find));
	memcpy(to_find.hash, hdr->prev_hash, 32);
	
	// check whether or not the node can be added into the main_chain
	p_prev_node = (chain_node_t **)tfind(&to_find, &bc->chain_root, chain_nodes_compare);
	if(p_prev_node)
	{
		height = (*p_prev_node)->height + 1;
		node->height = height;
		p_node = tsearch(node, &bc->chain_root, chain_nodes_compare);
		assert(NULL != p_node);
		
		++bc->chain_blocks_count;
		chain_node_list_append(&bc->blocks[height], node);		
		if(height > bc->height) bc->height = height;
		
		pending_queue_check(bc, node);
		
		
	}else // add to the pending queue
	{		
		p_pending = (chain_node_t **)tfind(node, &bc->pending_root, pending_nodes_compare);
		if(p_pending)
		{
			// check whether or not the node has already in the pending queue
			chain_node_list head = * p_pending;
			while(head)
			{
				if(memcmp(head->hash, node->hash, 32) == 0)
				{					
					return node;
				}
				head = head->next;
			}
			chain_node_list_append(p_pending, node);
		}else
		{
			p_pending = tsearch(node, &bc->pending_root, pending_nodes_compare);
		}
		++bc->pending_blocks_count;
	}
	
	return node;
}

