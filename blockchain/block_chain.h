#ifndef _BLOCK_CHAIN_H_
#define _BLOCK_CHAIN_H_


#include "merkle_tree.h"
#include "satoshi_protocol.h"
#include "satoshi_block.h"
#include "chutil.h"

#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif


struct chain_node
{
	unsigned char hash[32];
	int32_t height;
	satoshi_block_header_t hdr;
	
	int32_t file_index;
	int64_t file_pos;
	const unsigned char * data;
	struct chain_node * next;
};
typedef struct chain_node chain_node_t, * chain_node_list;

#define MAX_BLOCKS (5000000)
struct block_chain
{
	uint32_t magic;	// network magic
	chain_node_list blocks[MAX_BLOCKS];
	int32_t height;	
	
	void * root; // all blocks
	size_t blocks_count;
	
	void * chain_root;	// main_chain: T-tree, including orphan blocks
	size_t chain_blocks_count; 
	
	void * pending_root;	// blocks cannot add into the main_chain temporarily (due to no parent node in the main chain)
	size_t pending_blocks_count;
	
	int err_code;
	bool (* on_parse_block)(struct block_chain * bc, block_parser_t * bp);
};
typedef struct block_chain block_chain_t;


chain_node_t * block_chain_add(block_chain_t * bc, const satoshi_block_header_t * hdr);
//~ int block_chain_discard_orphans(block_chain_t * bc); 

void block_chain_release(block_chain_t * bc);
chain_node_t * block_chain_set_genesis_block(block_chain_t * bc, const satoshi_block_header_t * hdr);


#ifdef __cplusplus
}
#endif
#endif

