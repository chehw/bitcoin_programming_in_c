#ifndef _MERKLE_TREE_H_
#define _MERKLE_TREE_H_

#include "satoshi_protocol.h"


typedef struct merkle_tree_level
{
	uint32_t size;
	int32_t count;
	uint256_t hashes[0];
}merkle_tree_level_t;


#define MAX_MERKLE_TREE_HEIGHT 32
typedef struct merkle_tree
{
	int height;
	merkle_tree_level_t * levels[MAX_MERKLE_TREE_HEIGHT];
}merkle_tree_t;


#ifdef __cplusplus
extern "C" {
#endif


merkle_tree_t * merkle_tree_init(merkle_tree_t * mtree);
void merkle_tree_reset(merkle_tree_t * mtree);
void merkle_tree_destroy(merkle_tree_t * mtree);
merkle_tree_t * merkle_tree_build(merkle_tree_t * mtree, uint256_t hashes[], int count);
void merkle_tree_dump(const merkle_tree_t * mtree);

static inline const uint256_t * merkle_tree_root(const merkle_tree_t * mtree)
{
	if(NULL == mtree || mtree->height <= 0 || mtree->height > MAX_MERKLE_TREE_HEIGHT) return NULL;
	return (const uint256_t *) & (mtree->levels[mtree->height - 1]->hashes[0]);
}




#ifdef __cplusplus
}
#endif

#endif
