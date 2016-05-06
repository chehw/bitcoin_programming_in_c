/*
 * merkle_tree.c
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
#include <stdint.h>
#include "chutil.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "merkle_tree.h"


merkle_tree_level_t * merkle_tree_level_new(size_t count)
{
	merkle_tree_level_t * level;
	if(count == 0) return NULL;
	
	if(count & 0x01) ++count;
	size_t size = 8 + sizeof(uint256_t) * count;
	
	level = (merkle_tree_level_t *)malloc(size);
	assert(NULL != level);
	memset(level, 0, size);
	level->size = size;
	
	return level;
}

void merkle_tree_level_destroy(merkle_tree_level_t * level)
{
	free(level);
}



merkle_tree_t * merkle_tree_init(merkle_tree_t * mtree)
{
	if(NULL == mtree) mtree = (merkle_tree_t *)malloc(sizeof(merkle_tree_t));
	assert(NULL != mtree);
	memset(mtree, 0, sizeof(merkle_tree_t));
	return mtree;
} 

void merkle_tree_reset(merkle_tree_t * mtree)
{
	int i;
	if(NULL == mtree) return;
	for(i = 0; i < MAX_MERKLE_TREE_HEIGHT; ++i)
	{
		if(mtree->levels[i])
		{
			merkle_tree_level_destroy(mtree->levels[i]);
			mtree->levels[i] = NULL;
		}
	}
	mtree->height = 0;
}

void merkle_tree_destroy(merkle_tree_t * mtree)
{
	merkle_tree_reset(mtree);
	free(mtree);
}

merkle_tree_t * merkle_tree_build(merkle_tree_t * mtree, uint256_t hashes[], int count)
{
	if(NULL == mtree) mtree = merkle_tree_init(NULL);
	assert(NULL != mtree);	
	merkle_tree_level_t * level;
	int height = 0;
	
	level = merkle_tree_level_new(count);
	if(NULL == level)
	{
		fprintf(stderr, "ERROR: insufficient memory.\n");		
		merkle_tree_destroy(mtree);
		return NULL;
	}
	
	// copy leafs
	memcpy(level->hashes, hashes, count * sizeof(uint256_t));
	if(count & 0x01)
	{
		// duplicate last hash
		memcpy(&level->hashes[count], &level->hashes[count - 1], sizeof(uint256_t));
	}
	mtree->levels[height++] = level;
	
	while(count > 1)
	{
		int i;
		merkle_tree_level_t * prev;
		
		
		if(count & 0x01) ++count;
		count /= 2;
		
		prev = level;
		level = merkle_tree_level_new(count);
		if(NULL == level)
		{
			fprintf(stderr, "ERROR: insufficient memory.\n");		
			merkle_tree_destroy(mtree);
			return NULL;
		}
		
		for(i = 0; i < count; ++i)
		{
			hash256(&prev->hashes[i * 2], sizeof(uint256_t) * 2, (unsigned char *)&level->hashes[i]);
		}
		
		if(count & 0x01)
		{
			// duplicate last hash
			memcpy(&level->hashes[count], &level->hashes[count - 1], sizeof(uint256_t));
		}
		mtree->levels[height++] = level;
	}
	
	if(height > MAX_MERKLE_TREE_HEIGHT)
	{
		fprintf(stderr, "ERROR: insufficient memory.\n");		
		merkle_tree_destroy(mtree);
		mtree = NULL;
	}
	mtree->height = height;
	return mtree;
}


void merkle_tree_dump(const merkle_tree_t * mtree)
{
	int i;
	printf("height = %d\n", mtree->height);
	for(i = 0; i < mtree->height; ++i)
	{
		printf("level: %d:\t", i);
		dump(&mtree->levels[i]->hashes[0], 32);
		printf("\n");
	}
	//~ printf("level: %d:\t", i);
	//~ dump(&mtree->levels[i]->hashes[0], 32);
	//~ printf("\n");
}

