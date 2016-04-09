/*
 * satoshi_block.c
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
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "satoshi_protocol.h"
#include "chutil.h"

#include "satoshi_block.h"

//~ 
//~ typedef struct tx_parser
//~ {
	//~ union
	//~ {
		//~ const satoshi_tx_t * tx;
		//~ const unsigned char * raw_data;
	//~ };
	//~ size_t tx_size;
	//~ unsigned char hash[32];
	//~ int txin_count;
	//~ int txout_count;
	//~ satoshi_txin_t ** pp_txin;
	//~ satoshi_txout_t ** pp_txout;
	//~ uint32_t locktime;
//~ }tx_parser_t;

void tx_parser_dump(tx_parser_t * tp)
{
	printf("tx_size: %lu, hash: ", tp->tx_size);
	dump(tp->hash, 32);
	printf("txin_count: %d, txout_count: %d\n", tp->txin_count, tp->txout_count);
}

const unsigned char * tx_parser_attach(tx_parser_t * tp, const unsigned char * p_begin, const unsigned char * p_end)
{
	assert((NULL != tp) && (NULL != p_begin) && (p_begin < p_end));	
	tp->raw_data = p_begin;
	const unsigned char * p = p_begin + sizeof(int32_t); // version
	int i;
	tp->txin_count = (int)varint_get_value((varint_t *)p);
	if(tp->txin_count < 1)
	{
		return NULL;
	}
	p += varint_size((varint_t *)p); // varint txin_count
	
	tp->pp_txin = (satoshi_txin_t **)calloc(sizeof(satoshi_txin_t *), tp->txin_count);
	assert(NULL != tp->pp_txin);
	
	for(i = 0; i < tp->txin_count; ++i)
	{
		tp->pp_txin[i] = (satoshi_txin_t *)p;
		p += 36; // outpoint
		p += varstr_size((varstr_t *)p); // sig_script
		p += sizeof(uint32_t); // sequence		
	}
	
	tp->txout_count = (int)varint_get_value((varint_t *)p);
	if(tp->txout_count < 0)
	{
		free(tp->pp_txin);
		return NULL;
	}
	p += varint_size((varint_t *)p); // varint txout_count
	
	tp->pp_txout = (satoshi_txout_t **)calloc(sizeof(satoshi_txout_t *), tp->txout_count);
	assert(NULL != tp->pp_txout);
	
	
	for(i = 0; i < tp->txout_count; ++i)
	{
		tp->pp_txout[i] = (satoshi_txout_t *)p;
		p += sizeof(int64_t); // value
		p += varstr_size((varstr_t *)p);
	}
	
	tp->locktime = *(uint32_t *)p;
	p += sizeof(uint32_t);
	
	tp->tx_size = p - tp->raw_data;
	hash256(tp->raw_data, tp->tx_size, tp->hash);
	
	return p;	
}

void tx_parser_detach(tx_parser_t * tp)
{
	if(NULL == tp) return;
	if(NULL != tp->pp_txin) 
	{
		free(tp->pp_txin);
		//~ tp->pp_txin = NULL;
	}
	if(NULL != tp->pp_txout) 
	{
		free(tp->pp_txout);
		//~ tp->pp_txout = NULL;
	}
	memset(tp, 0, sizeof(tx_parser_t));
}


const unsigned char * block_parser_attach(block_parser_t * bp, const unsigned char * p_begin, uint32_t length)
{
	assert((NULL != bp) && (NULL != p_begin) && length /* && (length <= CONSENSUS.block_size) */);
	const unsigned char * p = p_begin;
	const unsigned char * p_end = p + length;
	int i;
	bp->raw_data = p_begin;
	bp->length = length;
	
	hash256(p_begin, sizeof(satoshi_block_header_t), bp->hash);
	
	p += sizeof(satoshi_block_header_t);
	bp->txn_count = (int)varint_get_value((varint_t *)p);
	p += varint_size((varint_t *)p);
	if(bp->txn_count < 1) 
	{
		fprintf(stderr, "invalid txn_count (%d)\n", bp->txn_count);
		return NULL;
	}
	
	bp->p_tp = (tx_parser_t *)calloc(sizeof(tx_parser_t), bp->txn_count);
	assert(NULL != bp->p_tp);
	for(i = 0; i < bp->txn_count; ++i)
	{
		p = tx_parser_attach(&bp->p_tp[i], p, p_end);
	}
	
	//~ assert(p == p_end);
	if(p != p_end)
	{
		fprintf(stderr, "block format error\n");
		return NULL;
	}
	
	return p_end;
}

void block_parser_detach(block_parser_t * bp)
{
	if(NULL == bp) return;
	int i;
	if(bp->p_tp)
	{
		for(i = 0; i < bp->txn_count; ++i)
		{
			tx_parser_detach(&bp->p_tp[i]);
		}
		free(bp->p_tp);
		bp->p_tp = NULL;
	}
}


//~ typedef struct block_parser
//~ {
	//~ union
	//~ {
		//~ const satoshi_block_t * block;
		//~ const unsigned char * raw_data;
	//~ };
	//~ uint32_t length;
	//~ unsigned char hash[32];
	//~ int txn_count;
	//~ tx_parser_t * p_tp;
//~ }block_parser_t;

void block_parser_dump(block_parser_t * bp)
{
	if(NULL == bp) return;
	printf("length = %u, hash: ", bp->length);
	dump(bp->hash, 32);
	
	int i;
	printf("txn_count: %d\n", bp->txn_count);
	for(i = 0; i < bp->txn_count; ++i)
	{
		printf("%d: ", i);
		tx_parser_dump(&bp->p_tp[i]);
	}
}
