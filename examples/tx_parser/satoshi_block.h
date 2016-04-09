#ifndef _SATOSHI_BLOCK_H_
#define _SATOSHI_BLOCK_H_

#include <stdint.h>
#include "satoshi_protocol.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct block_file_header
{
	uint32_t magic;
	uint32_t length;
}block_file_header_t;

typedef struct satoshi_block_header
{
	int32_t version;
	unsigned char prev_hash[32];
	unsigned char merkle_root[32];
	uint32_t timestamp;
	uint32_t bits;
	uint32_t nonce;	
}satoshi_block_header_t;

typedef struct satoshi_block
{
	satoshi_block_header_t hdr;
	unsigned char txn_count[1];
}satoshi_block_t;

typedef struct satoshi_tx
{
	int32_t version;
	unsigned char txin_count[1];
	// satoshi_txin_t txin[];
	// satoshi_txout_t txout[];
	// uint32_t locktime
}satoshi_tx_t;


typedef struct satoshi_outpoint
{
	unsigned char hash[32];
	uint32_t index;
}satoshi_outpoint_t;




typedef struct satoshi_txin
{
	satoshi_outpoint_t outpoint;
	varstr_t sig_script;
	// uint32_t sequence;
}satoshi_txin_t;
#define SATOSHI_TXIN_SEQ(txin) *(uint32_t *)(((unsigned char *)txin->sig_script) + varstr_size(txin->sig_script))

typedef struct satoshi_txout
{
	int64_t value;
	varstr_t pk_script;
}satoshi_txout_t;


typedef struct tx_parser
{
	union
	{
		const satoshi_tx_t * tx;
		const unsigned char * raw_data;
	};
	size_t tx_size;
	unsigned char hash[32];
	int txin_count;
	int txout_count;
	satoshi_txin_t ** pp_txin;
	satoshi_txout_t ** pp_txout;
	uint32_t locktime;
}tx_parser_t;

const unsigned char * tx_parser_attach(tx_parser_t * tp, const unsigned char * p_begin, const unsigned char * p_end);
void tx_parser_detach(tx_parser_t * tp);

typedef struct block_parser
{
	union
	{
		const satoshi_block_t * block;
		const unsigned char * raw_data;
	};
	uint32_t length;
	unsigned char hash[32];
	int txn_count;
	tx_parser_t * p_tp;
}block_parser_t;

const unsigned char * block_parser_attach(block_parser_t * bp, const unsigned char * p_begin, uint32_t length);
void block_parser_detach(block_parser_t * bp);
void block_parser_dump(block_parser_t * bp);


#ifdef __cplusplus
}
#endif
#endif
