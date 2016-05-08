/*
 * bitcoin-consensus.c
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


#include "bitcoin-consensus.h"
#include <string.h>



bitcoin_consensus_t mainnet_consensus;
bitcoin_consensus_t testnet_consensus;
bitcoin_consensus_t regnet_consensus;

const unsigned char mainnet_genesis_hash[32] = {
		0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 
		0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 
		0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 
		0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00
	};

const unsigned char mainnet_bip34_hash[32] = {
		0xb8, 0x08, 0x08, 0x9c, 0x75, 0x6a, 0xdd, 0x15, 
		0x91, 0xb1, 0xd1, 0x7b, 0xab, 0x44, 0xbb, 0xa3, 
		0xfe, 0xd9, 0xe0, 0x2f, 0x94, 0x2a, 0xb4, 0x89, 
		0x4b, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
const unsigned char mainnet_pow_limit[32] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
	};

const unsigned char mainnet_genesis_block[] = {
		0x01, 0x00, 0x00, 0x00, // version
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // prev_hash
		0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61, 
		0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a, // merkle_root
		0x29, 0xab, 0x5f, 0x49, // timestamp
		0xff, 0xff, 0x00, 0x1d, // bits
		0x1d, 0xac, 0x2b, 0x7c, // nonce
		0x01, // txn_count
		0x01, 0x00, 0x00, 0x00, // tx_version
		0x01, // txin_count
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0xff, 0xff, 0xff, 0xff, // outpoint
		0x4d, // coinbase length
		0x04, 0xff, 0xff, 0x00, 0x1d, // Satoshi's data := bits
		0x01, 0x04, // Satoshi's data := date (01/04, 2019)
		0x45, 0x54, 0x68, 0x65, 0x20, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x20, 0x30, 0x33, 0x2f, 0x4a, 0x61, 
		0x6e, 0x2f, 0x32, 0x30, 0x30, 0x39, 0x20, 0x43, 0x68, 0x61, 0x6e, 0x63, 0x65, 0x6c, 0x6c, 0x6f, 
		0x72, 0x20, 0x6f, 0x6e, 0x20, 0x62, 0x72, 0x69, 0x6e, 0x6b, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x65, 
		0x63, 0x6f, 0x6e, 0x64, 0x20, 0x62, 0x61, 0x69, 0x6c, 0x6f, 0x75, 0x74, 0x20, 0x66, 0x6f, 0x72, 
		0x20, 0x62, 0x61, 0x6e, 0x6b, 0x73, // Satoshi's message
		0xff, 0xff, 0xff, 0xff, // sequence
		0x01, // txout_count
		0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, // value: 50 BTC == 5000000000 satoshi
		0x43, // pk_script length
		0x41, 0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30, 
		0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61, 
		0xde, 0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04, 0xe5, 0x1e, 0xc1, 
		0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, 0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1, 
		0x1d, 0x5f, 0xac, // pk_script
		0x00, 0x00, 0x00, 0x00	// lock_time
	};


//~ typedef struct bitcoin_consensus
//~ {
	//~ unsigned int max_block_size;
	//~ unsigned int max_block_sigops;
	//~ int coinbase_maturify;
	//~ 
	//~ unsigned char genesis_block_hash[32];
	//~ int subsidy_halving_interval;
	//~ int majority_enforce_block_upgrade;
	//~ int majority_reject_block_outdated;
	//~ int majority_window_size;
	//~ 
	//~ int bip34_height;
	//~ unsigned char bip34_enabled_block_hash[32];
	//~ 
	//~ uint32_t rule_change_activation_threshold;
	//~ uint32_t miner_confirmation_window;	
	//~ bip9_deployment_t bip9s[BIP9_INDEX_MAX_VERSION_BITS_DEPLOYMENTS];
	//~ 
	//~ unsigned char pow_limit[32];
	//~ bool pow_allow_min_difficulty_blocks;
	//~ bool pow_no_retargeting;
	//~ 
	//~ int64_t pow_target_spacing;
	//~ int64_t pow_target_timespan;
	//~ int64_t difficulty_adjustment_interval;
//~ }bitcoin_consensus_t;

__attribute__((constructor))
static void bitcoin_consensus_init(void)
{
	int i;
	uint32_t * p_u32; 
	// init mainnet_consensus
	mainnet_consensus.max_block_size = 1000000;
	mainnet_consensus.max_block_sigops = mainnet_consensus.max_block_size / 50;
	mainnet_consensus.coinbase_maturify = 100;
	
	memcpy(mainnet_consensus.genesis_block_hash, mainnet_genesis_hash, sizeof(mainnet_genesis_hash));
	mainnet_consensus.subsidy_halving_interval = 210000;
	mainnet_consensus.majority_enforce_block_upgrade = 750;
	mainnet_consensus.majority_reject_block_outdated = 950;
	mainnet_consensus.majority_window_size = 1000;
	
	mainnet_consensus.bip34_height = 227931;
	memcpy(mainnet_consensus.bip34_enabled_block_hash, mainnet_bip34_hash, sizeof(mainnet_bip34_hash));
	
	mainnet_consensus.rule_change_activation_threshold = 1916;
	mainnet_consensus.miner_confirmation_window = 2016;
	
	mainnet_consensus.bip9s[BIP9_INDEX_DEPLOYMENT_TESTDUMMY].bit = 28;
	mainnet_consensus.bip9s[BIP9_INDEX_DEPLOYMENT_TESTDUMMY].start_time = 1199145601; // January 1, 2008
	mainnet_consensus.bip9s[BIP9_INDEX_DEPLOYMENT_TESTDUMMY].timeout = 1230767999; // December 31, 2008
	
	// Deployment of BIP68, BIP112, and BIP113.
	mainnet_consensus.bip9s[BIP9_INDEX_DEPLOYMENT_CSV].bit = 0;
	mainnet_consensus.bip9s[BIP9_INDEX_DEPLOYMENT_CSV].start_time = 1462060800; // May 1st, 2016
	mainnet_consensus.bip9s[BIP9_INDEX_DEPLOYMENT_CSV].timeout = 1493596800; // May 1st, 2017
	
	
	
	p_u32 = (uint32_t *)&mainnet_consensus.pow_limit[0];
	p_u32[7] = 0;
	for(i = 0; i < 7; ++i)
	{
		p_u32[i] = 0xFFFFFFFF;
	}
	
	mainnet_consensus.pow_allow_min_difficulty_blocks = false;
	mainnet_consensus.pow_no_retargeting = false;
	
	mainnet_consensus.pow_target_spacing = 10 * 60;	// 600 seconds
	mainnet_consensus.pow_target_timespan = 14 * 24 * 60 * 60; // two weeks
	mainnet_consensus.difficulty_adjustment_interval = 
		mainnet_consensus.pow_target_timespan / mainnet_consensus.pow_target_spacing;
		
		
	// init testnet_consensus
	//~ static const char testnet_bip34_hash_be[65] = "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8";
	//~ unsigned char hash[32];
	testnet_consensus.max_block_size = 1000000;
	testnet_consensus.max_block_sigops = mainnet_consensus.max_block_size / 50;
	testnet_consensus.coinbase_maturify = 100;
	
	memcpy(testnet_consensus.genesis_block_hash, mainnet_genesis_hash, sizeof(mainnet_genesis_hash));
	testnet_consensus.subsidy_halving_interval = 210000;
	testnet_consensus.majority_enforce_block_upgrade = 51;
	testnet_consensus.majority_reject_block_outdated = 75;
	testnet_consensus.majority_window_size = 100;
	
	testnet_consensus.bip34_height = 21111;	
	/* testnet	
	consensus.BIP34Hash = uint256S();
	consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
	*/
	
	// Todo: 	
	// memcpy(testnet_consensus.bip34_enabled_block_hash, mainnet_bip34_hash, sizeof(mainnet_bip34_hash));
	
	testnet_consensus.rule_change_activation_threshold = 1512;
	testnet_consensus.miner_confirmation_window = 2016;
	
	testnet_consensus.bip9s[BIP9_INDEX_DEPLOYMENT_TESTDUMMY].bit = 28;
	testnet_consensus.bip9s[BIP9_INDEX_DEPLOYMENT_TESTDUMMY].start_time = 1199145601; // January 1, 2008
	testnet_consensus.bip9s[BIP9_INDEX_DEPLOYMENT_TESTDUMMY].timeout = 1230767999; // December 31, 2008
	
	// Deployment of BIP68, BIP112, and BIP113.
	testnet_consensus.bip9s[BIP9_INDEX_DEPLOYMENT_CSV].bit = 0;
	testnet_consensus.bip9s[BIP9_INDEX_DEPLOYMENT_CSV].start_time = 1456790400; // March 1st, 2016
	testnet_consensus.bip9s[BIP9_INDEX_DEPLOYMENT_CSV].timeout = 1493596800; // May 1st, 2017
	
	
	
	p_u32 = (uint32_t *)&testnet_consensus.pow_limit[0];
	p_u32[7] = 0;
	for(i = 0; i < 7; ++i)
	{
		p_u32[i] = 0xFFFFFFFF;
	}
	
	testnet_consensus.pow_allow_min_difficulty_blocks = true;
	testnet_consensus.pow_no_retargeting = false;
	
	testnet_consensus.pow_target_spacing = 10 * 60;	// 600 seconds
	testnet_consensus.pow_target_timespan = 14 * 24 * 60 * 60; // two weeks
	testnet_consensus.difficulty_adjustment_interval = 
		testnet_consensus.pow_target_timespan / testnet_consensus.pow_target_spacing;
}
