#ifndef _BITCOIN_CONSENSUS_H_
#define _BITCOIN_CONSENSUS_H_

#include <stdint.h>
#include <stdbool.h>

typedef struct bip9_deployment
{
	int bit;
	int64_t start_time;
	int64_t timeout;
}bip9_deployment_t;

enum BIP9_INDEX
{
	BIP9_INDEX_DEPLOYMENT_TESTDUMMY,
    BIP9_INDEX_DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    BIP9_INDEX_MAX_VERSION_BITS_DEPLOYMENTS
};


typedef struct bitcoin_consensus
{
	unsigned int max_block_size;
	unsigned int max_block_sigops;
	int coinbase_maturify;
	
	unsigned char genesis_block_hash[32];
	int subsidy_halving_interval;
	int majority_enforce_block_upgrade;
	int majority_reject_block_outdated;
	int majority_window_size;
	
	int bip34_height;
	unsigned char bip34_enabled_block_hash[32];
	
	uint32_t rule_change_activation_threshold;
	uint32_t miner_confirmation_window;	
	bip9_deployment_t bip9s[BIP9_INDEX_MAX_VERSION_BITS_DEPLOYMENTS];
	
	unsigned char pow_limit[32];
	bool pow_allow_min_difficulty_blocks;
	bool pow_no_retargeting;
	
	int64_t pow_target_spacing;
	int64_t pow_target_timespan;
	int64_t difficulty_adjustment_interval;
}bitcoin_consensus_t;

extern bitcoin_consensus_t mainnet_consensus;
extern bitcoin_consensus_t testnet_consensus;
extern bitcoin_consensus_t regnet_consensus;

#endif
