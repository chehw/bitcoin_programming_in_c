#ifndef _SATOSHI_PROTOCOL_H_
#define _SATOSHI_PROTOCOL_H_


#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <stdint.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "util.h"

#if defined(__cplusplus)
extern "C" {
#endif



#ifdef _WIN32
	#ifndef VAR_ARRAY_LENGTH
	#define VAR_ARRAY_LENGTH (1)
	#endif
#else
	#ifndef VAR_ARRAY_LENGTH
	#define VAR_ARRAY_LENGTH (0)
	#endif
#endif

// default protocol version
#ifndef SATOSHI_PROTOCOL_VERSION
#define SATOSHI_PROTOCOL_VERSION (70002)
#endif

#ifndef SATOSHI_MESSAGE_COMMAND_COUNT
#define SATOSHI_MESSAGE_COMMAND_COUNT (24)
#endif
extern const char SATOSHI_MESSAGE_COMMANDS[SATOSHI_MESSAGE_COMMAND_COUNT][12];
#define SATOSHI_MESSAGE_COMMAND_VERSION "version"
#define SATOSHI_MESSAGE_COMMAND_VERACK "verack"

enum SATOSHI_ADDRESS_PREFIX
{
	//MAIN
	SATOSHI_ADDRESS_PREFIX_P2PKH = 0x0,
	SATOSHI_ADDRESS_PREFIX_P2SH = 0x5,
	SATOSHI_ADDRESS_PREFIX_WIF = 0x80, // comressed and uncommpressed
	SATOSHI_ADDRESS_PREFIX_BIP32 = 0x04, // PUBKEY: 0x04[0x88,0xB2,0X1E]; PRIVKEY: Ox04[0x88,0xAD,0xE4]
	// TESTNET
	SATOSHI_ADDRESS_PREFIX_P2PKH_TESTNET = 0x6F,
	SATOSHI_ADDRESS_PREFIX_P2SH_TESTNET = 0xC4,
	SATOSHI_ADDRESS_PREFIX_WIF_TESTNET = 0xEF, // comressed and uncommpressed
	SATOSHI_ADDRESS_PREFIX_BIP32_TESTNET = 0x04, // PUBKEY: 0x04[0x35,0x87,0XCF]; PRIVKEY: Ox04[0x35,0x83,0x94]
};




enum SATOSHI_SERVICE_TYPE
{
	SATOSHI_SERVICE_TYPE_NODE_NETWORK = 1
};

typedef struct uint256
{
	unsigned char vch[32];
}uint256_t, hash256_t;

typedef struct uint160
{
	unsigned char vch[20];
}uint160_t, hash160_t;

typedef struct varint
{
	unsigned char vch[1];
}varint_t;

varint_t * VARINT_new();
void VARINT_free(varint_t * p_var);
varint_t * VARINT_setdata(varint_t * p_var, uint64_t value);
uint64_t VARINT_getdata(const varint_t * p_var);
uint32_t VARINT_length(const varint_t * p_var);
uint32_t VARINT_write(const varint_t * p_var, int handle);
uint32_t VARINT_fwrite(const varint_t * p_var, FILE * fp);


typedef struct VARSTR
{
	varint_t length;
	// char data[0];
}VARSTR_t;

VARSTR_t * VARSTR_new(uint64_t length);
void VARSTR_free(VARSTR_t * p_var);
VARSTR_t * VARSTR_setdata(VARSTR_t * p_var, const char * string, uint64_t cbString);
const char * VARSTR_getdata(const VARSTR_t * p_var);
uint64_t VARSTR_get_size(const VARSTR_t * p_var);
uint64_t VARSTR_write(const VARSTR_t * p_var, int handle);
uint64_t VARSTR_fwrite(const VARSTR_t * p_var, FILE * fp);

typedef struct SATOSHI_MESSAGE_HEADER SATOSHI_MESSAGE_HEADER_t;
struct SATOSHI_MESSAGE_HEADER 
{
	union
	{
		uint32_t magic;
		unsigned char magic_b[4];
	};
	char command[12];
	uint32_t length;
	union
	{
		uint32_t checksum;
		unsigned char checksum_b[4];
	};	
}__attribute__((packed));
void SATOSHI_MESSAGE_HEADER_dump(const SATOSHI_MESSAGE_HEADER_t *p_hdr);

extern const uint32_t satoshi_magic_main;
extern const uint32_t satoshi_magic_testnet;
extern const uint32_t satoshi_magic_testnet3;
extern const uint32_t satoshi_magic_namecoin;
extern const uint32_t hash256_checksum_null;



typedef struct SATOSHI_NETADDR_LEGACY SATOSHI_NETADDR_LEGACY_t;
struct SATOSHI_NETADDR_LEGACY
{
	uint64_t service;
	char ip[16];
	uint16_t port;
}__attribute__((packed));

typedef struct SATOSHI_NETADDR
{
	#if (SATOSHI_PROTOCOL_VERSION >= 31402)
	uint32_t time;
	#endif
	SATOSHI_NETADDR_LEGACY_t addr;
}SATOSHI_NETADDR_t;

enum SATOSHI_OBJECT_TYPE
{
	SATOSHI_OBJECT_TYPE_ERROR = 0,
	SATOSHI_OBJECT_TYPE_MSG_TX = 1,
	SATOSHI_OBJECT_TYPE_MSG_BLOCK = 2,
	SATOSHI_OBJECT_TYPE_MSG_FILTERD_BLOCK = 3
};

typedef struct SATOSHI_INVENTORY
{
	union
	{
		uint32_t type;
		enum SATOSHI_OBJECT_TYPE obj_type;
	};
	hash256_t hash;
}SATOSHI_INVENTORY_t;

typedef struct SATOSHI_BLOCK_HEADER
{
	uint32_t version;
	hash256_t prev_block;
	hash256_t merkle_root;
	uint32_t timestamp;
	uint32_t bits;
	uint32_t nonce;
}SATOSHI_BLOCK_HEADER_t;

typedef struct SATOSHI_BLOCK
{
	SATOSHI_BLOCK_HEADER_t hdr;
	varint_t txn_count;
	// SATOSHI_TX_t tx[0];
}SATOSH_BLOCK_t;


#define SATOSHI_MESSAGE_VERSION_USER_AGENT_MAX_SIZE (4096)
typedef struct SATOSHI_MESSAGE_VERSION SATOSHI_MESSAGE_VERSION_t;
struct SATOSHI_MESSAGE_VERSION
{
	uint32_t version;
	uint64_t services;
	uint64_t timestamp;
	SATOSHI_NETADDR_LEGACY_t addr_recv;
	#if (SATOSHI_PROTOCOL_VERSION  >= 106)
	SATOSHI_NETADDR_LEGACY_t addr_from;
	uint64_t nonce;

	VARSTR_t user_agent;
	// int32_t start_height;
	// int8_t relay;
	#endif
}__attribute__((packed));

SATOSHI_MESSAGE_VERSION_t * SATOSHI_MESSAGE_VERSION_new(const unsigned char * user_agent, uint32_t cbUserAgent, int32_t start_height, int8_t relay);
void SATOSHI_MESSAGE_VERSION_free(SATOSHI_MESSAGE_VERSION_t * p_ver);
uint32_t SATOSHI_MESSAGE_VERSION_calc_size(const SATOSHI_MESSAGE_VERSION_t * p_ver);
BOOL SATOSHI_MESSAGE_VERSION_set_start_height(SATOSHI_MESSAGE_VERSION_t * p_ver, int32_t height);
int32_t SATOSHI_MESSAGE_VERSION_get_start_height(const SATOSHI_MESSAGE_VERSION_t * p_ver);
BOOL SATOSHI_MESSAGE_VERSION_set_relay(SATOSHI_MESSAGE_VERSION_t * p_ver, int8_t relay);
int8_t SATOSHI_MESSAGE_VERSION_get_relay(const SATOSHI_MESSAGE_VERSION_t * p_ver);
BOOL SATOSHI_MESSAGE_VERSION_get_user_agent(const SATOSHI_MESSAGE_VERSION_t * p_ver, unsigned char * user_agent, uint32_t * p_cbUserAgent);

typedef struct SATOSHI_MESSAGE_GET_HEADERS SATOSHI_MESSAGE_GET_HEADERS_t;
struct SATOSHI_MESSAGE_GET_HEADERS
{
	uint32_t version;
	varint_t count;
	// hashs
	// hash_stop
}__attribute__((packed));

typedef struct SATOSHI_OUTPOINT
{
	hash256_t hash;
	uint32_t index;
}SATOSHI_OUTPOINT_t;

typedef struct SATOSHI_TXIN
{
	SATOSHI_OUTPOINT_t prev_output;
	varint_t length;
	// unsigned char sig_script;
	// uint32_t sequence;
}SATOSHI_TXIN_t;

typedef struct SATOSHI_TXOUT
{
	int64_t value; 
	VARSTR_t pk_script;	
}SATOSHI_TXOUT_t;

typedef struct SATOSHI_TX
{
	uint32_t version;
	varint_t tx_in_count;
	// SATOSHI_TXIN_t tx_in[0]; // 41+
	// varint tx_out_count;
	// SATOSHI_TXOUT_t tx_out[0]; // 9+
	// uint32_t lock_time;
}SATOSHI_TX_t;


#if defined(__cplusplus)
}
#endif

#endif
