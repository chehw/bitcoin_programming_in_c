/*
 * satoshi-script.c
 * 
 * Copyright 2015 Che Hongwei <htc.chehw@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */


#include "satoshi-script.h"
#include "util.h"
#include "satoshi-protocol.h"
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>


const SATOSHI_OP_COMMAND_t satoshi_ops[256] = {
	// 0x01 - 0x4b : OP_PUSHDATA
	// 0x00 - 0x0f
	{"OP_1", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, 
	{"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, 
	// 0x10 - 0x1f
	{"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, 
	{"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, 
	// 0x20 - 0x2f
	{"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, 
	{"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, 
	// 0x30 - 0x3f
	{"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, 
	{"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, 
	// 0x40 - 0x4f
	{"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, 
	{"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, {"OP_PUSHDATA", 1}, 
	
	// 0x50 - 0x5f
	{"OP_RESERVED", 2}, {"OP_1", 1}, {"OP_2", 1}, {"OP_3", 1}, {"OP_4", 1}, {"OP_5", 1}, {"OP_6", 1}, {"OP_7", 1}, 
	{"OP_8", 1}, {"OP_9", 1}, {"OP_10", 1}, {"OP_11", 1}, {"OP_12", 1}, {"OP_13", 1}, {"OP_14", 1}, {"OP_15", 1}, 
	// 0x60 - 0x6f
	{"OP_16", 1},  {"OP_NOP", 1}, {"OP_VER", 2}, {"OP_IF", 1}, {"OP_NOTIF", 1}, {"OP_VERIF", 0}, {"OP_VERNOTIF", 0}, {"OP_ELSE", 1}, 
	{"OP_ENDIF", 1}, {"OP_VERIFY", 1}, {"OP_RETURN", 1}, {"OP_TOALTSTACK", 1}, {"OP_FROMALTSTACK", 1}, {"OP_2DROP", 1}, {"OP_2DUP", 1}, {"OP_3DUP", 1}, 
	// 0x70 - 0x7f
	{"OP_2OVER", 1}, {"OP_2ROT", 1}, {"OP_2SWAP", 1}, {"OP_IFDUP", 1}, {"OP_DEPTH", 1}, {"OP_DROP", 1}, {"OP_DUP", 1}, {"OP_NIP", 1}, 
	{"OP_OVER", 1}, {"OP_PICK", 1}, {"OP_ROLL", 1}, {"OP_ROT", 1}, {"OP_SWAP", 1}, {"OP_TUCK", 1}, {"OP_CAT", 0}, {"OP_SUBSTR", 0}, 
	// 0x80 - 0x8f
	{"OP_LEFT", 0}, {"OP_RIGHT", 0}, {"OP_SIZE", 1}, {"OP_INVERT", 0}, {"OP_AND", 0}, {"OP_OR", 0}, {"OP_XOR", 0}, {"OP_EQUAL", 1}, 
	{"OP_EQUALVERIFY", 1}, {"OP_RESERVED1", 2}, {"OP_RESERVED2", 2}, {"OP_1ADD", 1}, {"OP_1SUB", 1}, {"OP_2MUL", 0}, {"OP_2DIV", 0}, {"OP_NEGATE", 1}, 
	// 0x90 - 0x9f
	{"OP_ABS", 1}, {"OP_NOT", 1}, {"OP_0NOTEQUAL", 1}, {"OP_ADD", 1}, {"OP_SUB", 1}, {"OP_MUL", 0}, {"OP_DIV", 0}, {"OP_MOD", 0}, 
	{"OP_LSHIFT", 0}, {"OP_RSHIFT", 0}, {"OP_BOOLAND", 1}, {"OP_BOOLOR", 1}, {"OP_NUMEQUAL", 1}, {"OP_NUMEQUALVERIFY", 1}, {"OP_NUMNOTEQUAL", 1}, {"OP_LESSTHAN", 1}, 
	// 0xa0 - 0xa8
	{"OP_GREATERTHAN", 1}, {"OP_LESSTHANOREQUAL", 1}, {"OP_GREATERTHANOREQUAL", 1}, {"OP_MIN", 1}, {"OP_MAX", 1}, {"OP_WITHIN", 1}, {"OP_RIPEMD160", 1}, {"OP_SHA1", 1}, 
	{"OP_SHA256", 1}, {"OP_HASH160", 1}, {"OP_HASH256", 1}, {"OP_CODESEPARATOR", 1}, {"OP_CHECKSIG", 1}, {"OP_CHECKSIGVERIFY", 1}, {"OP_CHECKMULTISIG", 1}, {"OP_CHECKMULTISIGVERIFY", 1}, 
	// 0xb0 - 0xb8
	{"OP_NOP1", 1}, {"OP_NOP2", 1}, {"OP_NOP3", 1}, {"OP_NOP4", 1}, {"OP_NOP5", 1}, {"OP_NOP6", 1}, {"OP_NOP7", 1}, {"OP_NOP8", 1}, 
	{"OP_NOP9", 1}, {"OP_NOP10", 1}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, 
	// 0xc0 - 0xc8
	{"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, 
	{"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, 
	// 0xd0 - 0xd8
	{"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, 
	{"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, 
	// 0xe0 - 0xe8
	{"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, 
	{"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, 
	// 0xf0 - 0xf8
	{"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, 
	{"", 0}, {"", 0}, {"", 0}, {"", 0}, {"", 0}, {"OP_PUBKEYHASH", 0}, {"OP_PUBKEY", 0}, {"OP_INVALIDOPCODE", 0}	
	
	
};

void SATOSHI_OP_STACK_DATA_free(SATOSHI_OP_STACK_DATA_t * data)
{
	if(NULL == data) return;
	if(data->type == SATOSHI_OP_STACK_DATA_TYPE_BINARY)
	{
		if(data->data)
		{
			free(data->data);
			data->type = SATOSHI_OP_STACK_DATA_TYPE_NULL;
			data->data = NULL;
			data->cb = 0;
		}
	}
}




BOOL SATOSHI_OP_STACK_init(SATOSHI_OP_STACK_t * stack, uint32_t max_size)
{
	assert(NULL != stack);
	SATOSHI_OP_STACK_DATA_t * data = NULL;
	if(max_size == 0) max_size = SATOSHI_OP_STACK_MAX_SIZE;
	
	uint32_t cb = max_size * sizeof(SATOSHI_OP_STACK_DATA_t);
	if(cb < max_size)
	{
		// interger overflow
		fprintf(stderr, "[SATOSHI_OP_STACK_init()]: invalid size.\n");
		return FALSE;
	}
	
	data = (SATOSHI_OP_STACK_DATA_t *)malloc(cb);
	assert(NULL != data);
	memset(data, 0, cb);
	
	stack->data = data;
	stack->size = 0;
	stack->max_size = max_size;
	return TRUE;
}

void SATOSHI_OP_STACK_reset(SATOSHI_OP_STACK_t * stack)
{
	assert(NULL != stack);
	uint32_t i;
		
	for (i = 0; i < stack->size; i++)
	{
		SATOSHI_OP_STACK_DATA_free(&stack->data[i]);
	}
	
	memset(stack->data, 0, stack->max_size);
	stack->size = 0;
}

void SATOSHI_OP_STACK_free(SATOSHI_OP_STACK_t * stack)
{
	assert(NULL != stack);
	uint32_t i; 
	if(stack->data)
	{
		for (i = 0; i < stack->size; i++)
		{
			SATOSHI_OP_STACK_DATA_free(&stack->data[i]);		
		}
		free(stack->data);
		stack->data = NULL;
	}
	stack->size = 0;
	stack->max_size = 0;
}

BOOL SATOSHI_OP_STACK_push(SATOSHI_OP_STACK_t * stack, uint32_t type, void * data, uint32_t cbData)
{
	assert(NULL != stack);
	SATOSHI_OP_STACK_DATA_t * top = NULL;
//	BOOL rc = FALSE;
	if(stack->size >= stack->max_size) 
	{
		fprintf(stderr, "SATOSHI_OP_STACK_push: stack overflow.\n");
		return FALSE;
	}
	
	
	top = & (stack->data[stack->size]);
	
	if(NULL == data) type = SATOSHI_OP_STACK_DATA_TYPE_NULL;
	
	if(type == SATOSHI_OP_STACK_DATA_TYPE_BINARY)
	{
		void * p = NULL;
		if(cbData == 0) 
		{
			type = SATOSHI_OP_STACK_DATA_TYPE_NULL;
			data = NULL;
		}
		else
		{
			p = malloc(cbData);
			if(NULL == p) 
			{
				fprintf(stderr, "SATOSHI_OP_STACK_push: insufficent buffer.\n");
				return FALSE;
			}
			memcpy(p, data, cbData);
			data = p;
		}		
	}
	
	top->type = type;
	top->cb = cbData;
	top->data = data;
	
	stack->size++;
	return TRUE;
}

BOOL SATOSHI_OP_STACK_push_int(SATOSHI_OP_STACK_t * stack, uint32_t type, uint64_t value, uint32_t cbValue)
{
	assert(NULL != stack);
	SATOSHI_OP_STACK_DATA_t * top = NULL;
//	BOOL rc = FALSE;
	if(stack->size >= stack->max_size) 
	{
		fprintf(stderr, "SATOSHI_OP_STACK_push: stack overflow.\n");
		return FALSE;
	}
	
	
	top = & (stack->data[stack->size]);
	
	switch(type)
	{
		case SATOSHI_OP_STACK_DATA_TYPE_BOOL:
		case SATOSHI_OP_STACK_DATA_TYPE_INTEGER:
			top->nData = value;
			top->cb = cbValue;
			break;
		default:
			return FALSE;
	}
	top->type = type;
	
	stack->size++;
	return TRUE;
}


SATOSHI_OP_STACK_DATA_t * SATOSHI_OP_STACK_pop(SATOSHI_OP_STACK_t * stack)
{
	assert(NULL != stack);
	SATOSHI_OP_STACK_DATA_t * top = NULL;
	
	if(stack->size == 0) return NULL;
	--stack->size;	
	top = &stack->data[stack->size];
	return top;
}

SATOSHI_OP_STACK_DATA_t * SATOSHI_OP_STACK_peek(SATOSHI_OP_STACK_t * stack, uint32_t depth) // 1 == top
{
	assert(NULL != stack );
	if(depth == 0) depth = 1;
	if(depth > stack->size) return NULL;
	
	SATOSHI_OP_STACK_DATA_t * data = &stack->data[stack->size - depth];
	return data;	
}

static BOOL IsOpValid(unsigned char op)
{
	return satoshi_ops[op & 0xff].fOpValid;
}

static BOOL SATOSHI_SCRIPT_push(SATOSHI_OP_STACK_t * s, uint32_t type, unsigned char * value, uint32_t cbValue)
{
	assert(NULL != s);
	BOOL rc = FALSE;
	rc = SATOSHI_OP_STACK_push(s, type, value, cbValue);
	return rc;	
}

static BOOL SATOSHI_SCRIPT_dup(SATOSHI_OP_STACK_t * s)
{
	assert(NULL != s);

	SATOSHI_OP_STACK_DATA_t * top;
	
	top = SATOSHI_OP_STACK_peek(s, 1);
	if(NULL == top) return FALSE;
	
	return SATOSHI_OP_STACK_push(s, top->type, top->data, top->cb);
}

static BOOL SATOSHI_SCRIPT_hash160(SATOSHI_OP_STACK_t * s)
{
	assert(NULL != s);
	SATOSHI_OP_STACK_DATA_t * top = SATOSHI_OP_STACK_pop(s);
	BOOL rc = FALSE;
	hash160_t h160;
	uint32_t cb = 0;
	if(NULL == top) return FALSE;

	switch(top->type)
	{
		case SATOSHI_OP_STACK_DATA_TYPE_BINARY:
		case SATOSHI_OP_STACK_DATA_TYPE_POINTER:
			cb = hash160(top->data, top->cb, h160.vch);
			break;
		case SATOSHI_OP_STACK_DATA_TYPE_INTEGER:
		case SATOSHI_OP_STACK_DATA_TYPE_BOOL:
			cb = hash160(&top->nData, top->cb, h160.vch);
			break;
		case SATOSHI_OP_STACK_DATA_TYPE_NULL:
			break;
	}
	SATOSHI_OP_STACK_DATA_free(top);
	if(cb != 20) return FALSE;
	
	
	rc = SATOSHI_OP_STACK_push(s, SATOSHI_OP_STACK_DATA_TYPE_BINARY, &h160.vch[0], cb);	
	return rc;
	
}

static BOOL SATOSHI_SCRIPT_equal(SATOSHI_OP_STACK_t * s)
{
	assert(NULL != s);
	BOOL rc = FALSE;
	if(s->size < 2) return FALSE;
	SATOSHI_OP_STACK_DATA_t * top1 = SATOSHI_OP_STACK_pop(s);
	SATOSHI_OP_STACK_DATA_t * top2 = SATOSHI_OP_STACK_pop(s);
	
	switch(top1->type)
	{
		case SATOSHI_OP_STACK_DATA_TYPE_BINARY:
		case SATOSHI_OP_STACK_DATA_TYPE_POINTER:
			if(top2->type != SATOSHI_OP_STACK_DATA_TYPE_BINARY && top2->type != SATOSHI_OP_STACK_DATA_TYPE_POINTER)
			{
				break;
			}else if(top1->cb != top2->cb) {
				break;
			}			
			rc = (0 == memcmp(top1->data, top2->data, top1->cb));			
			break;
		case SATOSHI_OP_STACK_DATA_TYPE_INTEGER:			
		case SATOSHI_OP_STACK_DATA_TYPE_BOOL:
			if(top2->type != SATOSHI_OP_STACK_DATA_TYPE_INTEGER && top2->type != SATOSHI_OP_STACK_DATA_TYPE_BOOL)
			{
				break;
			}
			rc = (top1->nData == top2->nData);
			break;
		case SATOSHI_OP_STACK_DATA_TYPE_NULL:
			if(top2->type != top1->type) break;
			rc = TRUE;
			break;
	}
	
	
	SATOSHI_OP_STACK_DATA_free(top1);
	SATOSHI_OP_STACK_DATA_free(top2);
	
	SATOSHI_OP_STACK_push_boolean(s, rc, sizeof(rc));
	return rc;
	
}

static BOOL SATOSHI_SCRIPT_equalverify(SATOSHI_OP_STACK_t * s)
{
	assert(NULL != s);
	BOOL rc = FALSE;
	
	if(s->size < 2) return FALSE;
	
	SATOSHI_OP_STACK_DATA_t * top1 = SATOSHI_OP_STACK_pop(s);
	SATOSHI_OP_STACK_DATA_t * top2 = SATOSHI_OP_STACK_pop(s);
	
	
	switch(top1->type)
	{
		case SATOSHI_OP_STACK_DATA_TYPE_BINARY:
		case SATOSHI_OP_STACK_DATA_TYPE_POINTER:
			if(top2->type != SATOSHI_OP_STACK_DATA_TYPE_BINARY && top2->type != SATOSHI_OP_STACK_DATA_TYPE_POINTER)
			{
				break;
			}else if(top1->cb != top2->cb) {
				break;
			}			
			rc = (0 == memcmp(top1->data, top2->data, top1->cb));			
			break;
		case SATOSHI_OP_STACK_DATA_TYPE_INTEGER:			
		case SATOSHI_OP_STACK_DATA_TYPE_BOOL:
			if(top2->type != SATOSHI_OP_STACK_DATA_TYPE_INTEGER && top2->type != SATOSHI_OP_STACK_DATA_TYPE_BOOL)
			{
				break;
			}
			rc = (top1->nData == top2->nData);
			break;
		case SATOSHI_OP_STACK_DATA_TYPE_NULL:
			if(top2->type != top1->type) break;
			rc = TRUE;
			break;
	}
	
	
	SATOSHI_OP_STACK_DATA_free(top1);
	SATOSHI_OP_STACK_DATA_free(top2);
	
//	SATOSHI_OP_STACK_push(s, SATOSHI_OP_STACK_DATA_TYPE_BOOL, (void *)rc, sizeof(rc));
	return rc;
} 

static BOOL SATOSHI_SCRIPT_checksig(SATOSHI_OP_STACK_t * s, const unsigned char * message, uint32_t cbMessage)
{
	BOOL rc = FALSE;
	
	
	if(NULL == message || cbMessage == 0) return FALSE;
	
	SATOSHI_OP_STACK_DATA_t * pubkey = NULL, * sig = NULL;
	pubkey = SATOSHI_OP_STACK_pop(s);
	
	sig = SATOSHI_OP_STACK_pop(s);	
	
	if(NULL == pubkey || NULL == sig)
	{
		if(NULL != pubkey) SATOSHI_OP_STACK_DATA_free(pubkey);
		if(NULL != sig) SATOSHI_OP_STACK_DATA_free(sig);
		return FALSE;
	}
	
	// verify sig
	EC_KEY * p_key = EC_KEY_new_by_curve_name(NID_secp256k1);
	BN_CTX * ctx = BN_CTX_new();
	assert(NULL != p_key && NULL != ctx);
	const EC_GROUP * G = EC_KEY_get0_group(p_key);
	EC_POINT * Q = EC_POINT_new(G);
	EC_POINT_oct2point(G, Q, pubkey->data, pubkey->cb, ctx);
	EC_KEY_set_public_key(p_key, Q);
	
	rc = ECDSA_verify(0, message, cbMessage, sig->data, sig->cb, p_key);
	if(rc != 1)
	{
		if(-1 == rc)
		{
			// openssl error.
			ERR_print_errors_fp(stderr);		
		}
		rc = 0;
	}
	
	if(rc)
	{
		SATOSHI_OP_STACK_push_boolean(s, rc, sizeof(BOOL));		
	}
	
	EC_KEY_free(p_key);
	BN_CTX_free(ctx);
	
	SATOSHI_OP_STACK_DATA_free(pubkey);
	SATOSHI_OP_STACK_DATA_free(sig);
	return rc;
}


BOOL SATOSHI_SCRIPT_parse(SATOSHI_OP_STACK_t * s, const unsigned char * script, uint32_t cbScript, 
		const unsigned char * message, // usually the hash of the tx_raw data
		uint32_t cbMessage,
		SATOSHI_OP_STACK_t * altstack)
{
	unsigned char * p = (unsigned char *)script;
	unsigned char * p_end = p + cbScript;
	unsigned char op;
	BOOL rc = FALSE;
	
	// SATOSHI_OP_STACK s, alt;
	// SATOSHI_OP_STACK_init(&s, 0);
	// SATOSHI_OP_STACK_init(&alt, 0);
	
	while(p < p_end)
	{
		rc = FALSE;
		op = *p++;
		// print op
		printf("%s \n", satoshi_ops[op].str);
		if(!IsOpValid(op)) return FALSE;
		
		if(op <= 0x4b)
		{
			
			// push data			
			rc = SATOSHI_SCRIPT_push(s, SATOSHI_OP_STACK_DATA_TYPE_BINARY, p, op);
			if(!rc) return FALSE;			
			
			p += op;
			continue;
		}
		
		
		switch(op)
		{
			case OP_PUSHDATA1:
				if(!(rc = SATOSHI_SCRIPT_push(s, SATOSHI_OP_STACK_DATA_TYPE_INTEGER, p, 1))) return FALSE;				
				p++;
				break;
			case OP_PUSHDATA2:
				if(!(rc = SATOSHI_SCRIPT_push(s, SATOSHI_OP_STACK_DATA_TYPE_INTEGER, p, 2))) return FALSE;;
				p += 2;
				break;
			case OP_PUSHDATA4:
				if(!(rc = SATOSHI_SCRIPT_push(s, SATOSHI_OP_STACK_DATA_TYPE_INTEGER, p, 4))) return FALSE;
				p +=4;
				break;
			
			// P2PKH, P2SH
			case OP_DUP:
				if(!(rc = SATOSHI_SCRIPT_dup(s))) return FALSE;
				break;
			case OP_HASH160:
				if(!(rc = SATOSHI_SCRIPT_hash160(s))) return FALSE;				
				break;
			case OP_EQUAL:
				if(!(rc = SATOSHI_SCRIPT_equal(s))) return FALSE;;
				break;
			case OP_EQUALVERIFY:
				if(!(rc = SATOSHI_SCRIPT_equalverify(s))) return FALSE;
				break;
			case OP_CHECKSIG:
				if(!(rc = SATOSHI_SCRIPT_checksig(s, message, cbMessage))) return FALSE;
				break;
			default:
				fprintf(stderr, "not supported.\n");
				return FALSE;
					
		}
	}
	
	if(p != p_end) return FALSE;
	
	/*
	// check stack status
	SATOSHI_OP_STACK_DATA_t * top = NULL;
	uint64_t status = 0;
	while(s->size)
	{
		top = SATOSHI_OP_STACK_pop(s);
		if(NULL == top) return FALSE;
		status = 0;
		switch(top->type)
		{
		case SATOSHI_OP_STACK_DATA_TYPE_BOOL:
		case SATOSHI_OP_STACK_DATA_TYPE_INTEGER:
			status = top->nData;
			break;
		default:
			break;
		}
		SATOSHI_OP_STACK_DATA_free(top);
		if(status == 0) return FALSE;
	
	}
	* return (status != 0);
	*/
	
	return rc;	
}

