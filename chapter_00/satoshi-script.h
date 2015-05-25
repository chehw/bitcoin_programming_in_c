#ifndef _SATOSHI_SCRIPT_H_
#define _SATOSHI_SCRIPT_H_

#include <stdbool.h>

#include "util.h"


enum SATOSHI_OP
{
	// Push data
	OP_0 = 0, OP_FALSE = 0, // PUSH (null) to the stack
	// OP_DATALEN: 0x01 ~ 0x4b : PUSH the next [OP_DATALEN] bytes to the stack
	OP_PUSHDATA1 = 0x4c, // PUSH the next 1 bytes to the stack
	OP_PUSHDATA2 = 0x4d, // PUSH the next 2 bytes to the stack
	OP_PUSHDATA4 = 0x4e, // PUSH the next 4 bytes to the stack
	OP_1NEGATE = 0x4f,	// PUSH the number "-1" to the stack
	OP_1, OP_TRUE = 0x51, // PUSH the number "1" to the stack
	OP_2 = 0x52, OP_3 = 0x53, OP_4 = 0x54, OP_5 = 0x55, OP_6 = 0x56, OP_7 = 0x57, OP_8 = 0x58,
	OP_9 = 0x59, OP_10 = 0x5a, OP_11 = 0x5b, OP_12 = 0x5c, OP_13 = 0x5d, OP_14 = 0x5e, OP_15 = 0x5f,
	OP_16 = 0x60, // PUSH the number [2-16] to the stack
	
	// Flow control
	OP_NOP = 0x61, 	// Does nothing
	OP_IF = 0x63,	// [value] OP_IF [statment]: value = stack.pop(); if(value) then exec statement;
	OP_NOTIF = 0x64, // [value] OP_NOTIF [statment]: value = stack.pop(); if(!value) then exec statement;
	OP_ELSE = 0x67, // if the statement of the preceding OP_IF or OP_NOTIF not executed, then exec statement
	OP_ENDIF = 0x68, // OP_IF without OP_ENDIF would be invalid; OP_ENDIF without OP_IF is also invalid
	OP_VERIFY = 0x69, // value = stack.pop(); if(value == false) stack.push(false) and Mark the transaction as invalid
	OP_RETURN = 0x6a, // Mark the transaction as invalid
	
	// Stack
	OP_TOALTSTACK = 0x6b, //	107	0x6b	x1	(alt)x1	Puts the input onto the top of the alt stack. Removes it from the main stack.
	OP_FROMALTSTACK = 0x6b, //	108	0x6c	(alt)x1	x1	Puts the input onto the top of the main stack. Removes it from the alt stack.
	
	OP_IFDUP = 0x73, //	115	0x73	x	x / x x	If the top stack value is not 0, duplicate it.
	OP_DEPTH = 0x74, //	116	0x74	Nothing	<Stack size>	Puts the number of stack items onto the stack.
	OP_DROP = 0x75, //	117	0x75	x	Nothing	Removes the top stack item.
	OP_DUP = 0x76, //	118	0x76	x	x x	Duplicates the top stack item.
	OP_NIP = 0x77, //	119	0x77	x1 x2	x2	Removes the second-to-top stack item.
	OP_OVER = 0x78, //	120	0x78	x1 x2	x1 x2 x1	Copies the second-to-top stack item to the top.
	OP_PICK = 0x79, //	121	0x79	xn ... x2 x1 x0 <n>	xn ... x2 x1 x0 xn	The item n back in the stack is copied to the top.
	OP_ROLL = 0x7a, //	122	0x7a	xn ... x2 x1 x0 <n>	... x2 x1 x0 xn	The item n back in the stack is moved to the top.
	OP_ROT = 0x7b, //	123	0x7b	x1 x2 x3	x2 x3 x1	The top three items on the stack are rotated to the left.
	OP_SWAP = 0x7c, //	124	0x7c	x1 x2	x2 x1	The top two items on the stack are swapped.
	OP_TUCK = 0x7d, //	125	0x7d	x1 x2	x2 x1 x2	The item at the top of the stack is copied and inserted before the second-to-top item.
	
	OP_2DROP = 0x6d, //	109	0x6d	x1 x2	Nothing	Removes the top two stack items.
	OP_2DUP = 0x6e, //	110	0x6e	x1 x2	x1 x2 x1 x2	Duplicates the top two stack items.
	OP_3DUP = 0x6f, //	111	0x6f	x1 x2 x3	x1 x2 x3 x1 x2 x3	Duplicates the top three stack items.
	OP_2OVER = 0x70, //	112	0x70	x1 x2 x3 x4	x1 x2 x3 x4 x1 x2	Copies the pair of items two spaces back in the stack to the front.
	OP_2ROT = 0x71, //	113	0x71	x1 x2 x3 x4 x5 x6	x3 x4 x5 x6 x1 x2	The fifth and sixth items back are moved to the top of the stack.
	OP_2SWAP = 0x72, //	114	0x72	x1 x2 x3 x4	x3 x4 x1 x2	Swaps the top two pairs of items.
	
	// Splice
	// If any opcode marked as ***disabled*** is present in a script, it must abort and fail.
	OP_CAT = 0x7e,	//	126	0x7e	x1 x2	out	Concatenates two strings. ***disabled***.
	OP_SUBSTR = 0x7f,	//	127	0x7f	in begin size	out	Returns a section of a string. ***disabled***.
	OP_LEFT = 0x80,	//	128	0x80	in size	out	Keeps only characters left of the specified point in a string. ***disabled***.
	OP_RIGHT = 0x81,	//	129	0x81	in size	out	Keeps only characters right of the specified point in a string. ***disabled***.
	OP_SIZE = 0x82,	//	130	0x82	in	in size	Pushes the string length of the top element of the stack (without popping it).
	
	// Bitwise logic
	// If any opcode marked as disabled is present in a script, it must abort and fail.
	// Word	Opcode	Hex	Input	Output	Description
	OP_INVERT = 0x83,	//	131	0x83	in	out	Flips all of the bits in the input. disabled.
	OP_AND = 0x84,	//	132	0x84	x1 x2	out	Boolean and between each bit in the inputs. disabled.
	OP_OR = 0x85,	//	133	0x85	x1 x2	out	Boolean or between each bit in the inputs. disabled.
	OP_XOR = 0x86,	//	134	0x86	x1 x2	out	Boolean exclusive or between each bit in the inputs. disabled.
	OP_EQUAL = 0x87,	//	135	0x87	x1 x2	True / false	Returns 1 if the inputs are exactly equal, 0 otherwise.
	OP_EQUALVERIFY = 0x88,	//	136	0x88	x1 x2	True / false	Same as OP_EQUAL, but runs OP_VERIFY afterward.

	// Arithmetic
	// Note: Arithmetic inputs are limited to signed 32-bit integers, but may overflow their output.
	//	If any input value for any of these commands is longer than 4 bytes, the script must abort and fail. If any opcode marked as disabled is present in a script - it must also abort and fail.
	//	Word	Opcode	Hex	Input	Output	Description
	OP_1ADD	= 0x8b,	// 139	0x8b	in	out	1 is added to the input.
	OP_1SUB	= 0x8c,	// 	140	0x8c	in	out	1 is subtracted from the input.
	OP_2MUL	= 0x8d,	// 	141	0x8d	in	out	The input is multiplied by 2. disabled.
	OP_2DIV	= 0x8e,	// 	142	0x8e	in	out	The input is divided by 2. disabled.
	OP_NEGATE = 0x8f,	// 	143	0x8f	in	out	The sign of the input is flipped.
	OP_ABS	= 0x90,	// 	144	0x90	in	out	The input is made positive.
	OP_NOT	= 0x91,	// 	145	0x91	in	out	If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
	OP_0NOTEQUAL = 0x92,	// 	146	0x92	in	out	Returns 0 if the input is 0. 1 otherwise.
	OP_ADD	= 0x93,	// 	147	0x93	a b	out	a is added to b.
	OP_SUB	= 0x94,	// 	148	0x94	a b	out	b is subtracted from a.
	OP_MUL	= 0x95,	// 	149	0x95	a b	out	a is multiplied by b. disabled.
	OP_DIV	= 0x96,	// 	150	0x96	a b	out	a is divided by b. disabled.
	OP_MOD	= 0x97,	// 	151	0x97	a b	out	Returns the remainder after dividing a by b. disabled.
	OP_LSHIFT	= 0x98,	// 	152	0x98	a b	out	Shifts a left b bits, preserving sign. disabled.
	OP_RSHIFT	= 0x99,	// 	153	0x99	a b	out	Shifts a right b bits, preserving sign. disabled.
	OP_BOOLAND	= 0x9a,	// 	154	0x9a	a b	out	If both a and b are not 0, the output is 1. Otherwise 0.
	OP_BOOLOR	= 0x9b,	// 	155	0x9b	a b	out	If a or b is not 0, the output is 1. Otherwise 0.
	OP_NUMEQUAL	= 0x9c,	// 	156	0x9c	a b	out	Returns 1 if the numbers are equal, 0 otherwise.
	OP_NUMEQUALVERIFY = 0x9d,	// 	157	0x9d	a b	out	Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
	OP_NUMNOTEQUAL	= 0x9e,	// 	158	0x9e	a b	out	Returns 1 if the numbers are not equal, 0 otherwise.
	OP_LESSTHAN	= 0x9f,	// 	159	0x9f	a b	out	Returns 1 if a is less than b, 0 otherwise.
	OP_GREATERTHAN = 0xa0,	// 	160	0xa0	a b	out	Returns 1 if a is greater than b, 0 otherwise.
	OP_LESSTHANOREQUAL = 0xa1,	// 	161	0xa1	a b	out	Returns 1 if a is less than or equal to b, 0 otherwise.
	OP_GREATERTHANOREQUAL = 0xa2,	// 	162	0xa2	a b	out	Returns 1 if a is greater than or equal to b, 0 otherwise.
	OP_MIN	= 0xa3,	// 	163	0xa3	a b	out	Returns the smaller of a and b.
	OP_MAX	= 0xa4,	// 	164	0xa4	a b	out	Returns the larger of a and b.
	OP_WITHIN = 0xa5,	// 	165	0xa5	x min max	out	Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.
	
	// Crypto
	// Word	Opcode	Hex	Input	Output	Description
	OP_RIPEMD160 = 0xa6, //	166	0xa6	in	hash	The input is hashed using RIPEMD-160.
	OP_SHA1 = 0xa7, //	167	0xa7	in	hash	The input is hashed using SHA-1.
	OP_SHA256 = 0xa8, //	168	0xa8	in	hash	The input is hashed using SHA-256.
	OP_HASH160 = 0xa9, //	169	0xa9	in	hash	The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
	OP_HASH256 = 0xaa, //	170	0xaa	in	hash	The input is hashed two times with SHA-256.
	OP_CODESEPARATOR = 0xab, //	171	0xab	Nothing	Nothing	All of the signature checking words will only match signatures to the data after the most recently-executed OP_CODESEPARATOR.
	OP_CHECKSIG = 0xac, //	172	0xac	sig pubkey	True / false	The entire transaction's outputs, inputs, and script (from the most recently-executed OP_CODESEPARATOR to the end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this hash and public key. If it is, 1 is returned, 0 otherwise.
	OP_CHECKSIGVERIFY = 0xad, //	173	0xad	sig pubkey	True / false	Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
	OP_CHECKMULTISIG = 0xae, //	174	0xae	x sig1 sig2 ... <number of signatures> pub1 pub2 <number of public keys>	True / False	Compares the first signature against each public key until it finds an ECDSA match. Starting with the subsequent public key, it compares the second signature against each remaining public key until it finds an ECDSA match. The process is repeated until all signatures have been checked or not enough public keys remain to produce a successful result. All signatures need to match a public key. Because public keys are not checked again if they fail any signature comparison, signatures must be placed in the scriptSig using the same order as their corresponding public keys were placed in the scriptPubKey or redeemScript. If all signatures are valid, 1 is returned, 0 otherwise. Due to a bug, one extra unused value is removed from the stack.
	OP_CHECKMULTISIGVERIFY = 0xaf, //	175	0xaf	x sig1 sig2 ... <number of signatures> pub1 pub2 ... <number of public keys>	True / False	Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.
	
	// Pseudo-words
	// These words are used internally for assisting with transaction matching. They are invalid if used in actual scripts.
	// Word	Opcode	Hex	Description
	OP_PUBKEYHASH = 0xfd, //	253	0xfd	Represents a public key hashed with OP_HASH160.
	OP_PUBKEY = 0xfe, //	254	0xfe	Represents a public key compatible with OP_CHECKSIG.
	OP_INVALIDOPCODE = 0xff, //	255	0xff	Matches any opcode that is not yet assigned.
	
	// Reserved words
	// Any opcode not assigned is also reserved. Using an unassigned opcode makes the transaction invalid.
	// Word	Opcode	Hex	When used...
	OP_RESERVED = 0x50, //	80	0x50	Transaction is invalid unless occuring in an unexecuted OP_IF branch
	OP_VER = 0x62, //	98	0x62	Transaction is invalid unless occuring in an unexecuted OP_IF branch
	OP_VERIF = 0x65, //	101	0x65	Transaction is invalid even when occuring in an unexecuted OP_IF branch
	OP_VERNOTIF = 0x66, //	102	0x66	Transaction is invalid even when occuring in an unexecuted OP_IF branch
	OP_RESERVED1 = 0x89, //	137	0x89	Transaction is invalid unless occuring in an unexecuted OP_IF branch
	OP_RESERVED2 = 0x8a, //	138	0x8a	Transaction is invalid unless occuring in an unexecuted OP_IF branch
	//OP_NOP1-OP_NOP10 , //	176-185	0xb0-0xb9	The word is ignored. Does not mark transaction as invalid.
	OP_NOP1 = 0xb0, OP_NOP2 = 0xb1, OP_NOP3 = 0xb2, OP_NOP4 = 0xb3, OP_NOP5 = 0xb4, 
	OP_NOP6 = 0xb5, OP_NOP7 = 0xb6, OP_NOP8 = 0xb7, OP_NOP9= 0xb8, OP_NOP10 = 0xb9,
};

typedef struct SATOSHI_OP_COMMAND
{
	//char str[28];
	const char * str;
	bool fOpValid;
}SATOSHI_OP_COMMAND_t;

extern const SATOSHI_OP_COMMAND_t satoshi_ops[256];


enum SATOSHI_OP_STACK_DATA_TYPE
{
	SATOSHI_OP_STACK_DATA_TYPE_NULL = 0,
	SATOSHI_OP_STACK_DATA_TYPE_INTEGER = 1,
	SATOSHI_OP_STACK_DATA_TYPE_BINARY = 2, // use internal allocator to alloc buffer (<default: malloc()>), the caller should call SATOSHI_OP_STACK_DATA_free() to free the buffer
	SATOSHI_OP_STACK_DATA_TYPE_POINTER = 3, // store only pointers. the caller should free this pointer later by himself.
	SATOSHI_OP_STACK_DATA_TYPE_BOOL = 4
};

typedef struct SATOSHI_OP_STACK_DATA
{
	uint32_t type;
	uint32_t cb;
	union
	{
		uint64_t nData;
		unsigned char * data;
	};
//	struct SATOSHI_OP_STACK_DATA * next;	
}SATOSHI_OP_STACK_DATA_t;
void SATOSHI_OP_STACK_DATA_free(SATOSHI_OP_STACK_DATA_t * data);

#define SATOSHI_OP_STACK_MAX_SIZE (512)
typedef struct SATOSHI_OP_STACK
{
	SATOSHI_OP_STACK_DATA_t * data;
	uint32_t size;
	uint32_t max_size;
}SATOSHI_OP_STACK_t;

BOOL SATOSHI_OP_STACK_init(SATOSHI_OP_STACK_t * stack, uint32_t max_size);
void SATOSHI_OP_STACK_free(SATOSHI_OP_STACK_t * stack);
void SATOSHI_OP_STACK_reset(SATOSHI_OP_STACK_t * stack);
BOOL SATOSHI_OP_STACK_push(SATOSHI_OP_STACK_t * stack, uint32_t type, void * data, uint32_t cbData);
BOOL SATOSHI_OP_STACK_push_int(SATOSHI_OP_STACK_t * stack, uint32_t type, uint64_t value, uint32_t cbValue);
#define SATOSHI_OP_STACK_push_boolean(s, value, cbValue) SATOSHI_OP_STACK_push_int(s, SATOSHI_OP_STACK_DATA_TYPE_BOOL, value, cbValue)
SATOSHI_OP_STACK_DATA_t * SATOSHI_OP_STACK_pop(SATOSHI_OP_STACK_t * stack);
SATOSHI_OP_STACK_DATA_t * SATOSHI_OP_STACK_peek(SATOSHI_OP_STACK_t * stack, uint32_t depth); // 1 == top


BOOL SATOSHI_SCRIPT_parse(SATOSHI_OP_STACK_t * s, const unsigned char * script, uint32_t cbScript, 
		const unsigned char * message, // usually the hash of the tx_raw data
		uint32_t cbMessage,
		SATOSHI_OP_STACK_t * altstack);


#endif
