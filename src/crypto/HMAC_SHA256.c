/**
 * @file HMAC_SHA256.c
 * @brief File containing all the function definitions of the HMAC message hashing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
 /**************************************************************************************************************** 
  * Private include files 
  ****************************************************************************************************************/

#include "HMAC_SHA256.h"

/* Global variables definition ...................................... */ // CSP or PSP? ADD TO MEMORY TRACKER

unsigned char HMAC256_ihash[SHA256_HASH_SIZE];
unsigned char HMAC256_ohash[SHA256_HASH_SIZE];
unsigned char HMAC256_k[HMAC_SHA256_BLOCK_SIZE];
unsigned char HMAC256_k_ipad[HMAC_SHA256_BLOCK_SIZE];
unsigned char HMAC256_k_opad[HMAC_SHA256_BLOCK_SIZE];
SHA256_STRUCT HMAC256_sha256_struct; 

 /**************************************************************************************************************** 
  * Function definition zone 
  ****************************************************************************************************************/
unsigned char *API_hmac_sha256(unsigned char *key, int keylen, unsigned char *data, int datalen)
{
    int i;

    // By initializing HMAC256_k to a block of 0s we ensure the padding.
    memset(HMAC256_k, 0, HMAC_SHA256_BLOCK_SIZE);
    memset(HMAC256_k_ipad, 0x36, HMAC_SHA256_BLOCK_SIZE);
    memset(HMAC256_k_opad, 0x5c, HMAC_SHA256_BLOCK_SIZE);

    if (keylen > HMAC_SHA256_BLOCK_SIZE)
    {
        // If the key is larger than the hash algorithm's block size,
        // we must digest it first by changing its value to its SHA256 hash.
        API_sha256(key, keylen, HMAC256_k);
    }
    else
    {
        memcpy(HMAC256_k, key, keylen);
    }

    for (i = 0; i < HMAC_SHA256_BLOCK_SIZE; i++)
    {
        HMAC256_k_ipad[i] ^= HMAC256_k[i];
        HMAC256_k_opad[i] ^= HMAC256_k[i];
    }

    sha256_HMAC(HMAC256_k_ipad,HMAC_SHA256_BLOCK_SIZE,data, datalen,HMAC256_ihash);
    sha256_HMAC(HMAC256_k_opad,HMAC_SHA256_BLOCK_SIZE,HMAC256_ihash, SHA256_HASH_SIZE,HMAC256_ohash);

    return HMAC256_ohash;
}

int API_verify_HMAC(unsigned char *msg, unsigned char *key, unsigned char *sign, size_t length_msg, size_t length_key, size_t length_sign)
{
	int rc = 0; // Returns value variable
	if (!msg || !key || !sign )
	{
		return rc;
	}
	if (sign == NULL || length_sign == 0)
	{ // Error when there is not signature
		return rc;
	}
	unsigned char *out ;
	out = API_hmac_sha256(key, length_key, msg, length_msg);
    for(int i = 0 ; i < length_sign ; i++)
        rc = sign[i] == out[i]? rc:rc++;
	if (rc)//if not verified
		return MAC_NOT_VERIFIED;
	else //if verified
		return MAC_VERIFIED;
}

static void sha256_HMAC(unsigned char *key,size_t key_length,unsigned char *msg, int length_msg ,unsigned char *out)
{
	CP_sha256_init(&HMAC256_sha256_struct);
	CP_sha256_update(&HMAC256_sha256_struct, key, key_length);
    CP_sha256_update(&HMAC256_sha256_struct, msg, length_msg);
	CP_sha256_final(&HMAC256_sha256_struct,out);
}


