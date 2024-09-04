/**
 * @file hmac.c
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

unsigned char ihash[SHA256_HASH_SIZE];
unsigned char ohash[SHA256_HASH_SIZE];
unsigned char k[HMAC_SHA256_BLOCK_SIZE];
unsigned char k_ipad[HMAC_SHA256_BLOCK_SIZE];
unsigned char k_opad[HMAC_SHA256_BLOCK_SIZE];

unsigned char sha_buf[SHA256_HASH_SIZE];


 /**************************************************************************************************************** 
  * Function definition zone 
  ****************************************************************************************************************/
unsigned char *API_hmac_sha256(unsigned char *key, int keylen, unsigned char *data, int datalen)
{
    int i;

    // By initializing k to a block of 0s we ensure the padding.
    memset(k, 0, HMAC_SHA256_BLOCK_SIZE);
    memset(k_ipad, 0x36, HMAC_SHA256_BLOCK_SIZE);
    memset(k_opad, 0x5c, HMAC_SHA256_BLOCK_SIZE);

    if (keylen > HMAC_SHA256_BLOCK_SIZE)
    {
        // If the key is larger than the hash algorithm's block size,
        // we must digest it first by changing its value to its SHA256 hash.
        API_sha256(key, keylen, k);
    }
    else
    {
        memcpy(k, key, keylen);
    }

    for (i = 0; i < HMAC_SHA256_BLOCK_SIZE; i++)
    {
        k_ipad[i] ^= k[i];
        k_opad[i] ^= k[i];
    }

    sha256_HMAC(k_ipad,HMAC_SHA256_BLOCK_SIZE,data, datalen,ihash);
    sha256_HMAC(k_opad,HMAC_SHA256_BLOCK_SIZE,ihash, SHA256_HASH_SIZE,ohash);

    return ohash;
}

int API_verify_HMAC(unsigned char *msg, unsigned char *key, unsigned char *sign, size_t length_msg, size_t length_key, size_t length_sign)
{
	int rc = MAC_NOT_VERIFIED; // Returns value variable
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
	if (memcmp(sign, out, length_sign) != 0)// Match the HMAC signatures
		return MAC_NOT_VERIFIED;
	else
		return MAC_VERIFIED; // Returns true
}

static void sha256_HMAC(unsigned char *key,size_t key_length,unsigned char *msg, int length_msg ,unsigned char *out)
{
	SHA256_STRUCT sha256_struct; // CHECKEAR SI ES NECESARIO ZEROIZAR LO DE DENTRO DE ESTA ESTRUCTURA

	CP_sha256_init(&sha256_struct);

	CP_sha256_update(&sha256_struct, key, key_length);
    CP_sha256_update(&sha256_struct, msg, length_msg);

	CP_sha256_final(&sha256_struct,out);
}


