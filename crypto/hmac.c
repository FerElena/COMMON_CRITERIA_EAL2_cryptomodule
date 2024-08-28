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

#include "hmac.h"

/* Global variables definition ...................................... */ // CSP or PSP? ADD TO MEMORY TRACKER

unsigned char ihash[SHA256_HASH_SIZE];
unsigned char ohash[SHA256_HASH_SIZE];
unsigned char k[HMAC_SHA256_BLOCK_SIZE];
unsigned char k_ipad[HMAC_SHA256_BLOCK_SIZE];
unsigned char k_opad[HMAC_SHA256_BLOCK_SIZE];

unsigned char buf[HMAC_SHA256_BLOCK_SIZE + SHA256_HASH_SIZE];
unsigned char sha_buf[SHA256_HASH_SIZE];


 /**************************************************************************************************************** 
  * Function definition zone 
  ****************************************************************************************************************/
unsigned char *API_CP_hmac_sha256(unsigned char *key, int keylen, unsigned char *data, int datalen)
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

    CP_H_sha256(k_ipad, HMAC_SHA256_BLOCK_SIZE, data, datalen, ihash);
    CP_H_sha256(k_opad, HMAC_SHA256_BLOCK_SIZE, ihash, SHA256_HASH_SIZE, ohash );

    return ohash;
}

static void CP_H_sha256(unsigned char *k, int keylen, unsigned char *m, int mlen, unsigned char *out)
{
    // We concatenate 'k' and 'm' and save the concatenated message in 'buf'
    int buflen = keylen + mlen;
    memcpy(buf, k, keylen);
    memcpy(buf + keylen, m, mlen);

    // We save in 'out' the SHA256 hash of 'buf'
    API_sha256(buf, buflen,sha_buf);
    memcpy(out, sha_buf,SHA256_HASH_SIZE);
}
