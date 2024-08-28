/**
 * @file hmac.h
 * @brief File containing all the function headers of the HMAC message hashing.
 */

#ifndef _HMAC_H_
#define _HMAC_H_

/* Compiler include files ............................................ */
#include <stddef.h>
#include <stdint.h>

/* Private include files ............................................ */
#include "sha256.h"



/**
 * @brief SHA256 hash size value 
 * This variable defines the size value of the SHA256 hash (32 bits)
 */
#define SHA256_HASH_SIZE 32

/**
 * @brief HMAC-SHA256 block size value
 * This variable defines the block size of the HMAC-SHA256 alorithm (64 bytes)
 */
#define HMAC_SHA256_BLOCK_SIZE 64

/* Global variables definition ...................................... */

extern unsigned char ihash[SHA256_HASH_SIZE];
extern unsigned char ohash[SHA256_HASH_SIZE];
extern unsigned char k[HMAC_SHA256_BLOCK_SIZE];
extern unsigned char k_ipad[HMAC_SHA256_BLOCK_SIZE];
extern unsigned char k_opad[HMAC_SHA256_BLOCK_SIZE];

extern unsigned char buf[HMAC_SHA256_BLOCK_SIZE + SHA256_HASH_SIZE];
extern unsigned char sha_buf[SHA256_HASH_SIZE];

/* Function declaration zone ........................................ */

/**
 * @brief This function returns the HMAC-SHA256 hash of a given message with a given key
 * 
 * @tsfi{LGOT, SHA, HMAC}
 * @sfr{FCS_COP.1.1, FDP_ACF.1.1, FAU_GEN.1.1, FAU_GEN.1.2, FAU_STG.1.1, FTA_TSE.1.1, FDP_ITC.2.1, FDP_ITC.2.2, FDP_ITC.2.3, FDP_ITC.2.4, FDP_ITC.2.5, FTA_SSL.4.1}
 * @methodOfUse{This function is invoked by the mac.c}
 * 
 * @param key HMAC key
 * @param keylen HMAC key lenght
 * @param data Message to be hashed
 * @param datalen Message lenght
 * @param trunc HMAC-SHA256 hash size required
 * @return Returns the generated HMAC-SHA256 hash
 */
unsigned char *API_CP_hmac_sha256(unsigned char *key, int keylen, unsigned char *data, int datalen);


/**
 * @brief This function concatenates key k and message m, then returns a SHA256 hash of the concatenation.
 * 
 * @tsfi{LGOT, SHA, HMAC}
 * @sfr{FCS_COP.1.1, FDP_ACF.1.1, FAU_GEN.1.1, FAU_GEN.1.2, FAU_STG.1.1, FTA_TSE.1.1, FDP_ITC.2.1, FDP_ITC.2.2, FDP_ITC.2.3, FDP_ITC.2.4, FDP_ITC.2.5, FTA_SSL.4.1}
 * @methodOfUse{This function is invoked by the API_CP_hmac_sha256 function}
 * 
 * @param k Key
 * @param keylen Lenght of the key
 * @param m Message
 * @param mlen Message lenght
 * @param out Returnsed hash of concatenated key & message
 * @param outlen Out lenght
 */
static void CP_H_sha256(unsigned char *k, int keylen, unsigned char *m, int mlen, unsigned char *out);

#endif // _HMAC_H_
