/**
 * @file HMAC_SHA256.h
 * @brief File containing all the function headers of the HMAC message hashing.
 */

#ifndef _HMAC_H_
#define _HMAC_H_

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stddef.h>
#include <stdint.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "SHA256.h"

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

/**
 * @brief MAC not verified value
 * This variable defines the value when the MAC is not verified
 */
#define MAC_NOT_VERIFIED 0

/**
 * @brief MAC verified value
 * This variable defines the value when the MAC is verified
 */
#define MAC_VERIFIED 1

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

extern unsigned char HMAC256_ihash[SHA256_HASH_SIZE];
extern unsigned char HMAC256_ohash[SHA256_HASH_SIZE];
extern unsigned char HMAC256_k[HMAC_SHA256_BLOCK_SIZE];
extern unsigned char HMAC256_k_ipad[HMAC_SHA256_BLOCK_SIZE];
extern unsigned char HMAC256_k_opad[HMAC_SHA256_BLOCK_SIZE];
extern SHA256_STRUCT HMAC256_sha256_struct; 

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief This function returns the HMAC-SHA256 hash of a given message with a given key
 * 
 * 
 * @param key HMAC key
 * @param keylen HMAC key lenght
 * @param data Message to be hashed
 * @param datalen Message lenght
 * @return Returns the generated HMAC-SHA256 hash
 */
unsigned char *API_hmac_sha256(unsigned char *key, int keylen, unsigned char *data, int datalen);


/**
 * @brief This function concatenates key HMAC256_k and message m, then returns a SHA256 hash of the concatenation.
 * 
 * 
 * @param HMAC256_k Key
 * @param keylen Lenght of the key
 * @param m Message
 * @param mlen Message lenght
 * @param out Returnsed hash of concatenated key & message
 * @param outlen Out lenght
 */
static void CP_H_sha256(unsigned char *HMAC256_k, int keylen, unsigned char *m, int mlen, unsigned char *out);

/**
 * @brief Verify the HMAC-SHA256 signature sent by the receiver
 *
 * The purpose of this function is to verify the HMAC-SHA256 signature received by the
 * library and verify if it is correct or not. Then returns the result of the verification
 *
 *
 * @param msg Message we want to verify
 * @param key Key used to sign the message
 * @param sign HMAC signature generated to grant the message integrity
 * @param length_msg Message length
 * @param length_key HMAC key length
 * @param length_sign HMAC signature length 
 * 
 * @return Returns an 1 if the function was successfull, or 0 if the function failed
 *
 * @errors
 * @error{ ERROR 1, The parameter msg key sign or mode has a NULL value or is empty }
 * @error{ ERROR 2, The parameter sign or length_sign is incorrect NULL or zero }
 */
int API_verify_HMAC(unsigned char* msg, unsigned char* key, unsigned char* sign, size_t length_msg, size_t length_key, size_t length_sign);

static void sha256_HMAC(unsigned char *key,size_t key_length,unsigned char *msg, int length_msg ,unsigned char *out);

#endif // _HMAC_H_
