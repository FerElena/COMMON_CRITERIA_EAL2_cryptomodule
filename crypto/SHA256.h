/**
 * @file sha256.h
 * @brief File containing all the function headers of the SHA_2_256 message hashing.
 */

#ifndef SHA_H
#define SHA_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>


/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/


/* Macros............................................................ */

/**
 * @brief Macro used to rotate the variable a, a number of bits to the right according to b for SHA256
*/
#define SHA256_ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

/**
 * @brief Macro used to perform the operation (x AND y)XOR(NOR(x AND z)) to the variables x y and z in an easy way (CH operation)
*/
#define SHA256_CH(x, y, z) ( (x & y) ^ ((~x) & z) )

/**
 * @brief Macro used to perform the operation  (x AND y) XOR (x AND z) XOR (y AND z) to the variables x y and z in an easy way (MAJ operation)
*/
#define SHA256_MAJ(x, y, z) ( (x & y) ^ (x & z) ^ (y & z) )

/**
 * @brief  Macro used to shift the bytes of x variable  2 positions, 13 positions and 22 positions to the right, and XOR between the 3 results
*/
#define SHA256_EP0(x) (SHA256_ROTRIGHT(x, 2) ^ SHA256_ROTRIGHT(x, 13) ^ SHA256_ROTRIGHT(x, 22))

/**
 * @brief  Macro used to shift the bytes of x variable  6 positions, 11 positions and 25 positions to the right, and XOR between the 3 results
*/

#define SHA256_EP1(x) (SHA256_ROTRIGHT(x, 6) ^ SHA256_ROTRIGHT(x, 11) ^ SHA256_ROTRIGHT(x, 25))

/**
 * @brief  Macro used to shift the bytes of x variable  7 positions, 18 positions and shift x 3 positions to the right, and XOR between the 3 results
*/

#define SHA256_SIG0(x) (SHA256_ROTRIGHT(x, 7) ^ SHA256_ROTRIGHT(x, 18) ^ ((x) >> 3))

/**
 * @brief Macro used to shift the bytes of x variable  17 positions, 19 positions and shift x 10 positions to the right, and XOR between the 3 results
*/
#define SHA256_SIG1(x) (SHA256_ROTRIGHT(x, 17) ^ SHA256_ROTRIGHT(x, 19) ^ ((x) >> 10))


/* Type definitions ................................................. */

/**
 * @brief Byte data type
 * Unsigned char reserved to be used as a 8-bit byte
 */
typedef unsigned char SHA256_BYTE;  

/**
 * @brief 32-bit integer data type
 * Unsigned int reserved to be used as a 32-bit integer , change to "long" for 16-bit machines
 */
typedef unsigned int _INT32; 

/**
 * @brief SHA256 structure wich stores the data of a sha256 block, the length of that data, and the temporal hash performed 
 */
typedef struct
{
    SHA256_BYTE data[64]; /**< 64 bytes data array for the hash */
    _INT32 datalen; /**< Hash data length */
    unsigned long long bitlen; /**< SHA bit length */
    _INT32 temp_hash[8]; /**< Temporal hash performed */
} SHA256_STRUCT;

/* Global variables definition ...................................... */

/**
 * @brief Success code
 * 
 * Code sent when the function success 
 */
#define SUCCESS 1

/**
 * @brief Fail code
 * 
 * Code sent when the function fails 
 */
#define FAIL 0

/**
 * @brief Hash block size
 * SHA256 digest message size
 */
#define SHA256_BLOCK_SIZE 32 

extern SHA256_STRUCT SHA256_ctx; // CSP

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/* Function declaration zone ........................................ */

/**
 * @brief Initializes the SHA-256 context.
 *
 * This function sets the initial hash values for the SHA-256 algorithm and resets the
 * data length and bit length fields in the provided SHA256_STRUCT. The initial hash values
 * are derived from the first 32 bits of the fractional parts of the square roots of the first
 * eight prime numbers.
 *
 * @param SHA256_ctx [out] Pointer to a SHA256_STRUCT that will be initialized.
 */

void CP_sha256_init(SHA256_STRUCT *SHA256_ctx);

/**
 * @brief Updates the SHA-256 context with new data.
 *
 * This function takes new data and adds it to the SHA-256 context. If a 512-bit chunk is
 * completed, it is processed using the SHA-256 computation function. The function manages
 * the data buffer and keeps track of the length of the data and bit length.
 *
 * @param SHA256_ctx [in, out] Pointer to a SHA256_STRUCT that holds the current state of the hash computation.
 * @param data [in] Pointer to the data to be added to the hash.
 * @param len [in] The length of the data to be added, in bytes.
 */

void CP_sha256_update(SHA256_STRUCT *SHA256_ctx, const SHA256_BYTE data[], size_t len);

/**
 * @brief Computes the SHA-256 hash for a given 512-bit chunk of data.
 *
 * This function processes a 512-bit chunk of data using the SHA-256 algorithm and updates the
 * intermediate hash values stored in the provided SHA256_STRUCT. The chunk is expanded into
 * 64 words, and the hash computation is performed in 64 rounds as specified by the SHA-256
 * algorithm.
 *
 * @param SHA256_ctx [in, out] Pointer to a SHA256_STRUCT that holds the current state of the hash computation.
 * @param data [in] Pointer to the 512-bit chunk of data to be processed.
 */

void CP_sha256_computation(SHA256_STRUCT *SHA256_ctx, const SHA256_BYTE data[]);

/**
 * @brief Finalizes the SHA-256 hash computation and produces the final hash value.
 *
 * This function pads any remaining data in the buffer, appends the length of the original
 * message in bits, and performs the final hash computation. It then copies the resulting
 * hash value into the provided output array, ensuring that the byte order is correct.
 *
 * @param SHA256_ctx [in, out] Pointer to a SHA256_STRUCT that holds the current state of the hash computation.
 * @param hash [out] Pointer to an array where the final SHA-256 hash value will be stored.
 */

void CP_sha256_final(SHA256_STRUCT *SHA256_ctx, SHA256_BYTE hash[]);

/**
 * @brief Computes the SHA-256 hash of a message.
 *
 * This function initializes the SHA-256 context, processes the provided message, and
 * finalizes the hash computation. The result is stored in the output array.
 *
 * @param msg [in] Pointer to the message data to be hashed.
 * @param length_msg [in] The length of the message data, in bytes.
 * @param out [out] Pointer to an array where the final SHA-256 hash value will be stored.
 */

void API_sha256(unsigned char *msg,int length_msg , unsigned char *out);


#endif
