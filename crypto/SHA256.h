/**
 * @file sha256.h
 * @brief File containing all the function headers of the SHA_2_256 message hashing.
 */

#ifndef SHA_H
#define SHA_H

/* Compiler include files ............................................ */
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>


/* Private include files ............................................ */


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

/* Function declaration zone ........................................ */

/**
 * @brief Initializes the SHA256_STRUCT structure
 * 
 * The purpose of this function is to initialize the the SHA256_STRUCT structure in order to begin the SHA256
 * 
 *
 * @param sha256_struct Characteristic structure of the SHA256
 */
void CP_sha256_init(SHA256_STRUCT *sha256_struct);

/**
 * @brief Splits the message into 512 bits chunk and computes it if necessary
 * 
 * The purpose of this function is to introduce our message into the 512bits chunk. If the chunk is completed, it is send to be computed.
 * 
 *
 * @param sha256_struct Characteristic structure of the SHA256
 * @param data Message to hash
 * @param len Message length
 */
void CP_sha256_update(SHA256_STRUCT *sha256_struct, const SHA256_BYTE data[], size_t len);

/**
 * @brief Computes the SHA256 algorithm
 * 
 * The purpose of this function is to compute the necessary operations of the SHA256 algorithm of a 512bits chunk
 * 
 *
 * @param sha256_struct Characteristic structure of the SHA256
 * @param data Portion of message to hash
 */
void CP_sha256_computation(SHA256_STRUCT *sha256_struct, const SHA256_BYTE data[]);

/**
 * @brief Processes the final chunk of 512 bits and calculates the final hash
 * 
 * The purpose of this function is to process the final chunk of 512bits by padding and adding the message lenght. Finally, it calculates the final hash.
 *  
 *
 * @param sha256_struct Characteristic structure of the SHA256
 * @param hash SHA256 message hash of 256-bit
 */
void CP_sha256_final(SHA256_STRUCT *sha256_struct, SHA256_BYTE hash[]);


void API_sha256(unsigned char *node,int lenght_node , unsigned char *out);


#endif
