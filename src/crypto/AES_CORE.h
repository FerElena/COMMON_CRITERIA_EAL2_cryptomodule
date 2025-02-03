/**
 * @file AES_CORE.h
 * @brief File containing all the function headers to interact with AES_CBC tables.
 */

#ifndef AESCORE_H
#define AESCORE_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdint.h>
#include <memory.h>

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

/**
 * @brief AES-128 key size
 * 
 */
#define AES_KEY_SIZE_128        16

/**
 * @brief AES-192 key size
 * 
 */
#define AES_KEY_SIZE_192        24

/**
 * @brief AES-256 key size
 * 
 */
#define AES_KEY_SIZE_256        32

/**
 * @brief AES block size
 * 
 */
#define AES_BLOCK_SIZE          16

/* Type definitions ................................................. */
/**
 * @brief AES context that must be initialized using API_CP_AesInitialize128, API_CP_AesInitialize192 or API_CP_AesInitialize256.
 * 
 */
typedef struct AesContext {
    uint32_t        eK[60]; /*Expanded cipher key*/
    uint32_t        dK[60]; /*Expanded decipher key  */
    uint_fast32_t   Nr; /*Round number*/
} AesContext;


/* Macros............................................................ */
#define Te0(x) TE0[x]
#define Te1(x) TE1[x]
#define Te2(x) TE2[x]
#define Te3(x) TE3[x]

#define Td0(x) TD0[x]
#define Td1(x) TD1[x]
#define Td2(x) TD2[x]
#define Td3(x) TD3[x]

#define BYTE(x, n) (((x) >> (8 * (n))) & 255)

#define STORE32H(x, y)                           \
{                                                \
    (y)[0] = (unsigned char)(((x)>>24)&255);     \
    (y)[1] = (unsigned char)(((x)>>16)&255);     \
    (y)[2] = (unsigned char)(((x)>>8)&255);      \
    (y)[3] = (unsigned char)((x)&255);           \
}

#define LOAD32H(x, y)                            \
{                                                \
    x = ((uint32_t)((y)[0] & 255)<<24)           \
      | ((uint32_t)((y)[1] & 255)<<16)           \
      | ((uint32_t)((y)[2] & 255)<<8)            \
      | ((uint32_t)((y)[3] & 255));              \
}

#define ROL(x, y)  ( (((uint32_t)(x)<<(uint32_t)((y)&31)) | (((uint32_t)(x)&0xFFFFFFFFUL)>>(uint32_t)((32-((y)&31))&31))) & 0xFFFFFFFFUL)
#define ROR(x, y)  ( ((((uint32_t)(x)&0xFFFFFFFFUL)>>(uint32_t)((y)&31)) | ((uint32_t)(x)<<(uint32_t)((32-((y)&31))&31))) & 0xFFFFFFFFUL)
#define ROLc(x, y) ( (((uint32_t)(x)<<(uint32_t)((y)&31)) | (((uint32_t)(x)&0xFFFFFFFFUL)>>(uint32_t)((32-((y)&31))&31))) & 0xFFFFFFFFUL)
#define RORc(x, y) ( ((((uint32_t)(x)&0xFFFFFFFFUL)>>(uint32_t)((y)&31)) | ((uint32_t)(x)<<(uint32_t)((32-((y)&31))&31))) & 0xFFFFFFFFUL)

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief Initializes an AES context with an AES Key.
 * 
 * 
 * @param Context AES struct that contains the context
 * @param Key AES key
 * @param KeySize AES key size
 * @return Returns a 0 if the function was successfull
 * 
 * @errors
 * @error{ ERROR 1, Return -1 if the key size is incorrect} 
 */
int API_CP_AesInitialize (AesContext* Context, void const* Key, uint32_t KeySize);

/**
 * @brief Performs an AES encryption of one block (128 bits) with an AES context
 * 
 * 
 * @param Context AES context
 * @param Input Input for the function AES to be encrypted
 * @param Output AES output encrypted
 */
void API_CP_AesEncrypt(AesContext const* Context, uint8_t const Input [AES_BLOCK_SIZE], uint8_t Output [AES_BLOCK_SIZE]);

/**
 * @brief Performs an AES decryption of one block (128 bits) with an AES context
 * 
 * 
 * @param Context AES context
 * @param Input Input for the function AES to be decrypted
 * @param Output AES output decrypted
 */
void API_CP_AesDecrypt(AesContext const* Context, uint8_t const Input [AES_BLOCK_SIZE], uint8_t Output [AES_BLOCK_SIZE]);


#endif