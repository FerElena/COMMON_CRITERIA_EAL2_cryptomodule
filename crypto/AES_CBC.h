/**
 * @file AES_CBC.h
 * @brief File containing all the function headers of the AES_CBC.
 */

#ifndef AESCBC_H
#define AESCBC_H


/* Compiler include files ............................................ */
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <memory.h>

 /* Private include files ............................................ */

#include "AES_CORE.h"


/* Type definitions ................................................. */

/**
 * @brief AES_CBC context struct
 */
typedef struct AesCbcContext {
    AesContext      Aes; /*Actual AES context block*/
    uint8_t         PreviousCipherBlock [AES_BLOCK_SIZE]; /*Previous AES cipher block*/
} AesCbcContext;


/* Macros............................................................ */

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define STORE64H(x, y)                     \
  {                                        \
    (y)[0] = (uint8_t)(((x) >> 56) & 255); \
    (y)[1] = (uint8_t)(((x) >> 48) & 255); \
    (y)[2] = (uint8_t)(((x) >> 40) & 255); \
    (y)[3] = (uint8_t)(((x) >> 32) & 255); \
    (y)[4] = (uint8_t)(((x) >> 24) & 255); \
    (y)[5] = (uint8_t)(((x) >> 16) & 255); \
    (y)[6] = (uint8_t)(((x) >> 8) & 255);  \
    (y)[7] = (uint8_t)((x)&255);           \
  }

/* Function declaration zone ........................................ */

void CP_XorAesBlock(uint8_t *Block1, uint8_t const *Block2);

void CP_AesCbcInitialize(AesCbcContext* Context, AesContext const* InitializedAesContext, uint8_t const IV [AES_BLOCK_SIZE]);

int CP_AesCbcInitializeWithKey(AesCbcContext* Context, uint8_t const* Key, uint32_t KeySize, uint8_t const IV [AES_BLOCK_SIZE]);

int CP_AesCbcEncrypt(AesCbcContext* Context, void const* InBuffer, void* OutBuffer, uint32_t Size);

int CP_AesCbcDecrypt(AesCbcContext* Context, void const* InBuffer, void* OutBuffer, uint32_t Size);

int API_AESCBC_encrypt(unsigned char *plaintext, size_t *len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *ciphertext);

int API_AESCBC_decrypt(unsigned char *ciphertext, size_t *len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *plaintext);

void CP_addPaddingAes(unsigned char *message, size_t *length, unsigned char *padded_message);

int CP_getPaddingLength(const unsigned char *padded_message, size_t length);


#endif 
