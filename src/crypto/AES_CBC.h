/**
 * @file AES_CBC.h
 * @brief File containing all the function headers of the AES_CBC.
 */

#ifndef AESCBC_H
#define AESCBC_H


/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <memory.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "AES_CORE.h"


/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

/**
 * @brief AES_CBC context struct
 */

extern AesContext AES_CBC_ctx; //auxiliar ctx to store round keys, CSP!

/* Macros............................................................ */

#define MIN(x, y) (((x) < (y)// SHA256 selftests starts) ? (x) : (y))

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

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief Adds PKCS#7 padding to a message for AES encryption.
 *
 * PKCS#7 padding is used to ensure that the message length is a multiple of the AES block size.
 * The padding added is the number of bytes needed to complete the block, with each padding byte
 * set to the number of padding bytes added.
 *
 * @param[in,out] message Pointer to the original message buffer. This buffer will be modified to include padding.
 * @param[in,out] length Pointer to the length of the original message. This value will be updated to reflect
 *                       the new length after padding.
 * @param[out] padded_message Pointer to the buffer where the padded message will be stored. It should be
 *                             large enough to accommodate the padded message.
 */

void CP_addPaddingAes(unsigned char *message, size_t *length, unsigned char *padded_message);

/**
 * @brief Retrieves the length of the PKCS#7 padding from a padded message.
 *
 * This function checks the padding of a message and returns the length of the padding. If the padding
 * is invalid (e.g., the padding bytes do not match or exceed the block size), the function returns -1.
 *
 * @param[in] padded_message Pointer to the padded message buffer.
 * @param[in] length The length of the padded message.
 *
 * @return The length of the padding in bytes if valid, otherwise -1 if padding is invalid.
 */

int CP_getPaddingLength(const unsigned char *padded_message, size_t length);

/**
 * @brief Performs XOR between two AES blocks.
 * 
 * This function performs an XOR operation between two blocks of data of size AES_BLOCK_SIZE.
 *
 * @param[in] Block1  The first block of data. The result is stored in this block.
 * @param[in] Block2  The second block of data to XOR with Block1.
 * @param[out] result Result of the XOR block operation
 */

void CP_XorAesBlock(uint8_t *Block1, uint8_t const *Block2, uint8_t *result);


/**
 * @brief Encrypts plaintext using AES-CBC mode.
 *
 * This function initializes the AES-CBC context with the provided key and IV, and then encrypts the plaintext.
 *
 * @param[in]  plaintext  The buffer containing the plaintext to encrypt.
 * @param[in,out] len     The length of the plaintext buffer. Updated to the length of the ciphertext.
 * @param[in]  key        The encryption key.
 * @param[in]  AES_KEY_SIZE The size of the encryption key.
 * @param[in]  iv         The initialization vector for CBC mode.
 * @param[out] ciphertext The buffer to store the encrypted ciphertext.
 * 
 * @return 1 on success, 0 on failure.
 */

int API_AESCBC_encrypt(unsigned char *plaintext, size_t len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *ciphertext);

/**
 * @brief Decrypts ciphertext using AES-CBC mode.
 *
 * This function initializes the AES-CBC context with the provided key and IV, and then decrypts the ciphertext.
 *
 * @param[in]  ciphertext The buffer containing the ciphertext to decrypt.
 * @param[in,out] len      The length of the ciphertext buffer. Updated to the length of the plaintext.
 * @param[in]  key         The encryption key.
 * @param[in]  AES_KEY_SIZE The size of the encryption key.
 * @param[in]  iv          The initialization vector for CBC mode.
 * @param[out] plaintext   The buffer to store the decrypted plaintext.
 * 
 * @return 1 on success, 0 on failure.
 */

int API_AESCBC_decrypt(unsigned char *ciphertext, size_t len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *plaintext);


#endif 
