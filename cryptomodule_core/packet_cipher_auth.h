/**
 * @file packet_cipher_auth.h
 * @brief File containing the definition for packet cipherer/authenticator
 */
#ifndef PACKET_CIPHER_AUTH_H
#define PACKET_CIPHER_AUTH_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdlib.h>
#include <string.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "../crypto/crypto.h"
#include "../secure_memory_management/DmemManager.h"
#include "../prng/random_number.h"
#include "../state_machine/State_Machine.h"

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

#define HMAC_SHA256_key_size 32

#define HMAC_SHA256_sign_size 32

#define AESCBC_key_size 32

#define IV_size_header_length 24

#define data_buffer_sign_encrypt_length 262144 //256 kilobytes of static memory so it is not necesary to allocate memory all time CSP


#define NOT_ALLOCATED_MEMORY 1

#define ALLOCATED_MEMORY 2

extern unsigned char PCA_data_buffer_sed[data_buffer_sign_encrypt_length]; // 256 kilobytes of static memory to avoid memory allocation every time CSP is used
extern unsigned char PCA_data_buffer_sed_aux[data_buffer_sign_encrypt_length];

/*
Structure of the encrypted packet; the text and signature are encrypted using AES-CBC-256.



+-----------------------+-----------------------+--------------------------+---------------------------+
|   8-byte Packet       |   AES IV (16 bytes)   | HMAC Signature (32 bytes)|       Text (length n)     |
+-----------------------+-----------------------+--------------------------+---------------------------+
|                       |                       |                          |                           |
|   [Packet Size]       |   [16-byte AES IV]    | [32-byte HMAC Signature] |     [Text of length n]    |
|        (8 B)          |        (16 B)         |           (32 B)         |           (n B)           |
|                       |                       |                          |                           |
+-----------------------+-----------------------+--------------------------+---------------------------+

*/


/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief Encrypt and sign a data packet using AES CBC and HMAC-SHA256.
 * 
 * This function first calculates the HMAC-SHA256 signature of the input data,
 * appends the data to the signature, and then encrypts the combined data using
 * AES CBC encryption. The function handles padding and dynamically allocates
 * memory if the default buffer is not large enough (IMPORTANT FREE MEMORY IF MEMORY HAVE BEEN ALLOCATED).
 *
 * @param data_in Pointer to the input data.
 * @param data_in_length Length of the input data.
 * @param key_AES Pointer to the AES key.
 * @param key_HMAC Pointer to the HMAC key.
 * @param out_data Pointer to the output buffer that will contain the encrypted data.
 * @param out_data_length Pointer to a size_t that will be set to the length of the encrypted data.
 * 
 * @return Returns 1 on NOT ALLOCATED MEMORY, 2 on ALLOCATED_MEMORY, potentially different values on failure to indicate the type of error.
 */
int API_PCA_sign_encrypt_packet(unsigned char *data_in, size_t data_in_length, unsigned char *key_AES, unsigned char *key_HMAC, unsigned char **out_data, size_t *out_data_length);

/**
 * @brief Decrypt a data packet and verify its HMAC signature using AES CBC and HMAC-SHA256.
 * 
 * This function decrypts a data packet that was encrypted and signed using the
 * API_PCA_sign_encrypt_packet function. It first decrypts the data using AES CBC,
 * then verifies the HMAC-SHA256 signature of the decrypted data. The function
 * dynamically allocates memory if the input data length exceeds the size of the
 * default buffer (IMPORTANT FREE MEMORY IF MEMORY HAVE BEEN ALLOCATED).
 *
 * @param data_in Pointer to the encrypted data packet.
 * @param data_in_length Length of the encrypted data packet.
 * @param key_AES Pointer to the AES key.
 * @param key_HMAC Pointer to the HMAC key.
 * @param out_data Pointer to the output buffer that will contain the sign + the decrypted data, in order to access decrypted data, +32 the pointer.
 * @param out_data_length  Pointer to a size_t that will be set to the length of the plain data.
 * @param verify Pointer to the buffer where the result of the HMAC verification will be stored.
 * 
 * @return Returns  1 on NOT ALLOCATED MEMORY, 2 on ALLOCATED_MEMORY, potentially different values on failure to indicate the type of error.
 */
int API_PCA_decrypt_verify_packet(unsigned char *data_in, size_t data_in_length, unsigned char *key_AES, unsigned char *key_HMAC, unsigned char **out_data, size_t *out_data_length ,unsigned char *verify);

#endif