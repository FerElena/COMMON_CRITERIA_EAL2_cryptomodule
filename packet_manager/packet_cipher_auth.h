/**
 * @file file_system.c
 * @brief File containing all the functions for the cryptographic library file system
 */

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/
#include <stdlib.h>
#include <string.h>

#include "../crypto/crypto.h"
#include "../Dynamic_Memory_Manager/DmemManager.h"
#include "../prng/random_number.h"

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/
#define HMAC_SHA256_key_size 32

#define HMAC_SHA256_sign_size 32

#define AESCBC_key_size 32

#define data_buffer_sign_encrypt_length 262144 //256 kilobytes of static memory so it is not necesary to allocate memory all time CSP


#define ALLOCATED_MEMORY 1

#define NOT_ALLOCATED_MEMORY 0

/*
estructura del paquete cifrado, el texto y la firma están cifrados por el AES-CBC-256

+-----------------------+-----------------------+--------------------------+------------------------+
|  Paquete de 8 bytes   |  IV de AES (16 bytes) |   Texto (longitud n)     | Firma HMAC (32 bytes)  |
+-----------------------+-----------------------+--------------------------+------------------------+
|                       |                       |                          |                        |
|  [Tamaño del paquete] |   [IV AES de 16 B]    |  [Texto de longitud n]   |  [Firma HMAC de 32 B]  |
|        (8 B)          |        (16 B)         |         (n B)            |         (32 B)         |
|                       |                       |                          |                        |
+-----------------------+-----------------------+--------------------------+------------------------+

*/


/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/


int API_PCA_sign_encrypt_packet(unsigned char *data_in, size_t data_in_length, unsigned char *key_AES, unsigned char *key_HMAC, unsigned char **out_data, size_t *out_data_length);

int API_PCA_decrypt_verify_packet(unsigned char *data_in, size_t data_in_length, unsigned char *key_AES, unsigned char *key_HMAC, unsigned char **out_data ,unsigned char *verify);