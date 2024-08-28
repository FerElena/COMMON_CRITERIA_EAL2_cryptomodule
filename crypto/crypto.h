/**
 * @file crypto.h
 * @brief File containing all the function headers of the cryptographic library interface.
 */

#ifndef CRYPTO_H
#define CRYPTO_H
#pragma once

/* Private include files ............................................ */

#include "sha256.h"
#include "mac_verify.h"
#include "ECDSA_256.h"
#include "CRC_Galileo.h"
#include "AES_CBC.h"

#include "../library_tracer/log_manager.h"

/* Global variables definition ...................................... */

typedef enum type_CRC{
    crc16,
    crc24,
    crc32,
}CRC;

/**
 * @brief Segmentation fault code
 *
 * Error code sent when a crypto function fails
 */
#define SEGMENTATION_FAULT -1
/**
 * @brief Hash size number
 *
 * SHA-256 Hash digest size
 */
#define HASH_SIZE 32

/**
 * @brief Copernicus Page Length
 * 
 */
#define COPERNICUS_PAGE_LENGTH 32


/* Function declaration zone ........................................ */


int API_CP_verify_HMAC_SHA256(unsigned char *msg, unsigned char *key, unsigned char *sign, size_t length_msg, size_t length_key, size_t length_sign , uint8_t *result);

int API_CP_verify_ECDSA256(unsigned char *key,unsigned char *msg, unsigned char *sign , size_t length_pukey , size_t length_msg , size_t length_sign , uint8_t *result);

int API_CP_sha256(unsigned char *msg, size_t length_msg,unsigned char *sha_out);

int API_CP_crc(unsigned char *msg,size_t lenght_msg,CRC type_crc , unsigned int *CRC_out);

#endif
