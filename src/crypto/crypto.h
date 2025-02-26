/**
 * @file crypto.h
 * @brief File containing all the function headers of the cryptographic library interface.
 */

#ifndef CRYPTO_H
#define CRYPTO_H
#pragma once

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "SHA256.h"
#include "HMAC_SHA256.h"
#include "ECDSA_256.h"
#include "CRC_Galileo.h"
#include "AES_CORE.h"
#include "AES_CBC.h"
#include "AES_OFB.h"
#include "../library_tracer/log_manager.h"

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

typedef enum type_CRC {
    crc16,
    crc24,
    crc32,
} CRC;

/**
 * @brief Hash size number
 *
 * Defines the size of a SHA-256 hash digest.
 */
#define HASH_SIZE 32



extern AesContext aescbc_crypto_ctx;                      // AES AESCBC_CTX to store the derived AES key,CSP
extern AesContext aesofb_crypto_ctx;                      // AES AESOFB_CTX to store the derived AES key,CSP


/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/* Function declaration zone ........................................ */

/**
 * @brief Verifies the HMAC-SHA256 signature for a given message.
 *
 * This function computes and verifies the HMAC-SHA256 signature of a message using the provided key.
 *
 * @param msg Pointer to the message data.
 * @param key Pointer to the key data.
 * @param sign Pointer to the signature to verify.
 * @param length_msg Length of the message in bytes.
 * @param length_key Length of the key in bytes.
 * @param length_sign Length of the signature in bytes.
 * @param result Pointer to store the verification result (1 if successful, 0 if not).
 * 
 * @return 0 on success, non-zero on failure.
 */
int API_CP_verify_HMAC_SHA256(unsigned char *msg, unsigned char *key, unsigned char *sign, size_t length_msg, size_t length_key, size_t length_sign , uint8_t *result);

/**
 * @brief Computes the HMAC-SHA256 for a given message.
 *
 * This function computes the HMAC-SHA256 digest of a message using the provided key.
 *
 * @param msg Pointer to the message data.
 * @param key Pointer to the key data.
 * @param datalen Length of the message in bytes.
 * @param length_key Length of the key in bytes.
 * @param result Pointer to store the resulting HMAC-SHA256 digest.
 * 
 * @return 0 on success, non-zero on failure.
 */
int API_CP_hmac_sha256(unsigned char* msg, unsigned char* key, size_t datalen, size_t length_key , unsigned char **result);

/**
 * @brief Verifies an ECDSA-256 signature.
 *
 * This function verifies an ECDSA-256 signature of a given message using the provided public key.
 *
 * @param key Pointer to the public key.
 * @param msg Pointer to the message data.
 * @param sign Pointer to the signature to verify.
 * @param length_pukey Length of the public key in bytes.
 * @param length_msg Length of the message in bytes.
 * @param length_sign Length of the signature in bytes.
 * @param result Pointer to store the verification result (1 if successful, 0 if not).
 * 
 * @return 0 on success, non-zero on failure.
 */
int API_CP_verify_ECDSA256(unsigned char *key, unsigned char *msg, unsigned char *sign , size_t length_pukey , size_t length_msg , size_t length_sign , uint8_t *result);

/**
 * @brief Computes the SHA-256 hash of a given message.
 *
 * This function computes the SHA-256 hash of the provided message.
 *
 * @param msg Pointer to the message data.
 * @param length_msg Length of the message in bytes.
 * @param sha_out Pointer to store the resulting SHA-256 digest (32 bytes).
 * 
 * @return 0 on success, non-zero on failure.
 */
int API_CP_sha256(unsigned char *msg, size_t length_msg, unsigned char *sha_out);

/**
 * @brief Computes the CRC checksum for a given message.
 *
 * This function computes the CRC (Cyclic Redundancy Check) checksum of the provided message,
 * using the specified CRC type (16, 24, or 32 bits).
 *
 * @param msg Pointer to the message data.
 * @param lenght_msg Length of the message in bytes.
 * @param type_crc Type of CRC (crc16, crc24, crc32).
 * @param CRC_out Pointer to store the resulting CRC value.
 * 
 * @return 0 on success, non-zero on failure.
 */
int API_CP_crc(unsigned char *msg, size_t lenght_msg, CRC type_crc , unsigned int *CRC_out);

/**
 * @brief Encrypts a plaintext message using AES-CBC mode, uses PKCS7 padding
 *
 * This function encrypts the provided plaintext using AES-CBC (Cipher Block Chaining) mode.
 * The size of the plaintext buffer must be a multiple of 16 bytes.
 *
 * @param plaintext Pointer to the plaintext buffer.
 * @param len Pointer to the length of the plaintext (must be a multiple of 16 bytes).
 * @param key Pointer to the AES key.
 * @param AES_KEY_SIZE Size of the AES key in bits (128, 192, or 256 bits).
 * @param iv Pointer to the initialization vector (IV) for CBC mode.
 * @param ciphertext Pointer to the buffer to store the resulting ciphertext.
 * 
 * @return 0 on success, non-zero on failure.
 */
int API_CP_AESCBC_encrypt(unsigned char *plaintext, size_t *len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *ciphertext);

/**
 * @brief Decrypts a ciphertext message using AES-CBC mode, uses PKCS7 padding
 *
 * This function decrypts the provided ciphertext using AES-CBC (Cipher Block Chaining) mode.
 * The ciphertext buffer must be a multiple of 16 bytes.
 *
 * @param ciphertext Pointer to the ciphertext buffer.
 * @param len Pointer to the length of the ciphertext (must be a multiple of 16 bytes).
 * @param key Pointer to the AES key.
 * @param AES_KEY_SIZE Size of the AES key in bits (128, 192, or 256 bits).
 * @param iv Pointer to the initialization vector (IV) for CBC mode.
 * @param plaintext Pointer to the buffer to store the resulting plaintext.
 * 
 * @return 0 on success, non-zero on failure.
 */
int API_CP_AESCBC_decrypt(unsigned char *ciphertext, size_t *len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *plaintext);

int API_CP_AESOFB_encryptdecrypt(unsigned char *input, size_t in_len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *output);

#endif
