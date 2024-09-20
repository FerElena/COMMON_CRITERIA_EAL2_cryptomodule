/**
 * @file module_initialization.h
 * @brief Header file for module initialization and memory tracking functionality.
 *
 * This file contains the declarations for initializing memory trackers
 * and managing cryptographic components such as AES, ECDSA, HMAC, and SHA-256.
 */

#ifndef MODULE_INITIALIZATION_H
#define MODULE_INITIALIZATION_H

#include <stdlib.h>
#include <stdint.h>

#include "../secure_memory_management/file_system.h"
#include "../secure_memory_management/MemoryTracker.h"
#include "packet_cipher_auth.h"
#include "../crypto/AES_CBC.h"
#include "../crypto/AES_OFB.h"
#include "../crypto/ECDSA_256.h"
#include "../crypto/SHA256.h"

// TI (TRACKER INDEX) LIST for volatile memory integrity/zeroization
extern int TI_FS_cipher_key;      /**< File system cipher key tracker index */
extern int TI_FS_data_buffer;     /**< File system auxiliary data buffer tracker index */
extern int TI_PCA_data_buffer_sed; /**< Packet cipher and authentication module data buffer tracker index */
extern int TI_PCA_data_buffer_sed_aux; /**< Packet cipher and authentication module auxiliary data buffer tracker index */

// AES CSPs parameters
extern int TI_AES_CBC_ctx;        /**< AES-CBC context tracker index */
extern int TI_AESOFB_CTX;         /**< AES-OFB context tracker index */
extern int TI_AESOFB_outputBlock; /**< AES-OFB output block tracker index */
extern int TI_AESOFB_ivEnc;       /**< AES-OFB initialization vector encryption tracker index */

// ECDSA-256 operation parameters with private keys
extern int TI_ECDSA_curve_p;      /**< ECDSA curve parameter p tracker index */
extern int TI_ECDSA_curve_B;      /**< ECDSA curve parameter B tracker index */
extern int TI_ECDSA_curve_G;      /**< ECDSA curve generator point G tracker index */
extern int TI_ECDSA_curve_n;      /**< ECDSA curve order n tracker index */
extern int TI_ECDSA_k;            /**< ECDSA ephemeral key k tracker index */
extern int TI_ECDSA_l_tmp;        /**< ECDSA temporary value tracker index */
extern int TI_ECDSA_l_s;          /**< ECDSA signature value tracker index */

// HMAC-SHA256 operation parameters with secret keys
extern int TI_HMAC256_ihash;      /**< HMAC-SHA256 inner hash tracker index */
extern int TI_HMAC256_ohash;      /**< HMAC-SHA256 outer hash tracker index */
extern int TI_HMAC256_k;          /**< HMAC-SHA256 secret key tracker index */
extern int TI_HMAC256_k_ipad;     /**< HMAC-SHA256 key inner padding tracker index */
extern int TI_HMAC256_k_opad;     /**< HMAC-SHA256 key outer padding tracker index */
extern int TI_HMAC256_sha256_struct; /**< HMAC-SHA256 context structure tracker index */

// SHA-256 parameters
extern int TI_SHA256_ctx;         /**< SHA-256 context tracker index */

/**
 * @brief Initializes the memory tracking system and registers cryptographic components.
 *
 * This function initializes the memory tracking system for the cryptographic modules used
 * within the system, such as AES, ECDSA, HMAC, and SHA-256. It assigns tracker indexes
 * to each cryptographic component to ensure volatile memory integrity and proper zeroization.
 *
 * @return 0 on success, non-zero on failure.
 */
int Memory_tracking_initialization();

#endif // MODULE_INITIALIZATION_H
