/**
 * @file module_initialization.h
 * @brief Header file for module initialization and memory tracking functionality.
 *
 * This file contains the declarations for initializing memory MT_trackers
 * and managing cryptographic components such as AES, ECDSA, HMAC, and SHA-256.
 */

#ifndef MODULE_INITIALIZATION_H
#define MODULE_INITIALIZATION_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "Key_management.h"
#include "packet_cipher_auth.h"
#include "../secure_memory_management/file_system.h"
#include "../secure_memory_management/MemoryTracker.h"
#include "../state_machine/State_Machine.h"
#include "../library_tracer/log_manager.h"
#include "../crypto/crypto.h"
#include "../crypto/AES_CBC.h"
#include "../crypto/AES_OFB.h"
#include "../crypto/AES_CORE.h"
#include "../crypto/ECDSA_256.h"
#include "../crypto/SHA256.h"
#include "../prng/random_number.h"

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

// memorytracker initialization codes
#define CORRECT_TRACKER_INIT 1700
#define INIT_INCORRECT_TRACKER_INIT -1700
#define PREVIUS_NORMAL_STATE 1
#define PREVIUS_ERROR_STATE 2

// filesystem initialization codes
#define CORRECT_FILESYSTEM_INIT 1701
#define INIT_INCORRECT_KEYFILE_PATH -1701
#define INIT_INCORRECT_KEYFILE_FORMAT -1702
#define INIT_INCORRECT_KEYFILE_READ -1703
#define INIT_INCORRECT_FILESYSTEM_INIT -1704
#define INIT_TRACER_INIT_ERROR -1705
#define INIT_PREVIUS_ERROR_STATE -1706

#define INITIALIZE_OK_FIRST_INIT 1705
#define INITIALIZE_OK_NORMAL_INIT 1706

// TI (TRACKER INDEX) LIST for volatile memory integrity/zeroization
extern int TI_FS_cipher_key;	       /**< File system cipher key tracker index */
extern int TI_FS_data_buffer;	       /**< File system auxiliary data buffer tracker index */
extern int TI_PCA_data_buffer_sed;     /**< Packet cipher and authentication module data buffer tracker index */
extern int TI_PCA_data_buffer_sed_aux; /**< Packet cipher and authentication module auxiliary data buffer tracker index */
extern int TI_Current_Key_In_Use;      /**< Current key in use for cipher and authenticate packets */

// AES CSPs parameters
extern int TI_AES_CBC_ctx;	  /**< AES-CBC context tracker index */
extern int TI_AESOFB_ctx;	  /**< AES-OFB context tracker index */
extern int TI_AESOFB_outputBlock; /**< AES-OFB output block tracker index */
extern int TI_AESOFB_ivEnc;	  /**< AES-OFB initialization vector encryption tracker index */
extern int TI_AESGCM_ctx;     /**< AES-GCM context tracker index */

// ECDSA-256 operation parameters with private keys
extern int TI_ECDSA_curve_p; /**< ECDSA curve parameter p tracker index */
extern int TI_ECDSA_curve_B; /**< ECDSA curve parameter B tracker index */
extern int TI_ECDSA_curve_G; /**< ECDSA curve generator point G tracker index */
extern int TI_ECDSA_curve_n; /**< ECDSA curve order n tracker index */
extern int TI_ECDSA_k;	     /**< ECDSA ephemeral key k tracker index */
extern int TI_ECDSA_l_tmp;   /**< ECDSA temporary value tracker index */
extern int TI_ECDSA_l_s;     /**< ECDSA signature value tracker index */

// HMAC-SHA256 operation parameters with secret keys
extern int TI_HMAC256_ihash;	     /**< HMAC-SHA256 inner hash tracker index */
extern int TI_HMAC256_ohash;	     /**< HMAC-SHA256 outer hash tracker index */
extern int TI_HMAC256_k;	     /**< HMAC-SHA256 secret key tracker index */
extern int TI_HMAC256_k_ipad;	     /**< HMAC-SHA256 key inner padding tracker index */
extern int TI_HMAC256_k_opad;	     /**< HMAC-SHA256 key outer padding tracker index */
extern int TI_HMAC256_sha256_struct; /**< HMAC-SHA256 context structure tracker index */

// SHA-256 parameters
extern int TI_SHA256_ctx; /**< SHA-256 context tracker index */

#define CONF_FILENAME "Configuration_file"
#define CERT_FILENAME "Auth_certificate_file"

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

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

/**
 * @brief Performs the first-time initialization of the file system.
 *
 * This function initializes the file system by:
 * 1. Checking if the provided KEK certificate file path is valid.
 * 2. Attempting to open the KEK certificate file in binary read mode.
 * 3. Reading the AES-256 key, ECDSA signature, and public key from the file.
 * 4. Initializing the file system in 'init' mode.
 * 5. Setting up AES encryption with the loaded key.
 * 6. Creating configuration and authentication certificate files.
 * 7. Zeroing out the memory space used for the key.
 *
 * @param KEK_CERTIFICATE_file A pointer to the KEK certificate file.
 * @param Cryptodata_filename A pointer to the cryptodata file.
 * @return Returns CORRECT_FILESYSTEM_INIT if initialization is successful,
 *         otherwise returns an error code.
 */
int File_system_first_initialization(unsigned char *KEK_CERTIFICATE_file, unsigned char *Cryptodata_filename);

/**
 * @brief Performs normal initialization of the file system using the provided Key Encryption Key (KEK).
 *
 * This function reads a 256-bit AES key from the provided key file (KEK_CERTIFICATE_file) and uses it to load the existing file system.
 * It sets up the AES cipher for encryption/decryption operations. The file system is loaded in "load" mode,
 * which is used during normal startup.
 *
 * @param KEK_CERTIFICATE_file Path to the key file containing the AES 256-bit key. It should not be NULL.
 *
 * @return Returns one of the following status codes:
 * - CORRECT_FILESYSTEM_INIT: File system initialized successfully.
 * - INIT_INCORRECT_KEYFILE_PATH: Invalid key file path or the file cannot be opened.
 * - INIT_INCORRECT_KEYFILE_FORMAT: The key file is too short and does not contain enough data.
 * - INIT_INCORRECT_KEYFILE_READ: An error occurred while reading the key file.
 * - INIT_INCORRECT_FILESYSTEM_INIT: The file system could not be initialized.
 */

int File_system_normal_initialization(unsigned char *KEK_CERTIFICATE_file, unsigned char *Cryptodata_filename);

/**
 * @brief Performs the normal initialization of the file system.
 *
 * This function initializes the file system by:
 * 1. Checking if the provided KEK certificate file path is valid.
 * 2. Attempting to open the KEK certificate file in binary read mode.
 * 3. Reading the AES-256 key from the file.
 * 4. Initializing the file system in 'load' mode.
 * 5. Setting up AES encryption with the loaded key.
 * 6. Zeroing out the memory space used for the key.
 *
 * @param KEK_CERTIFICATE_file A pointer to the KEK certificate file.
 * @param Cryptodata_filename A pointer to the cryptodata file.
 * @return Returns CORRECT_FILESYSTEM_INIT if initialization is successful,
 *         otherwise returns an error code.
 */

int API_INIT_initialize_module(unsigned char *KEK_CERTIFICATE_file, unsigned char *Cryptodata_filename);

#endif // MODULE_INITIALIZATION_H