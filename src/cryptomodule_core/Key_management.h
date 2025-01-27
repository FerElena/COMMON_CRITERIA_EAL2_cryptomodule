/**
 * @file Key_management.h
 * @brief File containing the Key_management functions headers
 */


#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/
#include "../state_machine/State_Machine.h"
#include "../secure_memory_management/file_system.h"
#include "../crypto/AES_CORE.h"
#include "../crypto/key_derivation_function.h"
#include "../secure_memory_management/MemoryTracker.h"
#include "module_initialization.h"
/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

#define KM_OK 1300

#define KM_PARAMETERS_ERROR -1300
#define KM_KEY_NOT_LOADED -1301


#define MAXLENGTH_KEYID 50

typedef struct current_key_in_use{
	uint8_t Main_key[32];
	uint8_t Cipher_key[32];
	uint8_t Auth_key[32];
	unsigned char keyname[MAX_FILENAME_LENGTH];
	uint8_t IsLoaded;
}current_key_in_use;

extern current_key_in_use Current_key_in_use;

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief Stores a cryptographic key securely in the file system.
 *
 * This function stores a key in the file system if the current state is `STATE_CSP`. The key and its ID
 * must be valid, and the function constructs a file name using a prefix and the provided Key ID.
 * 
 * @param In_Key Pointer to the input key (32 bytes expected).
 * @param key_size Size of the key in bytes (should be <= 32 bytes for AES-256).
 * @param Key_id Pointer to the key identifier.
 * @param Key_id_length Length of the key identifier.
 * 
 * @return `KM_OK` on success, error code otherwise.
 */

int API_KM_storekey(uint8_t In_Key[32], size_t key_size, unsigned char *Key_id, size_t Key_id_length);

/**
 * @brief Loads a cryptographic key from the file system using the provided Key ID.
 *
 * This function retrieves a key from the file system based on a given Key ID. The key is loaded
 * into the current key structure and used for further cryptographic operations. It also updates
 * the memory tracker for the current key.
 *
 * @param Key_id Pointer to the key identifier.
 * @param Key_id_length Length of the key identifier.
 * 
 * @return `KM_OK` on success, error code otherwise.
 */

int API_KM_loadkey(unsigned char *Key_id, size_t Key_id_length);

/**
 * @brief Deletes a cryptographic key from the file system using the provided Key ID.
 *
 * This function securely deletes a key from the file system based on the given Key ID. The key is identified
 * by its name, which is constructed with a "KEY_" prefix followed by the provided Key ID. It ensures that the 
 * operation is performed in the correct state (`STATE_CSP`).
 * 
 * @param Key_id Pointer to the key identifier.
 * @param Key_id_length Length of the key identifier.
 * 
 * @return `KM_OK` on success, error code otherwise.
 */

int API_KM_delete_key(unsigned char *Key_id, size_t Key_id_length);
#endif