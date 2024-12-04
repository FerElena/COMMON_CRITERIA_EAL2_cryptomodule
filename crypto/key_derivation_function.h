/**
 * @file CRC_Galileo.h
 * @brief File containing all the function headers of the KDF.
 */

#ifndef KEY_DERIVATION_FUNCTION_H
#define KEY_DERIVATION_FUNCTION_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdlib.h>
#include <string.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "SHA256.h"
#include "crypto.h"

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * Derive two keys from an input key using predefined constants.
 * 
 * @param input_key: The original key or master key input (32 bytes).
 * @param derived_key_cipher: A pointer to store the derived key used for encryption (32 bytes).
 * @param derived_key_auth: A pointer to store the derived key used for authentication (32 bytes).
 */

void API_KDF_derive_complex_key(uint8_t input_key[32], uint8_t derived_key_cipher[32], uint8_t derived_key_auth[32]) ;

#endif