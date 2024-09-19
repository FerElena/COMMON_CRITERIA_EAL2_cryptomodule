#ifndef KEY_DERIVATION_FUNCTION_H
#define KEY_DERIVATION_FUNCTION_H

#include "SHA256.h"
#include "crypto.h"

/**
 * Derive two keys from an input key using predefined constants.
 * 
 * @param input_key: The original key or master key input (32 bytes).
 * @param derived_key_cipher: A pointer to store the derived key used for encryption (32 bytes).
 * @param derived_key_auth: A pointer to store the derived key used for authentication (32 bytes).
 */

void derive_complex_key(uint8_t input_key[32], uint8_t derived_key_cipher[32], uint8_t derived_key_auth[32]) ;

#endif