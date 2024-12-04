/**
 * @file key_derivation_function.h
 * @brief File containing the implementation of the KDF.
 */

#include "key_derivation_function.h"

// A buffer used for intermediate data in the key derivation process
unsigned char kdf_buffer[64];  // The buffer must be large enough to hold the concatenation of the input key and constants

// Two predefined random constants, each of 32 bytes (256 bits)
const unsigned char constant1[HASH_SIZE] = {
    0x1f, 0xa6, 0xd3, 0xc2, 0x87, 0x49, 0x32, 0xff, 0x2a, 0xe1, 0xbd, 0x56, 0x71, 0x9c, 0x11, 0x89,
    0xb8, 0x4e, 0x6f, 0x23, 0xcd, 0x15, 0xe2, 0x79, 0x5d, 0xc3, 0xab, 0xf4, 0x9d, 0x12, 0x60, 0xb2
};

const unsigned char constant2[HASH_SIZE] = {
    0xf8, 0x32, 0x1b, 0xa4, 0x45, 0xcd, 0xee, 0x91, 0x7b, 0x08, 0x3f, 0x72, 0x6c, 0xd9, 0x4a, 0x12,
    0xaa, 0x23, 0x39, 0x94, 0xd2, 0x4f, 0xc8, 0x81, 0x6e, 0x5b, 0x90, 0xef, 0x37, 0x63, 0xd1, 0x7f
};

void API_KDF_derive_complex_key(uint8_t input_key[32], uint8_t derived_key_cipher[32], uint8_t derived_key_auth[32]) {
    
    // Step 1: Derive cipher key by concatenating input_key and constant1, then applying SHA-256
    memcpy(kdf_buffer, input_key, HASH_SIZE);       
    memcpy(kdf_buffer + HASH_SIZE, constant1, HASH_SIZE);  
    API_sha256(kdf_buffer, HASH_SIZE * 2, derived_key_cipher);  // Hash the concatenation to produce the cipher key (32 bytes)

    // Step 2: Derive authentication key by concatenating input_key and constant2, then applying SHA-256
    memcpy(kdf_buffer, input_key, HASH_SIZE);        
    memcpy(kdf_buffer + HASH_SIZE, constant2, HASH_SIZE);  
    API_sha256(kdf_buffer, HASH_SIZE * 2, derived_key_auth);  // Hash the concatenation to produce the auth key (32 bytes)
}