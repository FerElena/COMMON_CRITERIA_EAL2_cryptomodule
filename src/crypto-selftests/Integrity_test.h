/**
 * @file Integrity_test.h
 * @brief File containing all the function headers of the integrity test.
 */

#ifndef INTEGRITY_TEST_H
#define INTEGRITY_TEST_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "../secure_memory_management/DmemManager.h"
#include "../cryptomodule_core/module_initialization.h"
#include "../crypto/ECDSA_256.h"
#include "../crypto/SHA256.h"

#define INTEGRITY_OK 1
#define INTEGRITY_ERROR 0

/**
 * @brief Loads the binary of the currently running program into a buffer.
 *
 * This function uses the `/proc/self/exe` path to access the binary of the currently 
 * running program and loads its content into a buffer of up to 4MB.
 *
 * @param[out] buffer Pointer to the memory where the binary content will be stored. 
 *                    This memory is allocated inside the function and must be freed by the caller.
 * @param[out] buffer_size Size of the data read into the buffer.
 * @return int Returns 0 on success, or -1 on error (e.g., if the file could not be opened or memory allocation failed).
 *
 * Example usage:
 * @code
 * unsigned char *buffer;
 * size_t buffer_size;
 * if (load_self_binary_to_buffer(&buffer, &buffer_size) == 0) {
 *     // Successfully loaded the binary, use buffer here
 *     free(buffer); // Don't forget to free the buffer after use
 * }
 * @endcode
 */

int load_self_binary_to_buffer(unsigned char **buffer, size_t *buffer_size);

/**
 * @brief Verifies the integrity of the current module by comparing its hash with a signed public key.
 * 
 * This function loads the current module's binary into memory, computes its SHA-256 hash, and verifies the signature 
 * using an ECDSA public key and a sign stored previusly in the filesystem.
 * 
 * @return int Returns INTEGRITY_OK if the module passes the integrity check, otherwise returns INTEGRITY_ERROR.
 */

int API_SFT_check_module_integrity();

#endif