#ifndef API_CORE_H
#define API_CORE_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "module_initialization.h"
#include "Error_Manager.h"
#include "packet_cipher_auth.h"
#include "Key_management.h"
#include "../state_machine/State_Machine.h"
#include "../library_tracer/log_manager.h"
#include "../crypto-selftests/selftests.h"
#include "../prng/random_number.h"

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

#define INITIALIZATION_OK 2000
#define KEY_OPERATION_OK 2001
#define CIPHER_AUTH_OPERATION_OK 2002
#define DECIPHER_AUTH_OPERATION_OK 2003

#define MC_INITIALIZATION_ERROR -2000
#define MC_PACKET_INTEGRITY_COMPROMISED -2001

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief returns current cryptomodule state
 * 
 * @return int returns current_state
 */

int API_MC_getcurrent_state();

/**
 * @brief Initializes the cryptographic module, setting up various subsystems and performing self-tests.
 * 
 * This function handles the initialization of the cryptomodule, including the memory tracker, 
 * filesystem, library tracer, and error manager. It also runs self-tests to ensure that the 
 * cryptographic module is operating correctly.
 *
 * @param[in] KEK_CERTIFICATE_file  Pointer to the key encryption key (KEK) certificate file.
 * @param[in] Cryptodata_filename   Pointer to the cryptographic data file.
 * 
 * @return int Returns `INITIALIZATION_OK` if the initialization is successful. 
 *             Returns `MC_INITIALIZATION_ERROR` if an error occurs during initialization.
 * 
 * The function follows these main steps:
 * - Changes the system state to `STATE_INITIALIZATION`.
 * - Calls `API_INIT_initialize_module` to initialize the filesystem and memory tracker.
 * - Depending on the initialization result, traces are written to indicate whether this is 
 *   the first initialization or a normal one.
 * - Initializes the error manager and sets the error counter to 0.
 * - Runs self-tests to ensure all components of the module are functioning correctly.
 * - If all tests pass, the system state changes to `STATE_OPERATIONAL`.
 * 
 * If an error occurs during any phase of initialization, the function logs the error message 
 * and returns an error code.
 * 
 * @note This function should be called during the system's initialization phase to set up
 * the cryptographic module.
 */

int API_MC_Initialize_module(unsigned char *KEK_CERTIFICATE_file,unsigned char *Cryptodata_filename);

/**
 * @brief Inserts a cryptographic key into the key management system.
 * 
 * This function ensures the system is in an operational state, switches to
 * cryptographic service provider (CSP) mode, and attempts to store the provided key.
 * It handles errors by logging the issue and incrementing the error counter. Upon
 * success or failure, it switches the system state back to operational.
 * 
 * @param[in] In_Key       The 32-byte cryptographic key to be inserted.
 * @param[in] key_size     The size of the key in bytes. Typically 32 bytes for AES-256.
 * @param[in] Key_id       The identifier for the key, used to reference it in future operations.
 * @param[in] Key_id_length The length of the key identifier in bytes.
 * 
 * @return int             Returns `KEY_OPERATION_OK` on success, or an error code 
 *                         (e.g., `SM_ERROR_STATE` or a key management error code) if the operation fails.
 * 
 * @pre The system must be in the `STATE_OPERATIONAL` state for this function to execute.
 * @post If successful, the key is stored and the system state is reverted to `STATE_OPERATIONAL`.
 * 
 * @note This function changes the system state to `STATE_CSP` during execution and logs the process.
 */
int API_MC_Insert_Key(uint8_t In_Key[32], size_t key_size, unsigned char *Key_id, size_t Key_id_length);

/**
 * @brief Loads a cryptographic key from the key management system into memory.
 * 
 * This function verifies that the system is in an operational state, switches to CSP mode, 
 * and attempts to load the key identified by `Key_id` from storage into RAM. It logs the result 
 * and manages errors by incrementing the error counter and restoring the system state to operational.
 * 
 * @param[in] Key_id       The identifier of the key to load.
 * @param[in] Key_id_length The length of the key identifier in bytes.
 * 
 * @return int             Returns `KEY_OPERATION_OK` on success, or an error code if the operation fails.
 * 
 * @pre The system must be in the `STATE_OPERATIONAL` state before this function is called.
 * @post On success, the key is loaded into RAM and the system state is reverted to `STATE_OPERATIONAL`.
 * 
 * @note This function logs both successful and failed key loading attempts and switches to `STATE_CSP` during execution.
 */
int API_MC_Load_Key(unsigned char *Key_id, size_t Key_id_length);

/**
 * @brief Deletes a cryptographic key from the key management system.
 * 
 * This function ensures that the system is in an operational state, switches to CSP mode, 
 * and attempts to delete the key identified by `Key_id` from both the filesystem and RAM. 
 * Errors are logged, and the system state is reverted to operational afterward.
 * 
 * @param[in] Key_id       The identifier of the key to delete.
 * @param[in] Key_id_length The length of the key identifier in bytes.
 * 
 * @return int             Returns `KEY_OPERATION_OK` on success, or an error code if the operation fails.
 * 
 * @pre The system must be in the `STATE_OPERATIONAL` state before this function is invoked.
 * @post If successful, the key is removed from both the filesystem and RAM, and the system state is restored to `STATE_OPERATIONAL`.
 * 
 * @note The system switches to `STATE_CSP` during execution and logs key deletion activities.
 */
int API_MC_Delete_Key(unsigned char *Key_id, size_t Key_id_length);

/**
 * @brief wrapper of RNG for API CORE.Fills a buffer with random bytes with 4MB of max size, attempting to use secure sources.
 *
 * This function first tries to fill the buffer using `/dev/random`. If that fails,
 * it attempts to use `/dev/urandom` as a fallback. If both of these fail, it will
 * generate pseudo-random bytes using `rand()` as a last resort, though this is less secure.
 *
 * @param buffer Pointer to the buffer that will be filled with random bytes.
 * @param size Size of the buffer, i.e., the number of random bytes to generate.
 *
 * @return int Returns `RANDOM_OK` if `/dev/random` was successfully used.
 * Returns `PSEUDORANDOM_OK` if `/dev/urandom` was used instead.
 * Returns `RNG_RANDOM_GENERATION_FAILED` if neither secure source was available
 * and pseudo-random data was generated.
 */

int API_MC_fill_buffer_random(unsigned char *buffer, size_t size);

/**
 * @brief Signs and encrypts a data packet.
 *
 * This function performs a secure signing and encryption operation on the input data.
 * It checks the system's operational state and loaded key integrity before processing. If the
 * system is not in the correct state or the key is not loaded, appropriate error codes
 * are returned. The resulting signed and encrypted data is stored in `packet_out`, and
 * the length of the data is stored in `packet_out_length`.
 *
 * @warning The memory pointed to by `unsigned char *packet_out` must be at least 72 bytes 
 * larger than the input data size (`data_size`). Failure to allocate enough memory will result 
 * in undefined behavior.
 *
 * @param[in]  data_in           Pointer to the input data to be signed and encrypted.
 * @param[in]  data_size         Size of the input data in bytes.
 * @param[out] packet_out        Pointer to the output buffer where the signed and encrypted
 *                               packet will be stored. **Must be at least 72 bytes larger than 
 *                               `data_size`.**
 * @param[out] packet_out_length Pointer to store the length of the output data after encryption 
 *                               and signing.
 *
 * @return int 
 *         - CIPHER_AUTH_OPERATION_OK on success.
 *         - SM_ERROR_STATE if the system is not in an operational state.
 *         - KM_KEY_NOT_LOADED if the cryptographic key is not loaded.
 *         - Various other error codes depending on the result of the key integrity check.
 */

int API_MC_Sing_Cipher_Packet(unsigned char *data_in, size_t data_size, unsigned char *packet_out, size_t *packet_out_length);

/**
 * @brief Decrypts and authenticates an encrypted data packet.
 *
 * This function decrypts an input data packet and verifies its authenticity. 
 * It checks whether the system is in an operational state and validates the integrity of the key in use.
 * If the system is not operational or the key is not loaded, the function returns appropriate error codes.
 * After successful decryption and authentication, the resulting data is stored in `out_data`, 
 * and the length of the data is stored in `out_data_length`.
 *
 * @warning The `out_data` buffer must have sufficient space to store the decrypted data. 
 *          Ensure that `out_data_length` points to a valid variable to capture the output size.
 *
 * @param[in]  data_in           Pointer to the encrypted input data to be decrypted and authenticated.
 * @param[in]  data_in_length    Size of the input data in bytes.
 * @param[out] out_data          Pointer to the buffer where the decrypted data will be stored.
 * @param[out] out_data_length   Pointer to store the length of the decrypted data.
 *
 * @return int 
 *         - DECIPHER_AUTH_OPERATION_OK on success.
 *         - SM_ERROR_STATE if the system is not in an operational state.
 *         - KM_KEY_NOT_LOADED if the cryptographic key is not loaded.
 *         - KM_PARAMETERS_ERROR if the input parameters are invalid (null).
 *         - MC_PACKET_INTEGRITY_COMPROMISED if the packet's authenticity check fails.
 *         - Other error codes depending on the result of the key integrity check.
 */


int API_MC_Decipher_Auth_Packet(unsigned char *data_in, size_t data_in_length,unsigned char *out_data, size_t *out_data_length);


/**
 * @brief Shuts down the cryptographic module.
 *
 * This function checks the current state of the system to ensure it is either operational
 * or in a soft error state before proceeding with the shutdown sequence. If the state is
 * incorrect, it logs the state, increments the error counter, and returns an error code.
 *
 * @return int Returns SM_ERROR_STATE if the current state is not valid. Returns 0 if the
 * shutdown process is successful.
 */

int API_MC_Shutdown_module();

#endif