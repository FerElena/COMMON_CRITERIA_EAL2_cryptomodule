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
#include "../state_machine/State_Machine.h"
#include "../library_tracer/log_manager.h"
#include "../crypto-selftests/selftests.h"

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

#define INITIALIZATION_OK 2000
#define MC_INITIALIZATION_ERROR -2000

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

#endif