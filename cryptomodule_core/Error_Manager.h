#ifndef ERROR_MANAGER_H
#define ERROR_MANAGER_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "../state_machine/State_Machine.h"
#include "../library_tracer/log_manager.h"
#include "../secure_memory_management/DmemManager.h"
#include "../secure_memory_management/file_system.h"
#include "../secure_memory_management/MemoryTracker.h"
#include "module_initialization.h"

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

#define REDUCTION_INTERVAL 60       // 60 seconds (1 minute)
#define MAX_ERRORS_SOFT 50          // Maximum SOFT error threshold
#define MAX_ERRORS_HARD 100         // Maximum HARD error threshhold

#define Errormanager_OK 1900


#define FS_ERROR -1000
#define FS_NO_FILESYSTEM_FILES -1001
#define FS_INCORRECT_MODE -1002
#define FS_NOT_EXISTANT_FILENAME -1003
#define FS_MAX_FILENAMES_REACHED -1004
#define FS_INCORRECT_ARGUMENT_ERROR -1005
#define FS_FILENAME_ALREADYEXIST_ERROR -1006
#define FS_MAX_SIZE_REACHED -1007
#define FS_CORRUPTED_DATA -1008
#define MT_FAIL -1100
#define MT_NO_MORE_TRACKERS -1102
#define MT_MEMORYVIOLATION_BEFORE_DELETE -1103
#define MT_MEMORYVIOLATION -1104
#define MT_MEMORY_LOCK_FAIL -1105
#define MM_ERROR_NULL_POINTER -1201
#define MM_MEMORY_ALLOCATION_FAILED -1202
#define MM_ERROR_HASH_COLLISION -1203
#define MM_MEMORY_DEALLOCATION_FAILED -1204
#define KM_PARAMETERS_ERROR -1300
#define KM_KEY_NOT_LOADED -1301
#define RNG_RANDOM_GENERATION_FAILED -1401
#define LT_TRACER_ERROR -1500
#define SFT_SELFTEST_FAILED -1600
#define SFT_SHA256_SELFTEST_FAILED -1601
#define SFT_HMAC_SHA256_SELFTEST_FAILED -1602
#define SFT_ECDSAP256_SELFTEST_FAILED -1603
#define SFT_AES256_CBC_SELFTEST_FAILED -1604
#define SFT_MODULE_INTEGRITY_SELFTEST_FAILED -1605
#define INIT_INCORRECT_TRACKER_INIT -1700
#define INIT_INCORRECT_KEYFILE_PATH -1701
#define INIT_INCORRECT_KEYFILE_FORMAT -1702
#define INIT_INCORRECT_KEYFILE_READ -1703
#define INIT_INCORRECT_FILESYSTEM_INIT -1704
#define INIT_TRACER_INIT_ERROR -1705
#define INIT_PREVIUS_ERROR_STATE -1706
#define SM_ERROR -1800         // Hard error state
#define SM_SOFTERROR -1801      // Soft error state
#define SM_ERROR_STATE -1802
#define EM_THREAD_ERROR -1900
#define MC_INITIALIZATION_ERROR -2000
#define MC_PACKET_INTEGRITY_COMPROMISED -2001

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief Function that runs in a separate thread to reduce the error counter.
 * 
 * This function is executed in an infinite loop where it reduces the error counter by 1 
 * every 10 minutes (600 seconds) as long as the counter is greater than 0. The access to 
 * the error counter is synchronized using a mutex to prevent data races.
 * 
 * @param arg Unused argument (can be NULL).
 * @return NULL Always returns NULL after execution.
 */

void* reduce_error_counter(void* arg);

/**
 * @brief Initializes the error counter and starts the reduction thread.
 * 
 * This function starts a new thread that periodically (every 10 minutes) reduces the 
 * error counter. It also detaches the thread to ensure that its resources are cleaned 
 * up automatically when the thread terminates. The function returns an error code if 
 * thread creation or detachment fails.
 * 
 * @return int Returns `Errormanager_OK` if initialization is successful, 
 *             or `EM_THREAD_ERROR` if the thread fails to be created or detached.
 */

int API_EM_init_error_counter();

/**
 * @brief Increments the error counter by a specified value.
 * 
 * This function increments the error counter by a given value. If the error counter 
 * exceeds the `MAX_ERRORS_SOFT` threshold after the increment, it triggers a state change 
 * indicating a soft error. The function uses a mutex to ensure thread-safe access 
 * to the error counter.
 * 
 * @param increment_value The value to add to the error counter.
 */

void API_EM_increment_error_counter(int increment_value);

/**
 * @brief Securely zeroizes all systems within the module.
 *
 * This function triggers the complete zeroization process for the entire module, 
 * including memory tracking, the memory management tree, and the file system. 
 * It ensures that all sensitive data across these subsystems is securely wiped.
 */

void API_EM_zeroize_entire_module();

/**
 * @brief Get error message corresponding to the error code.
 * 
 * @param error_code The error code to retrieve the message for.
 * @return A pointer to a static string representing the error message.
 */

const char* API_EM_get_error_message(int error_code);

#endif