#ifndef ERROR_MANAGER_H
#define ERROR_MANAGER_H

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include "../state_machine/State_Machine.h"
#include "../library_tracer/log_manager.h"

#define REDUCTION_INTERVAL 600 // 600 seconds (10 minutes)
#define MAX_ERRORS 50          // Maximum error threshold

#define Errormanager_OK 1900


#define FILESYSTEM_ERROR -1000
#define NO_FILESYSTEM_FILES -1001
#define INCORRECT_MODE -1002
#define NOT_EXISTANT_FILENAME -1003
#define MAX_FILENAMES_REACHED -1004
#define INCORRECT_ARGUMENT_ERROR -1005
#define FILENAME_ALREADYEXIST_ERROR -1006
#define MAX_SIZE_REACHED -1007
#define CORRUPTED_DATA -1008
#define MT_FAIL -1100
#define NO_MORE_TRACKERS -1102
#define MEMORYVIOLATION_BEFORE_DELETE -1103
#define MEMORYVIOLATION -1104
#define MEMORY_LOCK_FAIL -1105
#define ERROR_NULL_POINTER -1201
#define ERROR_MEMORY_ALLOCATION_FAILED -1202
#define ERROR_HASH_COLLISION -1203
#define ERROR_MEMORY_DEALLOCATION_FAILED -1204
#define ERROR_RANDOM_GENERATION_FAILED -1401
#define TRACER_ERROR -1500
#define SELFTEST_FAILED -1600
#define SHA256_SELFTEST_FAILED -1601
#define HMAC_SHA256_SELFTEST_FAILED -1602
#define ECDSAP256_SELFTEST_FAILED -1603
#define AES256_CBC_SELFTEST_FAILED -1604
#define MODULE_INTEGRITY_SELFTEST_FAILED -1605
#define INCORRECT_TRACKER_INIT -1700
#define INCORRECT_KEYFILE_PATH -1701
#define INCORRECT_KEYFILE_FORMAT -1702
#define INCORRECT_KEYFILE_READ -1703
#define INCORRECT_FILESYSTEM_INIT -1704
#define TRACER_INIT_ERROR -1705
#define STATE_CHANGE_ERROR -1800         // Hard error state
#define STATE_CHANGE_SOFTERROR -1801      // Soft error state
#define STATE_INCORRECTSTATE_ERROR -1802
#define Errormanager_thread_error -1900
#define INITIALIZATION_ERROR -2000


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
 *             or `Errormanager_thread_error` if the thread fails to be created or detached.
 */

int API_EM_init_error_counter();

/**
 * @brief Increments the error counter by a specified value.
 * 
 * This function increments the error counter by a given value. If the error counter 
 * exceeds the `MAX_ERRORS` threshold after the increment, it triggers a state change 
 * indicating a soft error. The function uses a mutex to ensure thread-safe access 
 * to the error counter.
 * 
 * @param increment_value The value to add to the error counter.
 */

void API_EM_increment_error_counter(int increment_value);

/**
 * @brief Get error message corresponding to the error code.
 * 
 * @param error_code The error code to retrieve the message for.
 * @return A pointer to a static string representing the error message.
 */

const char* API_EM_get_error_message(int error_code);

#endif