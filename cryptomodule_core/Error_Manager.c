#include "Error_Manager.h"

pthread_mutex_t error_counter_mutex = PTHREAD_MUTEX_INITIALIZER;
int error_counter;

// Function executed in a separate thread, reduces the counter every 10 minutes
void* reduce_error_counter(void* arg) {
    while (1) {
        sleep(REDUCTION_INTERVAL); // Wait for 10 minutes
        pthread_mutex_lock(&error_counter_mutex);
        if (error_counter > 0) {
            error_counter--;
        }
        pthread_mutex_unlock(&error_counter_mutex);
    }
    return NULL;
}

// Function to initialize the error counter and the reduction thread
int API_EM_init_error_counter() {
    error_counter = 0;
    pthread_t reduction_thread;

    // Start the thread that reduces the counter every 10 minutes
    if (pthread_create(&reduction_thread, NULL, reduce_error_counter, NULL) != 0) {
        return Errormanager_thread_error; // Error code
    }

    // Detach the thread so we don't need to join later
    if (pthread_detach(reduction_thread) != 0) {
        return Errormanager_thread_error; // Error code
    }

    return Errormanager_OK; // Success
}

// Function to increment the error counter from another thread or context
void API_EM_increment_error_counter(int increment_value) {
    pthread_mutex_lock(&error_counter_mutex);
    error_counter += increment_value;

    // Check if error counter exceeds the maximum allowed value
    if (error_counter > MAX_ERRORS) {
        API_SM_State_Change(STATE_CHANGE_SOFTERROR);
    }
    pthread_mutex_unlock(&error_counter_mutex);
}



const char* API_EM_get_error_message(int error_code) {
    static char* error_messages[] = {
        [FILESYSTEM_ERROR + 2000] = "File system error",
        [NO_FILESYSTEM_FILES + 2000] = "Not existing filesystem file",
        [INCORRECT_MODE + 2000] = "Incorrect cipher mode specified",
        [NOT_EXISTANT_FILENAME + 2000] = "Filename does not exist",
        [MAX_FILENAMES_REACHED + 2000] = "Max filenames reached",
        [INCORRECT_ARGUMENT_ERROR + 2000] = "Incorrect arguments",
        [FILENAME_ALREADYEXIST_ERROR + 2000] = "Error creating filename,already exists",
        [MAX_SIZE_REACHED + 2000] = "Max filesystem size reached",
        [CORRUPTED_DATA + 2000] = "Filesystem data corruption detected",
        [MT_FAIL + 2000] = "Memory tracker failure",
        [NO_MORE_TRACKERS + 2000] = "No more trackers",
        [MEMORYVIOLATION_BEFORE_DELETE + 2000] = "Memory violation before delete",
        [MEMORYVIOLATION + 2000] = "Memory tracker violation detected",
        [MEMORY_LOCK_FAIL + 2000] = "Memory lock failure",
        [ERROR_NULL_POINTER + 2000] = "Null pointer error",
        [ERROR_MEMORY_ALLOCATION_FAILED + 2000] = "Memory allocation failed",
        [ERROR_HASH_COLLISION + 2000] = "Hash collision detected",
        [ERROR_MEMORY_DEALLOCATION_FAILED + 2000] = "Memory deallocation failed",
        [ERROR_RANDOM_GENERATION_FAILED + 2000] = "Random generation failed",
        [TRACER_ERROR + 2000] = "Tracer error",
        [SELFTEST_FAILED + 2000] = "Self-testS FAILED",
        [SHA256_SELFTEST_FAILED + 2000] = "SHA256 Self-test FAILED",
        [HMAC_SHA256_SELFTEST_FAILED + 2000] = "HMAC-SHA256 Self-test FAILED",
        [ECDSAP256_SELFTEST_FAILED + 2000] = "ECDSAP256 Self-test FAILED",
        [AES256_CBC_SELFTEST_FAILED + 2000] = "AES256CBC Self-test FAILED",
        [MODULE_INTEGRITY_SELFTEST_FAILED + 2000] = "MODULE INTEGRITY Self-test FAILED",
        [INCORRECT_TRACKER_INIT + 2000] = "Incorrect tracker initialization",
        [INCORRECT_KEYFILE_PATH + 2000] = "Incorrect keyfile path",
        [INCORRECT_KEYFILE_FORMAT + 2000] = "Incorrect keyfile format",
        [INCORRECT_KEYFILE_READ + 2000] = "Incorrect keyfile read",
        [INCORRECT_FILESYSTEM_INIT + 2000] = "Incorrect filesystem initialization",
        [TRACER_INIT_ERROR + 2000] = "Tracer initialization error",
        [STATE_CHANGE_ERROR + 2000] = "Hard error occurred",
        [STATE_CHANGE_SOFTERROR + 2000] = "Soft error occurred",
        [STATE_INCORRECTSTATE_ERROR + 2000] = "Cannot perform this operation in current state",
        [Errormanager_thread_error + 2000] = "Thread error in error manager",
        [INITIALIZATION_ERROR + 2000] = "Initialization error",
    };

    // Return the corresponding error message
    return (error_code >= -2000 && error_code < 0) ? error_messages[error_code + 2000] : "Unknown error code";
}

