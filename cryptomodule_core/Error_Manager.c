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
    if(API_SM_get_current_state() != STATE_INITIALIZATION){
        return SM_ERROR_STATE;
    }
    error_counter = 0;
    pthread_t reduction_thread;

    // Start the thread that reduces the counter every 10 minutes
    if (pthread_create(&reduction_thread, NULL, reduce_error_counter, NULL) != 0) {
        return EM_THREAD_ERROR; // Error code
    }

    // Detach the thread so we don't need to join later
    if (pthread_detach(reduction_thread) != 0) {
        return EM_THREAD_ERROR; // Error code
    }

    return Errormanager_OK; // Success
}

// Function to increment the error counter from another thread or context
void API_EM_increment_error_counter(int increment_value) {
    pthread_mutex_lock(&error_counter_mutex);
    error_counter += increment_value;

    // Check if error counter exceeds the maximum allowed value
    if (error_counter > MAX_ERRORS) {
        API_SM_State_Change(SM_SOFTERROR);
    }
    pthread_mutex_unlock(&error_counter_mutex);
}



const char* API_EM_get_error_message(int error_code) {
    static char* error_messages[] = {
        [FS_ERROR + 2000] = "File system error",
        [FS_NO_FILESYSTEM_FILES + 2000] = "Not existing filesystem file",
        [FS_INCORRECT_MODE + 2000] = "Incorrect cipher mode specified",
        [FS_NOT_EXISTANT_FILENAME + 2000] = "Filename does not exist",
        [FS_MAX_FILENAMES_REACHED + 2000] = "Max filenames reached",
        [FS_INCORRECT_ARGUMENT_ERROR + 2000] = "Incorrect arguments",
        [FS_FILENAME_ALREADYEXIST_ERROR + 2000] = "Error creating filename,already exists",
        [FS_MAX_SIZE_REACHED + 2000] = "Max filesystem size reached",
        [FS_CORRUPTED_DATA + 2000] = "Filesystem data corruption detected",
        [MT_FAIL + 2000] = "Memory tracker failure",
        [MT_NO_MORE_TRACKERS + 2000] = "No more trackers",
        [MT_MEMORYVIOLATION_BEFORE_DELETE + 2000] = "Memory violation before delete",
        [MT_MEMORYVIOLATION + 2000] = "Memory tracker violation detected",
        [MT_MEMORY_LOCK_FAIL + 2000] = "Memory lock failure",
        [MM_ERROR_NULL_POINTER + 2000] = "Null pointer error",
        [MM_MEMORY_ALLOCATION_FAILED + 2000] = "Memory allocation failed",
        [MM_ERROR_HASH_COLLISION + 2000] = "Hash collision detected",
        [MM_MEMORY_DEALLOCATION_FAILED + 2000] = "Memory deallocation failed",
        [KM_PARAMETERS_ERROR + 2000] = "Incorrect key parameters!",
        [RNG_RANDOM_GENERATION_FAILED + 2000] = "Random generation failed",
        [LT_TRACER_ERROR + 2000] = "Tracer error",
        [SFT_SELFTEST_FAILED + 2000] = "Self-testS FAILED",
        [SFT_SHA256_SELFTEST_FAILED + 2000] = "SHA256 Self-test FAILED",
        [SFT_HMAC_SHA256_SELFTEST_FAILED + 2000] = "HMAC-SHA256 Self-test FAILED",
        [SFT_ECDSAP256_SELFTEST_FAILED + 2000] = "ECDSAP256 Self-test FAILED",
        [SFT_AES256_CBC_SELFTEST_FAILED + 2000] = "AES256CBC Self-test FAILED",
        [SFT_MODULE_INTEGRITY_SELFTEST_FAILED + 2000] = "MODULE INTEGRITY Self-test FAILED",
        [INIT_INCORRECT_TRACKER_INIT + 2000] = "Incorrect tracker initialization",
        [INIT_INCORRECT_KEYFILE_PATH + 2000] = "Incorrect keyfile path",
        [INIT_INCORRECT_KEYFILE_FORMAT + 2000] = "Incorrect keyfile format",
        [INIT_INCORRECT_KEYFILE_READ + 2000] = "Incorrect keyfile read",
        [INIT_INCORRECT_FILESYSTEM_INIT + 2000] = "Incorrect filesystem initialization",
        [INIT_TRACER_INIT_ERROR + 2000] = "Tracer initialization error",
        [SM_ERROR + 2000] = "Hard error occurred",
        [SM_SOFTERROR + 2000] = "Soft error occurred",
        [SM_ERROR_STATE + 2000] = "Cannot perform this operation in current state",
        [EM_THREAD_ERROR + 2000] = "Thread error in error manager",
        [MC_INITIALIZATION_ERROR + 2000] = "Initialization error",
    };

    // Return the corresponding error message
    return (error_code >= -2000 && error_code < 0) ? error_messages[error_code + 2000] : "Unknown error code";
}

