/**
 * @file Error_Manager.c
 * @brief File containing the implementation of the Error manager
 */

#include "Error_Manager.h"

pthread_mutex_t error_counter_mutex = PTHREAD_MUTEX_INITIALIZER;
int error_counter;
static uint8_t keep_normal_function = 1;

// Function executed in a separate thread, reduces the counter every 10 minutes
void* reduce_error_counter(void* arg) {
    while (1) {
        sleep(REDUCTION_INTERVAL); // Wait for 10 minutes
        pthread_mutex_lock(&error_counter_mutex);
        if (error_counter > 0) {
            if(keep_normal_function)
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
    char str[32] = {0};
    if(API_SM_get_current_state() == STATE_ERROR){
        API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);
        pthread_mutex_unlock(&error_counter_mutex);
        return;
    }

    if(keep_normal_function){
        error_counter += increment_value;
    }
    snprintf(str,32,"%d",increment_value);

    API_LT_traceWrite("Incorrect operation, incrementing error counter in:",str,NULL);
    // Check if error counter exceeds the maximum allowed value
    if (error_counter > MAX_ERRORS_SOFT) {
        API_LT_traceWrite("Maximum error umbral reached","proceeding to SOFT_error_state",NULL);
        API_SM_State_Change(STATE_SOFTERROR);
        API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);
    }
    if (error_counter > MAX_ERRORS_HARD) {
        keep_normal_function = 0;
        API_LT_traceWrite("Maximum error umbral reached","proceeding to HARD_error_state",NULL);
        API_SM_State_Change(STATE_ERROR);
        API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);
        API_EM_zeroize_entire_module();
    }
    pthread_mutex_unlock(&error_counter_mutex);
}


void API_EM_zeroize_entire_module() {
    /** <setup previus error state in filesystem */
    uint8_t previus_state = 2;
    int result = API_FS_update_file_data(CONF_FILENAME,strlen(CONF_FILENAME),&previus_state,sizeof(u_int8_t));

    API_MT_zeroize_and_free_all();   /**< Zeroize and free all memory tracked by the memory tracker. */
    API_MM_Zeroize_root();           /**< Zeroize the entire memory management tree. */
    API_FS_zeroize_file_system();    /**< Zeroize and wipe the file system. */
}


const char* API_EM_get_error_message(int error_code) {
    static char* error_messages[] = {
        [FS_ERROR + 2010] = "File system error",
        [FS_NO_FILESYSTEM_FILES + 2010] = "Not existing filesystem file",
        [FS_INCORRECT_MODE + 2010] = "Incorrect cipher mode specified",
        [FS_NOT_EXISTANT_FILENAME + 2010] = "Filename does not exist",
        [FS_MAX_FILENAMES_REACHED + 2010] = "Max filenames reached",
        [FS_INCORRECT_ARGUMENT_ERROR + 2010] = "Incorrect arguments",
        [FS_FILENAME_ALREADYEXIST_ERROR + 2010] = "Error creating filename,already exists",
        [FS_MAX_SIZE_REACHED + 2010] = "Max filesystem size reached",
        [FS_CORRUPTED_DATA + 2010] = "Filesystem data corruption detected",
        [MT_FAIL + 2010] = "Memory tracker failure",
        [MT_NO_MORE_TRACKERS + 2010] = "No more trackers",
        [MT_MEMORYVIOLATION_BEFORE_DELETE + 2010] = "Memory violation before delete",
        [MT_MEMORYVIOLATION + 2010] = "Memory tracker violation detected",
        [MT_MEMORY_LOCK_FAIL + 2010] = "Memory lock failure",
        [MM_ERROR_NULL_POINTER + 2010] = "Null pointer error",
        [MM_MEMORY_ALLOCATION_FAILED + 2010] = "Memory allocation failed",
        [MM_ERROR_HASH_COLLISION + 2010] = "Hash collision detected",
        [MM_MEMORY_DEALLOCATION_FAILED + 2010] = "Memory deallocation failed",
        [KM_PARAMETERS_ERROR + 2010] = "Incorrect key parameters!",
        [KM_KEY_NOT_LOADED + 2010] = "No Key loaded in RAM at the moment!",
        [RNG_RANDOM_GENERATION_FAILED + 2010] = "Random generation failed",
        [LT_TRACER_ERROR + 2010] = "Tracer error",
        [SFT_SELFTEST_FAILED + 2010] = "Self-testS FAILED",
        [SFT_SHA256_SELFTEST_FAILED + 2010] = "SHA256 Self-test FAILED",
        [SFT_HMAC_SHA256_SELFTEST_FAILED + 2010] = "HMAC-SHA256 Self-test FAILED",
        [SFT_ECDSAP256_SELFTEST_FAILED + 2010] = "ECDSAP256 Self-test FAILED",
        [SFT_AES256_CBC_SELFTEST_FAILED + 2010] = "AES256CBC Self-test FAILED",
        [SFT_MODULE_INTEGRITY_SELFTEST_FAILED + 2010] = "MODULE INTEGRITY Self-test FAILED",
        [INIT_INCORRECT_TRACKER_INIT + 2010] = "Incorrect tracker initialization",
        [INIT_INCORRECT_KEYFILE_PATH + 2010] = "Incorrect keyfile path",
        [INIT_INCORRECT_KEYFILE_FORMAT + 2010] = "Incorrect keyfile format",
        [INIT_INCORRECT_KEYFILE_READ + 2010] = "Incorrect keyfile read",
        [INIT_INCORRECT_FILESYSTEM_INIT + 2010] = "Incorrect filesystem initialization",
        [INIT_PREVIUS_ERROR_STATE + 2010] = "Previus Error state detected, module already zeroized",
        [INIT_TRACER_INIT_ERROR + 2010] = "Tracer initialization error",
        [SM_ERROR + 2010] = "Hard error occurred",
        [SM_SOFTERROR + 2010] = "Soft error occurred",
        [SM_ERROR_STATE + 2010] = "Cannot perform this operation in current state",
        [EM_THREAD_ERROR + 2010] = "Thread error in error manager",
        [MC_INITIALIZATION_ERROR + 2010] = "Initialization error",
        [MC_PACKET_INTEGRITY_COMPROMISED + 2010] = "Packet not authenticated integrity compromised!",
    };

    // Return the corresponding error message
    return (error_code >= -2010 && error_code < 0) ? error_messages[error_code + 2010] : "Unknown error code";
}

