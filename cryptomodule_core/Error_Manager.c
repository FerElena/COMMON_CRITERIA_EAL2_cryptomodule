#include "Error_Manager.h"

pthread_mutex_t error_counter_mutex = PTHREAD_MUTEX_INITIALIZER;
int error_counter = 0;

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
        State_Change(STATE_CHANGE_SOFTERROR);
    }
    pthread_mutex_unlock(&error_counter_mutex);
}
