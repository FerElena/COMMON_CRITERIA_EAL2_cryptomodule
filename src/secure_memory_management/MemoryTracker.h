/**
 * @file MemoryTracker.h
 * @brief Memory tracking system for secure allocation and deallocation of memory.!!TRACKED MEMORY MUST BE STATIC/DYNAMIC MEMORY OR SEGFAULTS WILL OCCUR¡¡¡¡¡¡
 *
 * This file provides the declarations and functionality for tracking static/dynamic memory allocations, 
 * verifying memory integrity, and securely deallocating memory blocks that contain Critical Security Parameters (CSP).
 * It also includes secure zeroization techniques to prevent sensitive data recovery.
 * 
 * @warning ONLY STATIC / HEAP ZONE MEMORY CAN BE TRACKED, DO NOT TRY TRACK STACK MEMORY ZONE
 */

#ifndef MEMORYTRACKER_H
#define MEMORYTRACKER_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <sys/mman.h>  // for mlock() and munlock()

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "../crypto/SHA256.h"

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

#define MT_FAIL -1100

#define MT_OK 1101

#define INVALID_INPUT_MT -1101

#define MT_NO_MORE_MT_trackers -1102
#define MT_MEMORYVIOLATION_BEFORE_DELETE -1103
#define MT_MEMORYVIOLATION -1104
#define MT_MEMORY_LOCK_FAIL -1105

// Schneier patrons for secure zeroization making it harder for data recovery
static const unsigned char Schneier_patterns[6] = {0x00, 0xFF, 0xAA, 0x55, 0xAA, 0x55};

// Constants for memory cleanup behavior.
#define MAX_MT_trackers 512 // Maximum number of memory allocations we can track.
#define CSP 1            // Flag to clear memory on deletion.
#define PSP 0            // Flag to preserve memory on deletion.

/**
 * @struct MemoryTracker
 * @brief Structure to track memory allocations and associated metadata.
 *
 * The MemoryTracker struct keeps track of individual memory blocks, 
 * including their size, a pointer to the memory, and a checksum for integrity verification.
 */

typedef struct MemoryTracker
{
    void *ptr;                  // Pointer to the allocated memory block.
    struct MemoryTracker *next; // Pointer to the next tracker in the list.
    size_t size;                // Size of the allocated memory block.s
    uint8_t IsCSP;              // Flag to indicate if memory should be cleared on deletion.
    uint8_t hash_sign[32];      // Hash for verifying memory integrity.
} MemoryTracker;

extern MemoryTracker MT_trackers[MAX_MT_trackers]; // Array of all memory trackers

extern MemoryTracker *Free_Tracker_List; // Linked list of available memory MT_trackers
extern MemoryTracker *Used_MT_trackers_List; // Linked list of used memory MT_trackers

extern pthread_mutex_t MT_mutex; // Mutex to ensure thread safety during memory operations

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief Initializes the memory tracker system by linking all MT_trackers in a free list.
 *
 * This function sets up the `MT_trackers` array by linking all available MT_trackers in a free list,
 * and initializes the `Free_Tracker_List` pointer to the beginning of this list.
 * It also ensures thread safety by locking a MT_mutex during the initialization process.
 *
 * @note Must be called before any other memory tracking functions are used.
 */
void API_MT_initialize_trackers();

/**
 * @brief Fetches a free tracker from the free list.
 *
 * This function retrieves a free `MemoryTracker` from the `Free_Tracker_List`. If no MT_trackers are available,
 * it returns `NULL`.
 *
 * @return A pointer to a `MemoryTracker` if available, or `NULL` if none are free.
 */
MemoryTracker *get_free_tracker();

/**
 * @brief Returns a used tracker back to the free list.
 *
 * This function returns a `MemoryTracker` that was previously in use back to the `Free_Tracker_List`.
 * It relinks the tracker into the list and resets its next pointer.
 *
 * @param tracker A pointer to the `MemoryTracker` to be returned to the free list.
 */
void return_tracker(MemoryTracker *tracker);

/**
 * @brief Adds a new memory block to the tracking system.
 *
 * This function adds a memory block to the tracking system by fetching a free tracker,
 * initializing it with the provided memory pointer, size, and a CSP (Critical Security Parameter) flag.
 * It then inserts the tracker into the `Used_MT_trackers_List`.
 *
 * @param ptr Pointer to the memory block to track.
 * @param size Size of the memory block.
 * @param isCSP Indicates if the block contains Critical Security Parameters (1 for CSP, 0 otherwise).
 * @return The index of the tracker in the `MT_trackers` array on success, or an error code on failure.
 */
int API_MT_add_tracker(void *ptr, size_t size, uint8_t isCSP);

/**
 * @brief Verifies the integrity of a tracked memory block.
 *
 * This function recalculates the checksum of the memory block associated with the given tracker
 * and compares it with the stored checksum to verify the memory block's integrity.
 *
 * @param tracker A pointer to the `MemoryTracker` to verify.
 * @return `MT_OK` if the integrity is valid, `MT_FAIL` otherwise.
 */
int API_MT_verify_integrity(MemoryTracker *tracker);

/**
 * @brief Updates the memory tracker, recalculates the checksum, and locks the memory.
 *
 * This function updates the memory tracker by performing the following steps:
 *  - Unlocks the previously locked memory (if applicable).
 *  - Recalculates the checksum of the memory block.
 *  - Locks the memory again to prevent it from being swapped out.
 *
 * The function is thread-safe, using a MT_mutex to ensure exclusive access to the memory tracker during the update.
 *
 * @param tracker Pointer to the MemoryTracker structure to be updated.
 *
 * @return 
 *  - MT_OK (0) on success.
 *  - INVALID_INPUT_MT (-1) if the tracker pointer is NULL.
 *  - MT_MEMORY_LOCK_FAIL (-2) if mlock fails to lock the memory.
 */
int API_MT_update_tracker(MemoryTracker *tracker);

/**
 * @brief changes a memory tracker with a new memory block and size.
 *
 * This function changes the memory block and size for an existing tracker and recalculates its checksum.
 * It's intended for rare use cases where the memory block associated with a tracker needs to be changed.
 *
 * @param tracker A pointer to the `MemoryTracker` to update.
 * @param new_ptr A pointer to the new memory block.
 * @param new_size The size of the new memory block.
 * @return `MT_OK` on success, or an error code on failure.
 */
int API_MT_change_tracker(MemoryTracker *tracker, void *new_ptr, size_t new_size);

/**
 * @brief Removes a tracker from the used list, optionally zeroizing its memory.
 *
 * This function removes a tracker associated with a given memory pointer from the `Used_MT_trackers_List`.
 * If the memory contains Critical Security Parameters (CSP), it will be securely zeroized using a Schneier pattern.
 *
 * @param ptr A pointer to the memory block to remove.
 * @return `MT_OK` on success, or an error code on failure.
 */
int API_MT_remove_tracker(void *ptr);

/**
 * @brief Zeroizes and frees all tracked memory allocations.
 *
 * This function iterates over all used memory MT_trackers, securely zeroizes any memory that is marked as CSP,
 * and returns all MT_trackers to the free list. It ensures thread safety by locking the MT_mutex during the process.
 *
 * @note This function clears all tracked memory and should be used with caution.
 */
void API_MT_zeroize_and_free_all();

#endif