#ifndef MEMORYTRACKER_H
#define MEMORYTRACKER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <sys/mman.h>  // Para mlock() y munlock()


#define MT_OK 1
#define MT_FAIL 0
#define INVALID_INPUT_MT -1
#define NO_MORE_TRACKERS -2
#define MEMORYVIOLATION_BEFORE_DELETE -3
#define MEMORY_LOCK_FAIL -4

// Schneier patrons for secure zeroization making it harder for data recovery
static const unsigned char Schneier_patterns[6] = {0x00, 0xFF, 0xAA, 0x55, 0xAA, 0x55};

// Constants for memory cleanup behavior.
#define MAX_TRACKERS 512 // Maximum number of memory allocations we can track.
#define CSP 1            // Flag to clear memory on deletion.
#define PSP 0            // Flag to preserve memory on deletion.

// Struct to track memory allocations.
typedef struct MemoryTracker
{
    void *ptr;                  // Pointer to the allocated memory block.
    struct MemoryTracker *next; // Pointer to the next tracker in the list.
    unsigned int checksum;      // Checksum for verifying memory integrity.
    size_t size;                // Size of the allocated memory block.s
    uint8_t IsCSP;              // Flag to indicate if memory should be cleared on deletion.
} MemoryTracker;

extern MemoryTracker trackers[MAX_TRACKERS];

extern MemoryTracker *Free_Tracker_List;
extern MemoryTracker *Used_Trackers_List;

extern pthread_mutex_t mutex;

/**
 * @brief Initializes the memory tracker system by linking all trackers in a free list.
 *
 * This function sets up the `trackers` array by linking all available trackers in a free list,
 * and initializes the `Free_Tracker_List` pointer to the beginning of this list.
 * It also ensures thread safety by locking a mutex during the initialization process.
 *
 * @note Must be called before any other memory tracking functions are used.
 */
void initialize_trackers();

/**
 * @brief Fetches a free tracker from the free list.
 *
 * This function retrieves a free `MemoryTracker` from the `Free_Tracker_List`. If no trackers are available,
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
 * It then inserts the tracker into the `Used_Trackers_List`.
 *
 * @param ptr Pointer to the memory block to track.
 * @param size Size of the memory block.
 * @param isCSP Indicates if the block contains Critical Security Parameters (1 for CSP, 0 otherwise).
 * @return The index of the tracker in the `trackers` array on success, or an error code on failure.
 */
int add_tracker(void *ptr, size_t size, uint8_t isCSP);

/**
 * @brief Verifies the integrity of a tracked memory block.
 *
 * This function recalculates the checksum of the memory block associated with the given tracker
 * and compares it with the stored checksum to verify the memory block's integrity.
 *
 * @param tracker A pointer to the `MemoryTracker` to verify.
 * @return `MT_OK` if the integrity is valid, `MT_FAIL` otherwise.
 */
int verify_integrity(MemoryTracker *tracker);

/**
 * @brief Updates a memory tracker with a new memory block and size.
 *
 * This function updates the memory block and size for an existing tracker and recalculates its checksum.
 * It's intended for rare use cases where the memory block associated with a tracker needs to be changed.
 *
 * @param tracker A pointer to the `MemoryTracker` to update.
 * @param new_ptr A pointer to the new memory block.
 * @param new_size The size of the new memory block.
 * @return `MT_OK` on success, or an error code on failure.
 */
int update_tracker(MemoryTracker *tracker, void *new_ptr, size_t new_size);

/**
 * @brief Removes a tracker from the used list, optionally zeroizing its memory.
 *
 * This function removes a tracker associated with a given memory pointer from the `Used_Trackers_List`.
 * If the memory contains Critical Security Parameters (CSP), it will be securely zeroized using a Schneier pattern.
 *
 * @param ptr A pointer to the memory block to remove.
 * @return `MT_OK` on success, or an error code on failure.
 */
int remove_tracker(void *ptr);

/**
 * @brief Zeroizes and frees all tracked memory allocations.
 *
 * This function iterates over all used memory trackers, securely zeroizes any memory that is marked as CSP,
 * and returns all trackers to the free list. It ensures thread safety by locking the mutex during the process.
 *
 * @note This function clears all tracked memory and should be used with caution.
 */
void zeroize_and_free_all();

#endif