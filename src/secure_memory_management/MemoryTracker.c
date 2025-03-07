/**
 * @file Memory_Tracker.c
 * @brief This code is designed for a use case where the `API_MT_add_tracker` function (efficient, O(1) complexity search) is used at the beginning of
 *  a program's execution with all the data structures that require tracking, as they are CSP or PSP in our context.
 *  First, it must be initialized using `initialize_tracker`. The `update` and `remove` tracker functions are more costly (O(n) complexity search)
 *  and are intended for more exceptional cases. The `verify` function should be used throughout the program's execution in contexts prior to using one of
 *  the tracked data structures. The `zeroize` function zeroizes all CSPs and should only be used in extreme situations,
 *  as it applies the Schneier pattern to zeroize all memory tracked as CSP. For integrity checking, we use SHA256 NIST certified function,
 *
 */

#include "MemoryTracker.h"

// Array of MT_trackers for efficient management.
MemoryTracker MT_trackers[MAX_MT_trackers];

// Pointers for managing free and used tracker lists.
MemoryTracker *Free_Tracker_List = NULL;
MemoryTracker *Used_MT_trackers_List = NULL;

// Mutex for synchronizing access to the tracker structures.
pthread_mutex_t MT_mutex = PTHREAD_MUTEX_INITIALIZER;

// Initialize the tracker system.
void API_MT_initialize_trackers()
{
    pthread_mutex_lock(&MT_mutex); // Lock to ensure thread safety.
    for (int i = 0; i < MAX_MT_trackers - 1; i++)
    {
        MT_trackers[i].next = &MT_trackers[i + 1]; // Link all MT_trackers in a free list.
    }
    MT_trackers[MAX_MT_trackers - 1].next = NULL; // End of the free list.
    Free_Tracker_List = &MT_trackers[0];          // Point to the first tracker as the start of the free list.
    pthread_mutex_unlock(&MT_mutex);              // Unlock the MT_mutex.
}

// Fetch a free tracker from the list, low level function.
MemoryTracker *get_free_tracker()
{
    if (Free_Tracker_List == NULL) // if no more free MT_trackers
        return NULL;

    // Detach the first tracker from the free list and return it.
    MemoryTracker *tracker = Free_Tracker_List;
    Free_Tracker_List = Free_Tracker_List->next;
    tracker->next = NULL;
    return tracker;
}

// Return a tracker to the free list, low level function.
void return_tracker(MemoryTracker *tracker)
{
    tracker->next = Free_Tracker_List; // Insert it back into the free list.
    Free_Tracker_List = tracker;
}

// Add a new memory allocation to be tracked.
int API_MT_add_tracker(void *ptr, size_t size, uint8_t isCSP)
{
    if (ptr == NULL || isCSP > 1 || isCSP < 0) // if invalid input parameters
    {
        return INVALID_INPUT_MT;
    }

    pthread_mutex_lock(&MT_mutex);
    MemoryTracker *tracker = get_free_tracker(); // Get a free tracker.
    if (tracker == NULL)
    {
        pthread_mutex_unlock(&MT_mutex);
        return MT_NO_MORE_MT_trackers; // Indicate no more MT_trackers
    }
    // Initialize the tracker with the memory block's info.
    tracker->ptr = ptr;
    tracker->size = size;
    API_sha256(ptr, size, tracker->hash_sign); // Calculate the SHA256 hash for the memory block.
    tracker->IsCSP = isCSP;

    // Lock the memory to prevent swapping.
    if (mlock(ptr, size) != 0)
    {
        perror("mlock failed");
        return_tracker(tracker); // Return tracker to the free list
        pthread_mutex_unlock(&MT_mutex);
        return MT_MEMORY_LOCK_FAIL; // Indicate failure
    }

    // Add the tracker to the used list.
    tracker->next = Used_MT_trackers_List;
    Used_MT_trackers_List = tracker;
    pthread_mutex_unlock(&MT_mutex);
    return (tracker - MT_trackers); // Return the tracker's index as a success indicator, if positive, is successful
}

// Verify the memory block's integrity using its checksum, no need locks as it's a read-only function.
int API_MT_verify_integrity(MemoryTracker *tracker)
{
    if (tracker == NULL)
    {
        return INVALID_INPUT_MT;
    }
    uint8_t aux_hash[32];
    API_sha256(tracker->ptr, tracker->size, aux_hash); // recalculate the hash
    if (memcmp(tracker->hash_sign, aux_hash, 32) == 0) // Return whether the hashes match (if correct, MT_OK, if not MT_FAIL)
        return MT_OK;
    else
        return MT_MEMORYVIOLATION;
}

// updates a tracker with a new content and hash_sign, suposed to be used!!!
int API_MT_update_tracker(MemoryTracker *tracker)
{
    if (tracker == NULL)
    {
        return INVALID_INPUT_MT;
    }

    pthread_mutex_lock(&MT_mutex);

    // Unlock old memory if it's locked.
    munlock(tracker->ptr, tracker->size);

    // Update tracker hash.
    API_sha256(tracker->ptr, tracker->size, tracker->hash_sign);

    // Lock the new memory.
    if (mlock(tracker->ptr, tracker->size) != 0)
    {
        pthread_mutex_unlock(&MT_mutex);
        return MT_MEMORY_LOCK_FAIL; // Indicate failure.
    }

    pthread_mutex_unlock(&MT_mutex);
    return MT_OK;
}

// Change a tracker with a new memory block and size, you need to save the tracker index to use this function, not supposed to be used often
int API_MT_change_tracker(MemoryTracker *tracker, void *new_ptr, size_t new_size)
{
    if (tracker == NULL || new_ptr == NULL)
    {
        return INVALID_INPUT_MT;
    }

    pthread_mutex_lock(&MT_mutex);

    // Unlock old memory if it's locked.
    if (munlock(tracker->ptr, tracker->size) != 0)
    {
        perror("munlock failed");
    }

    // Update the memory pointer and size.
    tracker->ptr = new_ptr;
    tracker->size = new_size;

    // Update tracker hash.
    API_sha256(tracker->ptr, tracker->size, tracker->hash_sign);

    // Lock the new memory.
    if (mlock(new_ptr, new_size) != 0)
    {
        pthread_mutex_unlock(&MT_mutex);
        return MT_MEMORY_LOCK_FAIL; // Indicate failure
    }

    pthread_mutex_unlock(&MT_mutex);
    return MT_OK;
}

// Remove a tracker from used list, zeroizing its memory if it is a CSP.
int API_MT_remove_tracker(void *ptr)
{
    pthread_mutex_lock(&MT_mutex);
    // Find the tracker for the given memory pointer.
    MemoryTracker **indirect = &Used_MT_trackers_List;
    while (*indirect && (*indirect)->ptr != ptr)
    {
        indirect = &(*indirect)->next;
    }
    if (*indirect == NULL)
    {
        pthread_mutex_unlock(&MT_mutex); // Unlock if the tracker is not found.
        return INVALID_INPUT_MT;         // Indicate failure.
    }

    // Verify memory integrity before removal.
    MemoryTracker *toRemove = *indirect;

    int integrity = API_MT_verify_integrity(toRemove);

    // Clear memory if CSP, using secure scheme of Schneier Patron.
    if (toRemove->IsCSP)
    {
        for (int i = 0; i < 6; i++)
        {
            memset(toRemove->ptr, Schneier_patterns[i], toRemove->size);
        }
    }

    // Unlock memory before freeing it.
    munlock(toRemove->ptr, toRemove->size);

    // Remove the tracker from the used list.
    *indirect = toRemove->next;
    return_tracker(toRemove); // Return it to the free list.
    pthread_mutex_unlock(&MT_mutex);

    if(integrity == MT_MEMORYVIOLATION)
        return MT_MEMORYVIOLATION_BEFORE_DELETE;
    else
        return MT_OK; // Indicate success.
}

// Clean up all tracked memory allocations.
void API_MT_zeroize_and_free_all()
{
    pthread_mutex_lock(&MT_mutex);
    MemoryTracker *current = Used_MT_trackers_List;
    MemoryTracker *toFree = NULL;

    // Iterate over the used list and clear memory if necessary.
    while (current)
    {
        if (current->IsCSP)
        {
            for (int i = 0; i < 6; i++)
            {
                memset(current->ptr, Schneier_patterns[i], current->size);
            }
        }

        // Unlock memory before freeing it.
        munlock(current->ptr, current->size);
        toFree = current;
        current = current->next; // advance in Used MT_trackers linked list
        return_tracker(toFree);  // Return each tracker to the free list.
    }

    Used_MT_trackers_List = NULL; // Clear the used list.
    pthread_mutex_unlock(&MT_mutex);
}