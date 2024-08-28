#ifndef MEMORYTRACKER_H
#define MEMORYTRACKER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>


#define MT_OK 1
#define MT_FAIL 0
#define INVALID_INPUT_MT -1
#define NO_MORE_TRACKERS -2
#define MEMORYVIOLATION_BEFORE_DELETE -3

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

void initialize_trackers();

MemoryTracker *get_free_tracker();

void return_tracker(MemoryTracker *tracker);

int add_tracker(void *ptr, size_t size, uint8_t isCSP);

int verify_integrity(MemoryTracker *tracker);

int update_tracker(MemoryTracker *tracker, void *new_ptr, size_t new_size);

int remove_tracker(void *ptr);

void zeroize_and_free_all();

#endif