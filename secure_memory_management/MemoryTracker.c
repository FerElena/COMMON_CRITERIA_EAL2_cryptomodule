/*
este código está pensado para un caso de uso en el que la función API_MT_add_tracker(eficiente, busqueda de complejidad O 1)
es usada al principio de la ejecución de un programa con todas las estructuras de datos de las cuales hay que llevar un tracking
dado que son CSP o PSP en nuestro contexto. Primero este debe ser inicializado con initialice_tracker, las
funciones de update y remove tracker son mas costosas(busqueda de complejidad O n), y están pensadas para ser utilizadas en casos
más excepcionales, la función de verify se debe usar durante toda la ejecución del programa en contextos anteriores a la
utilización de una de las estructuras de datos Trackeadas. la función de zeroize zeroiza todos los CSPs, y solo se debe
usar bajo situaciones extremas, ya que esto zeroizara con el patrón de Schneier toda la memoria trackeada como CSP.
para checkear integridad utilizamos CRC-32 ya que es una función muy rápida, y para este caso no es necesario usar una
función certificada
*/

#include "MemoryTracker.h"
#include "../crypto/CRC_Galileo.h"

// Array of trackers for efficient management.
MemoryTracker trackers[MAX_TRACKERS];

// Pointers for managing free and used tracker lists.
MemoryTracker *Free_Tracker_List = NULL;
MemoryTracker *Used_Trackers_List = NULL;

// Mutex for synchronizing access to the tracker structures.
pthread_mutex_t MT_mutex = PTHREAD_MUTEX_INITIALIZER;

// Initialize the tracker system.
void API_MT_initialize_trackers()
{
    pthread_mutex_lock(&MT_mutex); // Lock to ensure thread safety.
    for (int i = 0; i < MAX_TRACKERS - 1; i++)
    {
        trackers[i].next = &trackers[i + 1]; // Link all trackers in a free list.
    }
    trackers[MAX_TRACKERS - 1].next = NULL; // End of the free list.
    Free_Tracker_List = &trackers[0];       // Point to the first tracker as the start of the free list.
    pthread_mutex_unlock(&MT_mutex);           // Unlock the MT_mutex.
}

// Fetch a free tracker from the list, low level function.
MemoryTracker *get_free_tracker()
{
    if (Free_Tracker_List == NULL) // if no more free Trackers
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
    if (ptr == NULL || size > SIZE_MAX || size < 0 || isCSP > 1 || isCSP < 0) // if invalid input parameters
    {
        return INVALID_INPUT_MT;
    }

    pthread_mutex_lock(&MT_mutex);
    MemoryTracker *tracker = get_free_tracker(); // Get a free tracker.
    if (tracker == NULL)
    {
        pthread_mutex_unlock(&MT_mutex);
        return MT_NO_MORE_TRACKERS; // Indicate no more Trackers
    }
    // Initialize the tracker with the memory block's info.
    tracker->ptr = ptr;
    tracker->size = size;
    tracker->checksum = crc_32(ptr, size); // Calculate the CRC_32 for the memory block.
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
    tracker->next = Used_Trackers_List;
    Used_Trackers_List = tracker;
    pthread_mutex_unlock(&MT_mutex);
    return (tracker - trackers); // Return the tracker's index as a success indicator, if positive, is successful
}

// Verify the memory block's integrity using its checksum, no need locks as it's a read-only function.
int API_MT_verify_integrity(MemoryTracker *tracker)
{
    if (tracker == NULL)
    {
        return INVALID_INPUT_MT;
    }

    unsigned int current_checksum = crc_32(tracker->ptr, tracker->size); // Recalculate the current checksum.
    if (current_checksum == tracker->checksum)                           // Return whether the checksums match (if correct, MT_OK, if not MT_FAIL)
        return MT_OK;
    else
        return MT_MEMORYVIOLATION;
}

// updates a tracker with a new content and CRC, suposed to be used!!!
int API_MT_update_tracker(MemoryTracker *tracker)
{
    if (tracker == NULL)
    {
        return INVALID_INPUT_MT;
    }

    pthread_mutex_lock(&MT_mutex);

    // Unlock old memory if it's locked.
    munlock(tracker->ptr, tracker->size);

    // Update tracker checksum.
    tracker->checksum = crc_32(tracker->ptr, tracker->size); // Recalculate the checksum.

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
    if (tracker == NULL || new_ptr == NULL || new_size < 0 || new_size > SIZE_MAX)
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
    tracker->checksum = crc_32(new_ptr, new_size); // Recalculate the checksum.

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
    MemoryTracker **indirect = &Used_Trackers_List;
    while (*indirect && (*indirect)->ptr != ptr)
    {
        indirect = &(*indirect)->next;
    }
    if (*indirect == NULL)
    {
        pthread_mutex_unlock(&MT_mutex); // Unlock if the tracker is not found.
        return INVALID_INPUT_MT; // Indicate failure.
    }

    // Verify memory integrity before removal.
    MemoryTracker *toRemove = *indirect;
    int integrity = API_MT_verify_integrity(toRemove);
    if (!integrity)
    {
        pthread_mutex_unlock(&MT_mutex);                     // Unlock on integrity violation.
        return MT_MEMORYVIOLATION_BEFORE_DELETE;             // Indicate failure.
    }

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
    return MT_OK; // Indicate success.
}

// Clean up all tracked memory allocations.
void API_MT_zeroize_and_free_all()
{
    pthread_mutex_lock(&MT_mutex);
    MemoryTracker *current = Used_Trackers_List;
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
        current = current->next; // advance in Used Trackers linked list
        return_tracker(toFree);  // Return each tracker to the free list.
    }

    Used_Trackers_List = NULL; // Clear the used list.
    pthread_mutex_unlock(&MT_mutex);
}