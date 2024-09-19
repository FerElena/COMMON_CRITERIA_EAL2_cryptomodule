#ifndef MODULE_INITIALIZATION_H
#define MODULE_INITIALIZATION_H

#include <stdlib.h>
#include <stdint.h>

//TRACKERS INDEX LIST for memory integrity/zeroization
uint32_t FS_cipher_key_tracker_index;
uint32_t FS_data_buffer_tracker_index;

#include "../secure_memory_management/file_system.h"
#include "../secure_memory_management/MemoryTracker.h"

#endif