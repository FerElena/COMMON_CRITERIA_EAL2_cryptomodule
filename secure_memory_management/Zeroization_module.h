#ifndef ZEROIZATION_MODULE_H
#define ZEROIZATION_MODULE_H

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "MemoryTracker.h"
#include "DmemManager.h"
#include "file_system.h"

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief Securely zeroizes all systems within the module.
 *
 * This function triggers the complete zeroization process for the entire module, 
 * including memory tracking, the memory management tree, and the file system. 
 * It ensures that all sensitive data across these subsystems is securely wiped.
 */

void API_ZM_zeroize_entire_module();

#endif