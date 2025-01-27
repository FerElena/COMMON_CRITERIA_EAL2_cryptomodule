/**
 * @file log_manager.h
 * @brief File containing all the headers from the logfile management functions
 */

#ifndef LOG_MANAGER
#define LOG_MANAGER

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "../secure_memory_management/file_system.h"

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

extern sem_t TraceSem_empty;
extern sem_t TraceSem_full;

#define TRACERLOW "TracerLOW"
#define TRACERHIGH "TracerHIGH"

#define TRACERLOW_LENGTH (sizeof(TRACERLOW))
#define TRACERHIGH_LENGTH (sizeof(TRACERHIGH))

#define MAX_ARGUMENTS 10

#define TRACER_OK 1500

#define LT_TRACER_ERROR -1500



/**
 * @brief Max number of bytes
 * The maximum number of bytes allowed written in the logfile text
 */
#define MAX_BYTES_TRACER_LOW 2000000
#define MAX_BYTES_TRACER_HIGH 200000

#define MAX_STRING 300

extern unsigned char concatenated_string[MAX_STRING];

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief Initializes and starts the trace system by creating two trace files and launching the trace writing thread.
 *
 * This function creates two trace files (TRACERLOW and TRACERHIGH) with initial content and starts a thread
 * to handle the writing of trace messages asynchronously. It also initializes the necessary semaphores for
 * synchronization.
 *
 * @return `TRACER_OK` if the trace system is successfully initialized, or `LT_TRACER_ERROR` if file creation fails.
 */
int API_LT_startTraceFile();

/**
 * @brief Writes a formatted trace message to the trace buffer.
 *
 * This function writes a formatted trace message to the buffer, appending a timestamp and processing 
 * variable arguments. If the total message length exceeds the maximum string size, the write is aborted.
 * The function ensures thread-safe access to the buffer using semaphores and a mutex.
 *
 * @param str A format string for the trace message, followed by a variable number of arguments.
 */
void API_LT_traceWrite(unsigned char *str, ...);


/**
 * @brief Asynchronous trace writing function that runs in a separate thread.
 *
 * This function continuously monitors the trace buffer and writes the contents to the trace files.
 * It writes to `TRACERLOW` by default, and if the message is marked as important, it also writes to `TRACERHIGH`.
 * If the file size exceeds the limit, the trace file is reset and new data is written from the beginning.
 *
 * @param arg Unused argument for thread compatibility.
 * @return Always returns `NULL`.
 */
void *WriteTrace();

/**
 * @brief Retrieves the current system time in a formatted string.
 *
 * This function gets the current system time and formats it as a string in the format `YYYY-MM-DD HH:MM:SS`.
 * The formatted time is stored in the provided buffer.
 *
 * @param aux A buffer to store the formatted time string. It should have space for at least 20 characters.
 */
void MT_getTime(unsigned char *aux);


// char* itoa(int value, char* str); función para testing


#endif
