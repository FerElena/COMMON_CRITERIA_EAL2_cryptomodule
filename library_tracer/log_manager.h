/**
 * @file log_manager.h
 * @brief File containing all the headers from the logfile management functions
 */

#ifndef LOG_MANAGER
#define LOG_MANAGER

/* Compiler include files ............................................ */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>

/* Private include files ............................................ */

#include "../file_system/file_system.h"

/* Global variables definition ...................................... */

extern sem_t TraceSem_empty;
extern sem_t TraceSem_full;

#define TRACERLOW "TracerLOW"
#define TRACERHIGH "TracerHIGH"

#define TRACERLOW_LENGTH (sizeof(TRACERLOW))
#define TRACERHIGH_LENGTH (sizeof(TRACERHIGH))

#define TRACER_OK 1

#define TRACER_ERROR 0



/**
 * @brief Max number of bytes
 * The maximum number of bytes allowed written in the logfile text
 */
#define MAX_BYTES_TRACER_LOW 2000000
#define MAX_BYTES_TRACER_HIGH 1000000

#define MAX_STRING 300

extern unsigned char concatenated_string[MAX_STRING];


/* Function declaration zone ........................................ */

/**
 * @brief Opens the trace file
 * 
 * This function opens and creates the trace file used to register every log
 * 
 * @sfr{FAU_STG.1.1}
 * @methodOfUse{This function is invoked by the checkinit_library.c} 
 * 
 */
int API_MT_startTraceFile();

/**
 * @brief Write the corresponding log into the logfile
 * 
 * This function is used to record the library activity and operations into the logfile, so later an administrator can review
 * every step followed to a desired point (a data breach, an error, an attack...)
 * 
 * @sfr{FAU_GEN.1.1, FAU_GEN.1.2, FAU_STG.1.1}
 * @methodOfUse{This function is invoked everytime the library requires to trace some library or client operations}
 * 
 * @param str Extra information that must be included into the log (e.g logcode, id...)
 * @param ... 
 * 
 * @errors
 * @error{ ERROR 1, Stops execution if there is an error allocating memory for the concatenated string}
 * @error{ERROR 2, Stops execution if the file Traces doesn´t exist}
 */
void API_MT_traceWrite(unsigned char *str, ...);

void *WriteTrace();


/**
 * @brief Get the Time object
 * Get the current computer time in the following format: (year-month-day hours-minutes-seconds)
 * 
 * @sfr{FAU_GEN.1.1, FAU_GEN.1.2, FAU_STG.1.1}
 * @methodOfUse{This function is invoked by the API_MT_traceWrite function}
 * 
 * @param aux The buffer where the time is stored
 */
void MT_getTime(unsigned char *aux);


// char* itoa(int value, char* str); función para testing


#endif
