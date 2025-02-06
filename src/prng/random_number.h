/**
 * @file random_number.h
 * @brief Header file for functions that generate random bytes using secure sources.
 */

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <errno.h>
#include <stdint.h>
#include <mmintrin.h>
#include <immintrin.h>  // Include for Intel RDRAND support

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

#define RANDOM_OK 1400
#define PSEUDORANDOM_OK 1401
#define PRNG_GENERATION_FAILED -1401


/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief Checks if Intel RDRAND is available.
 *
 * This function checks if the Intel RDRAND instruction is available on the processor.
 *
 * 
 */
void check_rdrand(void);

/**
 * @brief Fills a buffer with random bytes, attempting to use secure sources.
 *
 * This function first tries to fill the buffer using Intel RDRAND. If that fails,
 * it attempts to use `/dev/urandom` as a fallback. If both of these fail, it will
 * generate pseudo-random bytes using `rand()` as a last resort, though this is less secure.
 *
 * @param buffer Pointer to the buffer that will be filled with random bytes.
 * @param size Size of the buffer, i.e., the number of random bytes to generate.
 *
 * @return int Returns `RANDOM_OK` if RDRAND or `/dev/urandom` was successfully used.
 * Returns `PSEUDORANDOM_OK` if `/dev/urandom` was used instead of RDRAND.
 * Returns `PRNG_GENERATION_FAILED` if neither secure source was available
 * and pseudo-random data was generated.
 */
int API_RNG_fill_buffer_random(unsigned char *buffer, size_t size);
