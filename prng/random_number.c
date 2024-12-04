/**
 * @file random_number.c
 * @brief 
 * implementation of the random generation function
 */

#include "random_number.h"

int API_RNG_fill_buffer_random(unsigned char *buffer, size_t size) {
    int fd;
    ssize_t result;

    // First, attempt to fill the buffer using /dev/random
    fd = open("/dev/random", O_RDONLY);
    if (fd >= 0) {
        result = read(fd, buffer, size);
        if (result == (ssize_t)size) {
            close(fd);
            return RANDOM_OK;
        }
        close(fd);
    }

    // If unable to use /dev/random, try /dev/urandom
    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        result = read(fd, buffer, size);
        if (result == (ssize_t)size) {
            close(fd);
            return PSEUDORANDOM_OK;  // Return an error indicating that /dev/random was not used
        }
        close(fd);
    }

    // If both options fail, generate pseudo-random data as a last resort
    srand(time(NULL) ^ getpid());
    for (size_t i = 0; i < size; i++) {
        buffer[i] = rand() % 256;  // Generate a pseudo-random byte
    }

    return RNG_RANDOM_GENERATION_FAILED;  // Return an error indicating that no secure source was utilized
}