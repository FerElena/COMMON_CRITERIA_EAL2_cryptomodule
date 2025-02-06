/**
 * @file random_number.c
 * @brief 
 * implementation of the random generation function
 */

#include "random_number.h"

uint8_t rand_hw_support = 0;

void check_rdrand() {
    uint32_t random_number = 0;
    _rdrand32_step(&random_number);
    if(random_number)
        rand_hw_support = 1;
    else
        rand_hw_support = 0;
}

int API_RNG_fill_buffer_random(unsigned char *buffer, size_t size) {
    int fd;
    ssize_t result;

    // Check if Intel RDRAND is available and fill the buffer with RDRAND
    if (rand_hw_support) {
        for (size_t i = 0; i < size; ++i) {
            uint32_t random_number;
            while (_rdrand32_step(&random_number) == 0);
            buffer[i] = (unsigned char)(random_number & 0xFF);
        }
        return RANDOM_OK;
    }

    // Attempt to fill the buffer using /dev/urandom
    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        result = read(fd, buffer, size);
        if (result == (ssize_t)size) {
            close(fd);
            return PSEUDORANDOM_OK;
        }
        close(fd);
    }

    // If both options fail, generate pseudo-random data as a last resort
    srand(time(NULL) ^ getpid());
    for (size_t i = 0; i < size; i++) {
        buffer[i] = rand() % 256;  // Generate a pseudo-random byte
    }

    return PRNG_GENERATION_FAILED;  // Return an error indicating that no secure source was utilized

}