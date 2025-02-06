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

    if (rand_hw_support) {
        size_t i = 0;
        uint32_t random_number;

        // Fill the buffer in 4-byte chunks when possible
        for (; i + 3 < size; i += 4) {
            while (_rdrand32_step(&random_number) == 0);
            *(uint32_t *)(buffer + i) = random_number;
        }

        // Handle any remaining bytes without wasting entropy
        if (i < size) {
            while (_rdrand32_step(&random_number) == 0);
            for (size_t j = 0; i < size; ++i, ++j) {
                buffer[i] = (unsigned char)(random_number >> (j * 8));
            }
        }
        return RANDOM_OK;
    }

    // Attempt to read random data from /dev/urandom
    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        result = read(fd, buffer, size);
        close(fd);
        if (result == (ssize_t)size) {
            return PSEUDORANDOM_OK;
        }
    }

    // Fallback: Generate pseudo-random data (not cryptographically secure)
    srand(time(NULL) ^ getpid());
    for (size_t i = 0; i < size; i++) {
        buffer[i] = rand() % 256;
    }

    return PRNG_GENERATION_FAILED;
}
