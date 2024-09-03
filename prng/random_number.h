

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <errno.h>

#define RANDOM_OK 1
#define ERROR_SECURE_RANDOM_FAILED -1
#define ERROR_RANDOM_GENERATION_FAILED -2

int fill_buffer_with_random_bytes(unsigned char *buffer, size_t size);