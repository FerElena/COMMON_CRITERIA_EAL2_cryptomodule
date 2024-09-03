#include "random_number.h"

int fill_buffer_with_random_bytes(unsigned char *buffer, size_t size) {
    int fd;
    ssize_t result;

    // Primero intenta llenar el buffer usando /dev/random
    fd = open("/dev/random", O_RDONLY);
    if (fd >= 0) {
        result = read(fd, buffer, size);
        if (result == (ssize_t)size) {
            close(fd);
            return RANDOM_OK;
        }
        close(fd);
    }

    // Si no pudo usar /dev/random, intenta /dev/urandom
    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        result = read(fd, buffer, size);
        if (result == (ssize_t)size) {
            close(fd);
            return ERROR_SECURE_RANDOM_FAILED;  // Retorna un error indicando que no se usó /dev/random
        }
        close(fd);
    }

    // Si ambas opciones fallan, genera datos pseudoaleatorios como último recurso
    srand(time(NULL) ^ getpid());
    for (size_t i = 0; i < size; i++) {
        buffer[i] = rand() % 256;  // Genera un byte pseudoaleatorio
    }

    return ERROR_RANDOM_GENERATION_FAILED;  // Retorna un error indicando que ninguna fuente segura fue utilizada
}