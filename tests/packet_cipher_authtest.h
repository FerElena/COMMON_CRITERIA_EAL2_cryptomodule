#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "../cryptomodule_core/packet_cipher_auth.h"
#include "../prng/random_number.h"
#include "../secure_memory_management/DmemManager.h"

size_t random_size_t(size_t min, size_t max);
int test_encrypt_decrypt(unsigned char *plaintext, size_t plaintext_length, unsigned char *key_AES, unsigned char *key_HMAC);
void run_tests_packets(int num_times);
