#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "../packet_manager/packet_cipher_auth.h"
#include "../prng/random_number.h"

size_t random_size_t(size_t min, size_t max);
int test_encrypt_decrypt(unsigned char *plaintext, size_t plaintext_length, unsigned char *key_AES, unsigned char *key_HMAC);
void run_tests_packets(int num_times);
