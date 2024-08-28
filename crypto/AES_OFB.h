#ifndef AESOFB_H
#define AESOFB_H

#include <string.h>
#include <stdint.h>

#include "AES_CORE.h"

void AES_OFB_EncryptDecrypt(const uint8_t *input, size_t length, const uint8_t *key, size_t keySize, uint8_t *iv, uint8_t *output);

#endif