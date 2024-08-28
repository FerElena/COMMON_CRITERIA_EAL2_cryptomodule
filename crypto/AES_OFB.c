#include "AES_OFB.h"

void AES_OFB_EncryptDecrypt(const uint8_t *input, size_t length, const uint8_t *key, size_t keySize, uint8_t *iv, uint8_t *output) {
    AesContext ctx;
    uint8_t ivEnc[AES_BLOCK_SIZE];   // Buffer to store encrypted IV
    size_t i;

    // Initialize the AES context with the provided key
    API_CP_AesInitialize(&ctx, key, keySize);

    // Copy the IV to ivEnc
    memcpy(ivEnc, iv, AES_BLOCK_SIZE);

    // Process each data block
    for (i = 0; i < length; i += AES_BLOCK_SIZE) {
        uint8_t outputBlock[AES_BLOCK_SIZE];

        // Encrypt the IV or the last encrypted block
        CP_AesEncrypt(&ctx, ivEnc, outputBlock);

        // Update ivEnc for the next round
        memcpy(ivEnc, outputBlock, AES_BLOCK_SIZE);

        // XOR the input data with the encrypted block to get the final result in the output buffer
        size_t blockSize = (i + AES_BLOCK_SIZE > length) ? length - i : AES_BLOCK_SIZE;
        for (size_t j = 0; j < blockSize; j++) {
            output[i + j] = input[i + j] ^ outputBlock[j];
        }
    }
}
