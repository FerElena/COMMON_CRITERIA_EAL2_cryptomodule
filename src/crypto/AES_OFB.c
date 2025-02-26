/**
 * @file AES_CBC.h
 * @brief File containing the implementation of AES_OFB
 */

#include "AES_OFB.h"

uint8_t AESOFB_outputBlock[AES_BLOCK_SIZE]; //Buffer to store momentary output block, CSP
uint8_t AESOFB_ivEnc[AES_BLOCK_SIZE];       // Buffer to store encrypted IV, CSP


void API_AES_OFB_EncryptDecrypt(const AesContext aesofb_ctx,uint8_t *input, size_t length, uint8_t *iv, uint8_t *output) {
    size_t i;

    // Copy the IV to AESOFB_ivEnc
    memcpy(AESOFB_ivEnc, iv, AES_BLOCK_SIZE);

    // Process each data block
    for (i = 0; i < length; i += AES_BLOCK_SIZE) {

        // Encrypt the IV or the last encrypted block
        API_AES_encrypt_block(&aesofb_ctx, AESOFB_ivEnc, AESOFB_outputBlock);

        // Update AESOFB_ivEnc for the next round
        memcpy(AESOFB_ivEnc, AESOFB_outputBlock, AES_BLOCK_SIZE);

        // XOR the input data with the encrypted block to get the final result in the output buffer
        size_t blockSize = (i + AES_BLOCK_SIZE > length) ? length - i : AES_BLOCK_SIZE;
        for (size_t j = 0; j < blockSize; j++) {
            output[i + j] = input[i + j] ^ AESOFB_outputBlock[j];
        }
    }
}
