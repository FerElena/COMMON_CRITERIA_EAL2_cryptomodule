/**
 * @file AES_OFB.h
 * @brief File containing all the function headers of the AES_OFB.
 */

#ifndef AESOFB_H
#define AESOFB_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <string.h>
#include <stdint.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "AES_CORE.h"

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

extern uint8_t AESOFB_outputBlock[AES_BLOCK_SIZE]; //Buffer to store momentary output block, CSP
extern uint8_t AESOFB_ivEnc[AES_BLOCK_SIZE];       // Buffer to store encrypted IV, CSP


/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief AES-OFB (Output Feedback) encryption/decryption function.
 *
 * This function performs encryption or decryption using AES in OFB mode. 
 * OFB mode is a stream cipher mode, meaning that the same function can be used for both 
 * encryption and decryption. It processes data block by block and XORs the input data 
 * with an encrypted IV or previously encrypted data block to generate the output.
 *
 * @param[in] AESOFB_CTX     Context with the AES key already expanded .
 * @param[in] input          Pointer to the input data to be encrypted or decrypted.
 * @param[in] length         Length of the input data in bytes.
 * @param[in, out] iv        Pointer to the initialization vector (IV), which will be updated 
 *                           after each block is processed.
 * @param[out] output        Pointer to the output buffer where the encrypted or decrypted data 
 *                           will be stored. Must be the same size as the input buffer.
 *
 * @note The same function is used for both encryption and decryption in OFB mode, as it 
 *       is a stream cipher mode and only involves XORing the data with the encrypted IV.
 *       The IV must be unique for each encryption operation to maintain security.
 *
 * @warning Ensure that the output buffer is large enough to hold the result (same size 
 *          as the input data).
 */
void API_AES_OFB_EncryptDecrypt(const AesContext aesofb_ctx,uint8_t *input, size_t length, uint8_t *iv, uint8_t *output);

#endif