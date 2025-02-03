/**
 * @file AES_CBC.c
 * @brief File containing all the function definitions of the AES_CBC algorithm.
 */

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/
#include "AES_CBC.h"

AesContext AES_CBC_ctx; // auxiliar ctx to store derives key, CSP!

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

void CP_addPaddingAes(unsigned char *message, size_t *length, unsigned char *padded_message)
{
  // Calculate the number of padding bytes needed
  // AES_BLOCK_SIZE is the block size of AES, usually 16 bytes
  // The padding is the number of bytes needed to complete a block
  int PadNumber = AES_BLOCK_SIZE - (*length % AES_BLOCK_SIZE);

  // Update the original message length with the new length (including padding)
  *length = *length + PadNumber;

  // Add the padding to the message
  // Loop to fill with the value of PadNumber (PKCS#7 padding)
  // PKCS#7 states that each added byte should be equal to the number of padding bytes
  for (int i = 0; i < PadNumber; i++)
  {
    // Insert the value of PadNumber in the final positions of the message
    // (*length - PadNumber) is the index where padding starts
    message[(*length - PadNumber) + i] = PadNumber;
  }
}

int CP_getPaddingLength(const unsigned char *padded_message, size_t length)
{
  if (length == 0)
  {
    return -1; // No message to check
  }
  unsigned char lastByte = padded_message[length - 1]; // Get the last byte, which indicates the padding
  if (lastByte > AES_BLOCK_SIZE || lastByte == 0)
  {
    return -1; // Invalid padding, as it cannot be greater than the block size or zero
  }

  // Check that all padding bytes are equal to the last byte
  for (int i = 0; i < lastByte; i++)
  {
    if (padded_message[length - 1 - i] != lastByte)
    {
      return -1; // Invalid padding if any byte doesn't match
    }
  }

  return lastByte; // Return the length of the padding, which is the value of the last byte
}

// XOR two AES blocks and store the result
void CP_XorAesBlock(uint8_t *Block1, uint8_t const *Block2, uint8_t *result)
{
  for (uint32_t i = 0; i < AES_BLOCK_SIZE; i++)
    result[i] = Block1[i] ^ Block2[i];
}

// Encrypt data using AES-CBC mode
int API_AESCBC_encrypt(unsigned char *plaintext, size_t len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *ciphertext)
{
  // Initialize AES context with the provided key
  API_AES_initkey(&AES_CBC_ctx, key, AES_KEY_SIZE);

  // Ensure the plaintext length is a multiple of 16 bytes
  if (len % 16 != 0)
    return 0;

  // Encrypt each block of plaintext
  for (size_t num_rounds = 0; num_rounds < len / 16; num_rounds++){
    if(num_rounds == 0){
      CP_XorAesBlock(plaintext, iv, ciphertext); // XOR with IV for the first block
    }
    else{
      CP_XorAesBlock(plaintext + (num_rounds * 16), ciphertext + ((num_rounds - 1) * 16), ciphertext + (num_rounds * 16)); // XOR with previous ciphertext block
    }
    API_AES_encrypt_block(&AES_CBC_ctx, ciphertext + (num_rounds * 16), ciphertext + (num_rounds * 16)); // Encrypt the XORed block
  }
  return 1;
}

// Decrypt data using AES-CBC mode
int API_AESCBC_decrypt(unsigned char *ciphertext, size_t len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *plaintext)
{
  // Initialize AES context with the provided key
  API_AES_initkey(&AES_CBC_ctx, key, AES_KEY_SIZE);

  // Ensure the ciphertext length is a multiple of 16 bytes
  if (len % 16 != 0)
    return 0;

  // Decrypt each block of ciphertext
  for (size_t num_rounds = 0; num_rounds < len / 16; num_rounds++){
    API_AES_decrypt_block(&AES_CBC_ctx, ciphertext + (num_rounds * 16), plaintext + (num_rounds * 16)); // Decrypt the block
    if(num_rounds == 0){
      CP_XorAesBlock(plaintext, iv, plaintext); // XOR with IV for the first block
    }
    else{
      CP_XorAesBlock(plaintext + (num_rounds * 16), ciphertext + ((num_rounds - 1) * 16), plaintext + (num_rounds * 16)); // XOR with previous ciphertext block
    }
  }
  return 1;
}


