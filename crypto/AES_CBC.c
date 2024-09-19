/**
 * @file AES_CBC.c
 * @brief File containing all the function definitions of the AES_CBC algorithm.
 */

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/
#include "AES_CBC.h"

AesCbcContext AES_CBC_ctx; //auxiliar ctx to store derives key, CSP!

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

void CP_XorAesBlock(uint8_t *Block1, uint8_t const *Block2)
{

  uint32_t i;

  for (i = 0; i < AES_BLOCK_SIZE; i++)
  {
    Block1[i] ^= Block2[i];
  }
}

void CP_AesCbcInitialize(AesCbcContext *Context, AesContext const *InitializedAesContext, uint8_t const IV[AES_BLOCK_SIZE])
{
  // Setup context values
  Context->Aes = *InitializedAesContext;
  memcpy(Context->PreviousCipherBlock, IV, sizeof(Context->PreviousCipherBlock));
}

int CP_AesCbcInitializeWithKey(AesCbcContext *Context, uint8_t const *Key, uint32_t KeySize, uint8_t const IV[AES_BLOCK_SIZE])
{

  AesContext aes;
  if (0 != API_CP_AesInitialize(&aes, Key, KeySize))
  {
    return -1;
  }

  // Now set-up AesCbcContext
  CP_AesCbcInitialize(Context, &aes, IV);
  return 0;
}

int CP_AesCbcEncrypt(AesCbcContext *Context, void const *InBuffer, void *OutBuffer, uint32_t Size)
{

  uint32_t numBlocks = Size / AES_BLOCK_SIZE;
  uint32_t offset = 0;
  uint32_t i;

  if (0 != Size % AES_BLOCK_SIZE)
  {
    // Size not a multiple of AES block size (16 bytes).
    return -1;
  }

  for (i = 0; i < numBlocks; i++)
  {
    // XOR on the next block of data onto the previous cipher block
    CP_XorAesBlock(Context->PreviousCipherBlock, (uint8_t *)InBuffer + offset);

    // Encrypt to make new cipher block
    API_CP_AesEncryptInPlace(&Context->Aes, Context->PreviousCipherBlock);

    // Output cipher block
    memcpy((uint8_t *)OutBuffer + offset, Context->PreviousCipherBlock, AES_BLOCK_SIZE);

    offset += AES_BLOCK_SIZE;
  }

  return 0;
}

int CP_AesCbcDecrypt(AesCbcContext *Context, void const *InBuffer, void *OutBuffer, uint32_t Size)
{

  uint32_t numBlocks = Size / AES_BLOCK_SIZE;
  uint32_t offset = 0;
  uint32_t i;
  uint8_t previousCipherBlock[AES_BLOCK_SIZE];

  if (0 != Size % AES_BLOCK_SIZE)
  {
    // Size not a multiple of AES block size (16 bytes).
    return -1;
  }

  for (i = 0; i < numBlocks; i++)
  {
    // Copy previous cipher block and place current one in context
    memcpy(previousCipherBlock, Context->PreviousCipherBlock, AES_BLOCK_SIZE);
    memcpy(Context->PreviousCipherBlock, (uint8_t *)InBuffer + offset, AES_BLOCK_SIZE);

    // Decrypt cipher block
    API_CP_AesDecrypt(&Context->Aes, Context->PreviousCipherBlock, (uint8_t *)OutBuffer + offset);

    // XOR on previous cipher block
    CP_XorAesBlock((uint8_t *)OutBuffer + offset, previousCipherBlock);

    offset += AES_BLOCK_SIZE;
  }

  return 0;
}

int API_AESCBC_encrypt(unsigned char *plaintext, size_t *len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *ciphertext)
{
	CP_AesCbcInitializeWithKey(&AES_CBC_ctx, key, AES_KEY_SIZE, iv);
	CP_AesCbcEncrypt(&AES_CBC_ctx, plaintext, ciphertext, *len);

	return 1;
}

int API_AESCBC_decrypt(unsigned char *ciphertext, size_t *len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *plaintext)
{
	CP_AesCbcInitializeWithKey(&AES_CBC_ctx, key, AES_KEY_SIZE, iv);
	CP_AesCbcDecrypt(&AES_CBC_ctx, ciphertext, plaintext, *len);

	return 1;
}


// Función que añade padding PKCS#7 para AES
void CP_addPaddingAes(unsigned char *message, size_t *length, unsigned char *padded_message)
{
    // Cálculo de cuántos bytes de padding se necesitan
    // AES_BLOCK_SIZE es el tamaño de bloque de AES, usualmente 16 bytes
    // El padding es la cantidad de bytes necesarios para completar un bloque
    int PadNumber = AES_BLOCK_SIZE - (*length % AES_BLOCK_SIZE);

    // Actualiza la longitud del mensaje original con la nueva longitud (incluyendo el padding)
    *length = *length + PadNumber;

    // Añade el padding al mensaje
    // Se hace un bucle para rellenar con el valor de PadNumber (PKCS#7 padding)
    // PKCS#7 dice que cada byte añadido debe ser igual al número de bytes de padding
    for (int i = 0; i < PadNumber; i++)
    {
        // Inserta el valor de PadNumber en las posiciones finales del mensaje
        // (*length - PadNumber) es el índice donde empieza el padding
        message[(*length - PadNumber) + i] = PadNumber;
    }
}


int CP_getPaddingLength(const unsigned char *padded_message, size_t length) {
    if (length == 0) {
        return -1; // No hay mensaje para revisar
    }
    unsigned char lastByte = padded_message[length - 1]; // Obtiene el último byte, que indica el padding
    if (lastByte > AES_BLOCK_SIZE || lastByte == 0) {
        return -1; // Padding no válido, ya que no puede ser mayor que el tamaño de bloque ni cero
    }

    // Verifica que todos los bytes de padding son iguales al último byte
    for (int i = 0; i < lastByte; i++) {
        if (padded_message[length - 1 - i] != lastByte) {
            return -1; // Padding no válido si algún byte no coincide
        }
    }

    return lastByte; // Retorna la longitud del padding, que es el valor del último byte
}
