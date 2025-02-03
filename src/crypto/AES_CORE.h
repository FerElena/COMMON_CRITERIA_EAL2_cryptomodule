/**
 * @file AES_CORE.h
 * @brief File containing all the function headers to interact with AES_CBC tables.
 */

#ifndef AESCORE_H
#define AESCORE_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdint.h>
#include <memory.h>
#include <wmmintrin.h> // for use of hardware AES core in x86 implementations
#include <cpuid.h>     // for checking the support of AES-NI

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

/**
 * @brief AES-128 key size
 *
 */
#define AES_KEY_SIZE_128 16

/**
 * @brief AES-192 key size
 *
 */
#define AES_KEY_SIZE_192 24

/**
 * @brief AES-256 key size
 *
 */
#define AES_KEY_SIZE_256 32

/**
 * @brief AES block size
 *
 */
#define AES_BLOCK_SIZE 16

/**
 * @brief AES context that must be initialized using API_AES_initkey
 *
 * This structure holds the expanded keys and other relevant data for AES
 * encryption and decryption. The context is designed to support both hardware
 * AES-NI implementations and software table-based implementations.
 */
typedef struct AesContext
{
    __m128i HK[27];   /**< Expanded cipher and decipher keys for hardware AES-NI implementations.
                           The __m128i type is used for 128-bit SSE instructions. The array size
                           is sufficient to hold keys for the maximum number of rounds. */
    uint32_t eK[60];  /**< Expanded cipher keys for software table-based implementations.
                           The array size accommodates the maximum key schedule length for AES-256. */
    uint32_t dK[60];  /**< Expanded decipher keys for software table-based implementations.
                           Like eK, this array size is designed for the AES-256 key schedule. */
    uint_fast32_t Nr; /**< Number of rounds for the AES algorithm.
                           The value of Nr depends on the key size: 10 rounds for AES-128,
                           12 rounds for AES-192, and 14 rounds for AES-256. */
} __attribute__((aligned(16))) AesContext;

/**
 * @brief Enumeration to define which AES implementation will be used
 *
 * This enumeration is used during initialization to determine whether to use
 * the software table-based AES implementation or the hardware AES-NI implementation.
 */
typedef enum AES_implementation
{
    still_to_check,           /**< Initial state, yet to be checked */
    software_table_based_aes, /**< Use the software table-based AES implementation */
    hardware_AES_NI           /**< Use the hardware-based AES-NI implementation */
} AES_implementation;

/* Macros............................................................ */
#define Te0(x) TE0[x]
#define Te1(x) TE1[x]
#define Te2(x) TE2[x]
#define Te3(x) TE3[x]

#define Td0(x) TD0[x]
#define Td1(x) TD1[x]
#define Td2(x) TD2[x]
#define Td3(x) TD3[x]

#define BYTE(x, n) (((x) >> (8 * (n))) & 255)

#define STORE32H(x, y)                               \
    {                                                \
        (y)[0] = (unsigned char)(((x) >> 24) & 255); \
        (y)[1] = (unsigned char)(((x) >> 16) & 255); \
        (y)[2] = (unsigned char)(((x) >> 8) & 255);  \
        (y)[3] = (unsigned char)((x) & 255);         \
    }

#define LOAD32H(x, y)                                                                                                                           \
    {                                                                                                                                           \
        x = ((uint32_t)((y)[0] & 255) << 24) | ((uint32_t)((y)[1] & 255) << 16) | ((uint32_t)((y)[2] & 255) << 8) | ((uint32_t)((y)[3] & 255)); \
    }

#define ROL(x, y) ((((uint32_t)(x) << (uint32_t)((y) & 31)) | (((uint32_t)(x) & 0xFFFFFFFFUL) >> (uint32_t)((32 - ((y) & 31)) & 31))) & 0xFFFFFFFFUL)
#define ROR(x, y) (((((uint32_t)(x) & 0xFFFFFFFFUL) >> (uint32_t)((y) & 31)) | ((uint32_t)(x) << (uint32_t)((32 - ((y) & 31)) & 31))) & 0xFFFFFFFFUL)
#define ROLc(x, y) ((((uint32_t)(x) << (uint32_t)((y) & 31)) | (((uint32_t)(x) & 0xFFFFFFFFUL) >> (uint32_t)((32 - ((y) & 31)) & 31))) & 0xFFFFFFFFUL)
#define RORc(x, y) (((((uint32_t)(x) & 0xFFFFFFFFUL) >> (uint32_t)((y) & 31)) | ((uint32_t)(x) << (uint32_t)((32 - ((y) & 31)) & 31))) & 0xFFFFFFFFUL)

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief Function to check if AES-NI assembly instructions are supported in this machine core.
 *
 * This function uses the CPUID instruction to check if the processor supports
 * AES-NI (Advanced Encryption Standard New Instructions). The support for AES-NI
 * is indicated by bit 25 in the ECX register when calling CPUID with EAX set to 1.
 *
 * @return Returns 1 if AES-NI is supported, 0 otherwise.
 */
int supportsAESNI();

/**
 * @brief AES-128 key expansion using AES-NI instructions
 *
 * This function performs AES-128 key expansion for hardware-based AES-NI implementation.
 * It generates the round keys for both encryption and decryption.
 *
 * @param key The original 128-bit AES key
 * @param ks  The key schedule array where the expanded keys are stored
 */
void aes128_aesni_key_expansion(const uint8_t *key, __m128i *ks);

/**
 * @brief AES-192 key expansion using AES-NI instructions
 *
 * This function performs AES-192 key expansion for hardware-based AES-NI implementation.
 * It generates the round keys for both encryption and decryption.
 *
 * @param key The original 192-bit AES key
 * @param ks  The key schedule array where the expanded keys are stored
 */
void aes192_aesni_key_expansion(const uint8_t *key, __m128i *ks);

/**
 * @brief AES-256 key expansion using AES-NI instructions
 *
 * This function performs AES-256 key expansion for hardware-based AES-NI implementation.
 * It generates the round keys for both encryption and decryption.
 *
 * @param key The original 256-bit AES key
 * @param ks  The key schedule array where the expanded keys are stored
 */
void aes256_aesni_key_expansion(const uint8_t *key, __m128i *ks);

/**
 * @brief Key expansion for AES using AES-NI instructions
 *
 * This function performs key expansion for AES based on the provided key size.
 * It initializes the number of rounds and generates the round keys for encryption
 * and decryption using AES-NI instructions.
 *
 * @param Context Pointer to the AES context to be initialized
 * @param Key Pointer to the original AES key
 * @param KeySize Size of the AES key in bits (128, 192, or 256)
 */
void aes_ni_keyexpansion(AesContext* Context, void const* Key, uint32_t KeySize);

/**
 * @brief Encrypt a plaintext block using AES-NI instructions
 *
 * This function encrypts a single block of plaintext using the provided key
 * schedule and number of rounds. It uses AES-NI instructions for accelerated
 * encryption.
 *
 * @param ks Key schedule array
 * @param rounds Number of encryption rounds
 * @param plaintext Pointer to the plaintext block to be encrypted
 * @param ciphertext Pointer to the buffer where the encrypted ciphertext block will be stored
 */
void aes_aesni_encrypt(const __m128i *ks, int rounds, const uint8_t *plaintext, uint8_t *ciphertext);

/**
 * @brief Decrypt a ciphertext block using AES-NI instructions
 *
 * This function decrypts a single block of ciphertext using the provided key
 * schedule and number of rounds. It uses AES-NI instructions for accelerated
 * decryption.
 *
 * @param ks Key schedule array
 * @param rounds Number of decryption rounds
 * @param ciphertext Pointer to the ciphertext block to be decrypted
 * @param plaintext Pointer to the buffer where the decrypted plaintext block will be stored
 */
void aes_aesni_decrypt(const __m128i *ks, int rounds, const uint8_t *ciphertext, uint8_t *plaintext);

/**
 * @brief Key expansion for AES using table-based implementation
 *
 * This function performs key expansion for AES using a software table-based
 * implementation. It initializes the expanded keys for both encryption and
 * decryption based on the provided key size.
 *
 * @param Context Pointer to the AES context to be initialized
 * @param Key Pointer to the original AES key
 * @param KeySize Size of the AES key in bits (128, 192, or 256)
 */
void aes_table_key_expansion(AesContext* Context, void const* Key, uint32_t KeySize);

/**
 * @brief Encrypt a block of data using table-based AES implementation
 *
 * This function performs AES encryption on a single block of plaintext using
 * a table-based implementation. It uses the provided AES context, which contains
 * the expanded keys, to encrypt the input block and produce the output block.
 *
 * @param Context Pointer to the AES context containing the expanded keys
 * @param Input Pointer to the plaintext block to be encrypted
 * @param Output Pointer to the buffer where the encrypted ciphertext block will be stored
 */
void aes_table_encrypt(AesContext const* Context, uint8_t const Input [AES_BLOCK_SIZE], uint8_t Output [AES_BLOCK_SIZE]);

/**
 * @brief Decrypt a block of data using table-based AES implementation
 *
 * This function performs AES decryption on a single block of ciphertext using
 * a table-based implementation. It uses the provided AES context, which contains
 * the expanded keys, to decrypt the input block and produce the output block.
 *
 * @param Context Pointer to the AES context containing the expanded keys
 * @param Input Pointer to the ciphertext block to be decrypted
 * @param Output Pointer to the buffer where the decrypted plaintext block will be stored
 */
void aes_table_decrypt(AesContext const* Context, uint8_t const Input [AES_BLOCK_SIZE], uint8_t Output [AES_BLOCK_SIZE]);

/**
 * @brief Function to check hardware support for AES-NI and set the appropriate AES implementation
 *
 * This function checks if the processor supports AES-NI (Advanced Encryption Standard New Instructions)
 * using the `supportsAESNI` function. It sets the global variable `AES_implement` to either
 * `hardware_AES_NI` if AES-NI is supported or `software_table_based_aes` if it is not.
 *
 * @return The AES implementation being used (hardware_AES_NI or software_table_based_aes)
 */
int API_AES_checkHWsupport();

/**
 * @brief Initializes an AES context with an AES Key.
 *
 *
 * @param Context AES struct that contains the context
 * @param Key AES key
 * @param KeySize AES key size
 * @return Returns a 0 if the function was successfull
 *
 * @errors
 * @error{ ERROR 1, Return -1 if the key size is incorrect}
 */
int API_AES_initkey(AesContext *Context, void const *Key, uint32_t KeySize);

/**
 * @brief Performs an AES encryption of one block (128 bits) with an AES context
 *
 *
 * @param Context AES context
 * @param Input Input for the function AES to be encrypted
 * @param Output AES output encrypted
 */
void API_AES_encrypt_block(AesContext const *Context, uint8_t const Input[AES_BLOCK_SIZE], uint8_t Output[AES_BLOCK_SIZE]);

/**
 * @brief Performs an AES decryption of one block (128 bits) with an AES context
 *
 *
 * @param Context AES context
 * @param Input Input for the function AES to be decrypted
 * @param Output AES output decrypted
 */
void API_AES_decrypt_block(AesContext const *Context, uint8_t const Input[AES_BLOCK_SIZE], uint8_t Output[AES_BLOCK_SIZE]);

#endif