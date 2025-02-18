/**
 * @file AES_GCM.h
 * @brief File containing all the function headers of the AES_OFB.
 */

 #ifndef AESGCM_H
 #define AESGCM_H
 
 /****************************************************************************************************************
  * Compiler include files
  ****************************************************************************************************************/
 
 #include <string.h>
 #include <stdint.h>
 #include <stdio.h>
 
 /****************************************************************************************************************
  * Private include files
  ****************************************************************************************************************/
 
 #include "AES_CORE.h"

 /**
 * \brief          GCM context structure
 */
typedef struct
{
    AesContext cipher_ctx;       /*!< cipher context used */
    uint64_t HL[16];             /*!< Precalculated HTable */
    uint64_t HH[16];             /*!< Precalculated HTable */
    uint64_t len;                /*!< Total data length */
    uint64_t add_len;            /*!< Total add length */
    unsigned char base_ectr[16]; /*!< First ECTR for tag */
    unsigned char y[16];         /*!< Y working value */
    unsigned char buf[16];       /*!< buf working value */
    int mode;                    /*!< Encrypt or Decrypt */
} GCM_ctx;

static int gcm_gen_table(GCM_ctx *ctx);
int mbedtls_gcm_setkey(GCM_ctx *ctx,const unsigned char *key,unsigned int keybits);
static void gcm_mult(GCM_ctx *ctx, const unsigned char x[16],unsigned char output[16]);
int mbedtls_gcm_starts(GCM_ctx *ctx,int mode,const unsigned char *iv,size_t iv_len,const unsigned char *add,size_t add_len);
int mbedtls_gcm_update(GCM_ctx *ctx,size_t length,const unsigned char *input,unsigned char *output);
int mbedtls_gcm_finish(GCM_ctx *ctx,unsigned char *tag,size_t tag_len);
int mbedtls_gcm_crypt_and_tag(GCM_ctx *ctx,int mode,size_t length,const unsigned char *iv,size_t iv_len,const unsigned char *add,size_t add_len,const unsigned char *input,unsigned char *output,size_t tag_len,unsigned char *tag);
int mbedtls_gcm_auth_decrypt(GCM_ctx *ctx,size_t length,const unsigned char *iv,size_t iv_len,const unsigned char *add,size_t add_len,const unsigned char *tag,size_t tag_len,const unsigned char *input,unsigned char *output);

 #endif