#ifndef MODULE_INITIALIZATION_H
#define MODULE_INITIALIZATION_H

#include <stdlib.h>
#include <stdint.h>


#include "../secure_memory_management/file_system.h"
#include "../secure_memory_management/MemoryTracker.h"
#include "packet_cipher_auth.h"
#include "../crypto/AES_CBC.h"
#include "../crypto/AES_OFB.h"
#include "../crypto/ECDSA_256.h"
#include "../crypto/SHA256.h"

//TI (TRACKER INDEX) LIST for volatile memory integrity/zeroization
extern int TI_FS_cipher_key;                           // FS CIPHER key tracker INDEX
extern int TI_FS_data_buffer;                          // FS AUXILIAR buffer tracker INDEX
extern int TI_PCA_data_buffer_sed;                     // packet cipher and auth data buffer tracker index
extern int TI_PCA_data_buffer_sed_aux;                 // packet cipher and auth module auxiliar buffer index

//AES CSPs parameters
extern int TI_AES_CBC_ctx;                             // AESCBC CTX tracking index for the struct used to store the derived key
extern int TI_AESOFB_CTX;                              // AESOFB CTX tracking for the struct used to store the derived key
extern int TI_AESOFB_outputBlock;                      // tracker index for AESOFB block to xor the plain/cipher text index                   
extern int TI_AESOFB_ivEnc;                            // tracker index for the encrypted iv for AES_OFB 

//index parameters for ECDSA256 operations with private keys
extern int TI_ECDSA_curve_p;
extern int TI_ECDSA_curve_B;
extern int TI_ECDSA_curve_G;
extern int TI_ECDSA_curve_n;
extern int TI_ECDSA_k;
extern int TI_ECDSA_l_tmp;
extern int TI_ECDSA_l_s;

//index parameters for HMAC-SHA256 operations with secret keys
extern int TI_HMAC256_ihash;
extern int TI_HMAC256_ohash;
extern int TI_HMAC256_k;
extern int TI_HMAC256_k_ipad;
extern int TI_HMAC256_k_opad;
extern int TI_HMAC256_sha256_struct;

//index parameters for SHA-256
extern int TI_SHA256_ctx;



int Memory_tracking_initialization();

#endif