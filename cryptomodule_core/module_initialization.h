#ifndef MODULE_INITIALIZATION_H
#define MODULE_INITIALIZATION_H

#include <stdlib.h>
#include <stdint.h>

//TI (TRACKER INDEX) LIST for volatile memory integrity/zeroization
extern uint32_t TI_FS_cipher_key;                           // FS CIPHER key tracker INDEX
extern uint32_t TI_FS_data_buffer;                          // FS AUXILIAR buffer tracker INDEX
extern uint32_t TI_PCA_data_buffer_sed;                     // packet cipher and auth data buffer tracker index
extern uint32_t TI_PCA_data_buffer_sed_aux;                 // packet cipher and auth module auxiliar buffer index
extern uint32_t TI_AES_CBC_ctx;                             // AESCBC CTX tracking index for the struct used to store the derived key
extern uint32_t TI_AESOFB_CTX;                              // AESOFB CTX tracking for the struct used to store the derived key
extern uint32_t TI_AESOFB_outputBlock;                      // tracker index for AESOFB block to xor the plain/cipher text index                   
extern uint32_t TI_AESOFB_ivEnc;                            // tracker index for the encrypted iv for AES_OFB 


#include "../secure_memory_management/file_system.h"
#include "../secure_memory_management/MemoryTracker.h"
#include "packet_cipher_auth.h"
#include "../crypto/AES_CBC.h"
#include "../crypto/AES_OFB.h"

#endif