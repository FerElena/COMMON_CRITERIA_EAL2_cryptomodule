#include "module_initialization.h"

uint32_t TI_FS_cipher_key;
uint32_t TI_FS_data_buffer;
uint32_t TI_PCA_data_buffer_sed;
uint32_t TI_PCA_data_buffer_sed_aux;
uint32_t TI_AES_CBC_ctx;
uint32_t TI_AESOFB_CTX;  
uint32_t TI_AESOFB_outputBlock; 
uint32_t TI_AESOFB_ivEnc;       


int Memory_tracking_initialization(){
	// array for result returning
	uint8_t correct_tracker_init_result[64];
	uint32_t counter = 0;
	for(int i = 0; i < sizeof(correct_tracker_init_result) / sizeof(correct_tracker_init_result[0]); correct_tracker_init_result[i++] = 1); //initialize array with 1s
	//initialize the memory tracker pointers
	API_MT_initialize_trackers();
	//initialize trackers
	TI_FS_cipher_key = API_MT_add_tracker(FS_cipher_key,sizeof(FS_cipher_key),CSP); // FS cipher key TRACKER
	correct_tracker_init_result[counter++] = TI_FS_cipher_key >= 0 ? 1 : 0;

	TI_FS_data_buffer = API_MT_add_tracker(FS_data_buffer,sizeof(FS_data_buffer),CSP); // FS auxiliar buffer  TRACKER
	correct_tracker_init_result[counter++] = TI_FS_data_buffer >= 0 ? 1 : 0;

	TI_PCA_data_buffer_sed = API_MT_add_tracker(PCA_data_buffer_sed,sizeof(PCA_data_buffer_sed),CSP); //packet cipher and auth module buffer
	correct_tracker_init_result[counter++] = TI_PCA_data_buffer_sed >= 0 ? 1 : 0;

	TI_PCA_data_buffer_sed_aux = API_MT_add_tracker(PCA_data_buffer_sed_aux,sizeof(PCA_data_buffer_sed_aux),CSP); //packet cipher and auth module auxiliar buffer
	correct_tracker_init_result[counter++] = TI_PCA_data_buffer_sed_aux >= 0 ? 1 : 0;

	TI_AES_CBC_ctx = API_MT_add_tracker(&AES_CBC_ctx,sizeof(AES_CBC_ctx),CSP); // AESCBC CTX tracking for the struct used to store the derived key
	correct_tracker_init_result[counter++] = TI_AES_CBC_ctx >= 0 ? 1 : 0;

	TI_AESOFB_CTX = API_MT_add_tracker(&AESOFB_CTX,sizeof(AESOFB_CTX),CSP); // AESOFB CTX tracking for the struct used to store the derived key
	correct_tracker_init_result[counter++] = TI_AESOFB_CTX >= 0 ? 1 : 0;
	
	TI_AESOFB_outputBlock = API_MT_add_tracker(&AESOFB_outputBlock,sizeof(AESOFB_outputBlock),CSP); // tracker for AESOFB block to xor the plain/cipher text index  
	correct_tracker_init_result[counter++] = TI_AESOFB_outputBlock >= 0 ? 1 : 0; 

	TI_AESOFB_ivEnc = API_MT_add_tracker(&AESOFB_ivEnc,sizeof(AESOFB_ivEnc),CSP); // tracker index for the encrypted iv for AES_OFB 
	correct_tracker_init_result[counter++] = TI_AESOFB_ivEnc >= 0 ? 1 : 0;

}


int First_init_FS(unsigned char *cryptomodule_instance_name,size_t cryptomodule_instance_length,unsigned char *KeyEncryption_keyfile){

};