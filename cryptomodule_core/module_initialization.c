#include "module_initialization.h"

int TI_FS_cipher_key;
int TI_FS_data_buffer;
int TI_PCA_data_buffer_sed;
int TI_PCA_data_buffer_sed_aux;
int TI_AES_CBC_ctx;
int TI_AESOFB_CTX;  
int TI_AESOFB_outputBlock; 
int TI_AESOFB_ivEnc;   
int TI_ECDSA_curve_p;
int TI_ECDSA_curve_B;
int TI_ECDSA_curve_G;
int TI_ECDSA_curve_n;
int TI_ECDSA_k;
int TI_ECDSA_l_tmp;
int TI_ECDSA_l_s;
int TI_HMAC256_ihash;
int TI_HMAC256_ohash;
int TI_HMAC256_k;
int TI_HMAC256_k_ipad;
int TI_HMAC256_k_opad;
int TI_HMAC256_sha256_struct;
int TI_HMAC256_sha256_struct;
int TI_SHA256_ctx;

int Memory_tracking_initialization(){
	// array for result returning
	int correct_tracker_init_result[64];
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

	TI_AESOFB_ivEnc = API_MT_add_tracker(&AESOFB_ivEnc,sizeof(AESOFB_ivEnc),CSP); // tracker for the encrypted iv for AES_OFB 
	correct_tracker_init_result[counter++] = TI_AESOFB_ivEnc >= 0 ? 1 : 0;

	TI_ECDSA_curve_p = API_MT_add_tracker(ECDSA_curve_p,sizeof(ECDSA_curve_p),CSP);     //ECDSA_256 CSPs
	correct_tracker_init_result[counter++] = TI_ECDSA_curve_p >= 0 ? 1 : 0;

	TI_ECDSA_curve_B = API_MT_add_tracker(ECDSA_curve_b,sizeof(ECDSA_curve_b),CSP);     //ECDSA_256 CSPs
	correct_tracker_init_result[counter++] = TI_ECDSA_curve_B >= 0 ? 1 : 0;

	TI_ECDSA_curve_G = API_MT_add_tracker(&ECDSA_curve_G,sizeof(ECDSA_curve_G),CSP);     //ECDSA_256 CSPs
	correct_tracker_init_result[counter++] = TI_ECDSA_curve_G >= 0 ? 1 : 0;

	TI_ECDSA_curve_n = API_MT_add_tracker(ECDSA_curve_n,sizeof(ECDSA_curve_n),CSP);     //ECDSA_256 CSPs
	correct_tracker_init_result[counter++] = TI_ECDSA_curve_n >= 0 ? 1 : 0;

	TI_ECDSA_k = API_MT_add_tracker(ECDSA_k,sizeof(ECDSA_k),CSP);                       //ECDSA_256 CSPs
	correct_tracker_init_result[counter++] = TI_ECDSA_k >= 0 ? 1 : 0;

	TI_ECDSA_l_tmp = API_MT_add_tracker(ECDSA_l_tmp,sizeof(ECDSA_l_tmp),CSP);           //ECDSA_256 CSPs
	correct_tracker_init_result[counter++] = TI_ECDSA_l_tmp >= 0 ? 1 : 0;

	TI_ECDSA_l_s = API_MT_add_tracker(ECDSA_l_s,sizeof(ECDSA_l_s),CSP);                 //ECDSA_256 CSPs
	correct_tracker_init_result[counter++] = TI_ECDSA_l_s >= 0 ? 1 : 0;

	TI_HMAC256_ihash = API_MT_add_tracker(HMAC256_ihash,sizeof(HMAC256_ihash),CSP);                 //HMAC-SHA256 CSPs
	correct_tracker_init_result[counter++] = TI_HMAC256_ihash >= 0 ? 1 : 0;

	TI_HMAC256_ohash = API_MT_add_tracker(HMAC256_ohash,sizeof(HMAC256_ohash),CSP);                 //HMAC-SHA256 CSPs
	correct_tracker_init_result[counter++] = TI_HMAC256_ohash >= 0 ? 1 : 0;
	
	TI_HMAC256_k = API_MT_add_tracker(HMAC256_k,sizeof(HMAC256_k),CSP);                 //HMAC-SHA256 CSPs
	correct_tracker_init_result[counter++] = TI_HMAC256_k >= 0 ? 1 : 0;

	TI_HMAC256_k_ipad = API_MT_add_tracker(HMAC256_k_ipad,sizeof(HMAC256_k_ipad),CSP);                 //HMAC-SHA256 CSPs
	correct_tracker_init_result[counter++] = TI_HMAC256_k_ipad >= 0 ? 1 : 0;

	TI_HMAC256_k_opad = API_MT_add_tracker(HMAC256_k_opad,sizeof(HMAC256_k_opad),CSP);                 //HMAC-SHA256 CSPs
	correct_tracker_init_result[counter++] = TI_HMAC256_k_opad >= 0 ? 1 : 0;

	TI_HMAC256_sha256_struct = API_MT_add_tracker(&HMAC256_sha256_struct,sizeof(HMAC256_sha256_struct),CSP);  //HMAC-SHA256 CSPs
	correct_tracker_init_result[counter++] = TI_HMAC256_sha256_struct >= 0 ? 1 : 0;

	TI_SHA256_ctx = API_MT_add_tracker(&SHA256_ctx,sizeof(SHA256_ctx),CSP);  //SHA256 CSPs
	correct_tracker_init_result[counter++] = TI_SHA256_ctx >= 0 ? 1 : 0;




}


int First_init_FS(unsigned char *cryptomodule_instance_name,size_t cryptomodule_instance_length,unsigned char *KeyEncryption_keyfile){

};