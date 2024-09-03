/**
 * @file packet_cipher_auth.c
 * @brief File containing all the functions for the cryptographic library packet cipher and encrypt
 */

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/
#include "packet_cipher_auth.h"  

/****************************************************************************************************************
 * Global variables definition
 ****************************************************************************************************************/
unsigned char data_buffer_sed[data_buffer_sign_encrypt_length]; // 256 kilobytes of static memory so it is not necesary to allocate memory all time CSP
								// stands for data buffer sign encrypt decrypt
unsigned char data_buffer_sed_aux[data_buffer_sign_encrypt_length]; 

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

int API_PCA_sign_encrypt_packet(unsigned char *data_in, size_t data_in_length, unsigned char *key_AES, unsigned char *key_HMAC, unsigned char **out_data, size_t *out_data_length)
{
	int error_management = 0;
	unsigned char allocated_memory = NOT_ALLOCATED_MEMORY;
	unsigned char AES_IV[16];
	unsigned char *sign_out, *aux_buffer_pointer, *out_buffer_pointer;
	unsigned int padding;
	size_t aux_buffer_length , out_buffer_length , data_in_len_aux; 

	data_in_len_aux = data_in_length;
	out_buffer_pointer = data_buffer_sed;
	aux_buffer_pointer = data_buffer_sed_aux;
	aux_buffer_length = data_in_len_aux + HMAC_SHA256_sign_size;
	out_buffer_length = aux_buffer_length + 24;

	padding = 16 - (aux_buffer_length % 16);

	if (padding != 16)
	{
		aux_buffer_length += padding;
		out_buffer_length += padding;
	}

	int result1  = API_CP_hmac_sha256(data_in, key_HMAC, data_in_len_aux, HMAC_SHA256_key_size, &sign_out);

	if (aux_buffer_length > data_buffer_sign_encrypt_length - 16 )
	{
		out_buffer_pointer = API_MM_allocateMem(out_buffer_length); // 24 extra out bytes, 8 for size, and 16 for iv
		aux_buffer_pointer = API_MM_allocateMem(aux_buffer_length);
		allocated_memory = ALLOCATED_MEMORY;
	}
	
	memcpy(aux_buffer_pointer,sign_out,HMAC_SHA256_sign_size);
	memcpy(aux_buffer_pointer + HMAC_SHA256_sign_size,data_in,data_in_len_aux);

	data_in_len_aux += HMAC_SHA256_sign_size;

	int result2 = fill_buffer_with_random_bytes(AES_IV,16);

	int result3 = API_CP_AESCBC_encrypt(aux_buffer_pointer, &data_in_len_aux,key_AES,AES_KEY_SIZE_256,AES_IV,out_buffer_pointer + 24);

	memcpy(out_buffer_pointer,&out_buffer_length,8);
	memcpy(out_buffer_pointer+8,AES_IV,16);

	*out_data = out_buffer_pointer;
	*out_data_length = out_buffer_length;

	if(allocated_memory)
		API_MM_freeMem(aux_buffer_pointer);

	return 1;
}

int API_PCA_decrypt_verify_packet(unsigned char *data_in, size_t data_in_length, unsigned char *key_AES, unsigned char *key_HMAC, unsigned char **out_data ,unsigned char *verify){
	unsigned char *out_buffer_pointer;
	unsigned char allocated_memory = NOT_ALLOCATED_MEMORY;
	size_t data_len_plaintext;
	size_t data_in_len_aux ;

	data_in_len_aux = data_in_length - 24;

	out_buffer_pointer = data_buffer_sed;

	if(data_in_length > data_buffer_sign_encrypt_length){
		out_buffer_pointer = API_MM_allocateMem(data_in_length);
		allocated_memory = ALLOCATED_MEMORY;
	}

	int result1 = API_CP_AESCBC_decrypt(data_in + 24 ,&data_in_len_aux,key_AES,AES_KEY_SIZE_256,data_in + 8,out_buffer_pointer); // +24 to skip size and iv part of the packet

	printf("\n");
	int result2 = API_CP_verify_HMAC_SHA256(out_buffer_pointer+ HMAC_SHA256_sign_size,key_HMAC , out_buffer_pointer ,data_in_len_aux - HMAC_SHA256_sign_size,
			HMAC_SHA256_key_size,HMAC_SHA256_sign_size,verify);

	*out_data = out_buffer_pointer;

	return 1;
}