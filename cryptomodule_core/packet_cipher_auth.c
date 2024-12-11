/**
 * @file packet_cipher_auth.c
 * @brief File containing all the functions for the cryptographic library packet cipher and encryption
 */

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/
#include "packet_cipher_auth.h"

/****************************************************************************************************************
 * Global variables definition
 ****************************************************************************************************************/
unsigned char PCA_data_buffer_sed[data_buffer_sign_encrypt_length]; // 256 kilobytes of static memory to avoid memory allocation every time CSP is used

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

// Function to encrypt and sign a data packet.
int API_PCA_sign_encrypt_packet(unsigned char *data_in, size_t data_in_length, unsigned char *key_AES, unsigned char *key_HMAC, unsigned char **out_data, size_t *out_data_length)
{
	if (API_SM_get_current_state() != STATE_CRYPTOGRAPHIC)
	{
		return SM_ERROR_STATE; // Return error if not operational
	}

	unsigned char allocated_memory ;     		   // Flag to manage dynamically allocated memory release.
	unsigned char AES_IV[16];					   // Buffer for AES initialization vector.
	unsigned char *sign_out, *out_buffer_pointer;  // Pointers for the signature and output buffers.
	unsigned int padding;						   // Variable for padding calculation.
	size_t out_buffer_length, data_in_len_aux;	   // Buffer and input data lengths.

	// Initialize variables and temporary buffer pointers.
	out_buffer_pointer = PCA_data_buffer_sed;
	allocated_memory = NOT_ALLOCATED_MEMORY;
	
	data_in_len_aux = data_in_length;
	out_buffer_length = data_in_length + IV_SIZE_HEADER_LENGTH + HMAC_SHA256_SIGN_SIZE; // Output buffer length, includes extra space for IV and length.

	// Calculate the padding needed to align the size to a multiple of 16.
	padding = 16 - (data_in_length % 16);

	// Adjust buffer sizes with the required size for padding
	out_buffer_length += padding;

	// Allocate memory if necessary.
	if (out_buffer_length > data_buffer_sign_encrypt_length )
	{
		out_buffer_pointer = API_MM_allocateMem(out_buffer_length); // Allocate memory for output buffer.
		allocated_memory = ALLOCATED_MEMORY;
	}
	// Generate IV for AES encryption.
	int result1 = API_RNG_fill_buffer_random(AES_IV, 16);
	if(result1 == RNG_RANDOM_GENERATION_FAILED){
		if(allocated_memory == ALLOCATED_MEMORY){
			API_MM_freeMem(out_buffer_pointer);
		}
		return RNG_RANDOM_GENERATION_FAILED;
	}

	// Encrypt the data and signature using AES in CBC mode.
	int result2 = API_CP_AESCBC_encrypt(data_in, &data_in_len_aux, key_AES, AES_KEY_SIZE_256, AES_IV, out_buffer_pointer + IV_SIZE_HEADER_LENGTH);

	// Copy the total size and IV to the beginning of the output buffer.
	size_t copysize = out_buffer_length;
	for (int i = 7; i >= 0; i--)
	{
		out_buffer_pointer[i] = (unsigned char)(copysize & 0xFF);
		copysize >>= 8;
	}
	memcpy(out_buffer_pointer + 8, AES_IV, 16);

	// Generate HMAC signature.
	int result3 = API_CP_hmac_sha256(out_buffer_pointer, key_HMAC, data_in_len_aux + IV_SIZE_HEADER_LENGTH, HMAC_SHA256_KEY_SIZE, &sign_out);
	// copy HMAC signature at the end of the packet
	memcpy(out_buffer_pointer + data_in_len_aux + IV_SIZE_HEADER_LENGTH,sign_out,HMAC_SHA256_SIGN_SIZE);

	// Assign the output buffer and its length to the output pointers.
	*out_data = out_buffer_pointer;
	*out_data_length = out_buffer_length;

	return allocated_memory; // Return success.
}

// Function to decrypt a data packet and verify its signature.
int API_PCA_decrypt_verify_packet(unsigned char *data_in, size_t data_in_length, unsigned char *key_AES, unsigned char *key_HMAC, unsigned char **out_data, size_t *out_data_length, unsigned char *verify)
{
	if (API_SM_get_current_state() != STATE_CRYPTOGRAPHIC)
	{
		return SM_ERROR_STATE; // Return error if not operational
	}
	unsigned char *out_buffer_pointer;	       // Pointer to the output buffer.
	unsigned char allocated_memory ;           // Flag for memory management.
	size_t data_len_packet;				       // Length of the plaintext after decryption.
	size_t data_in_len_aux;				       // Adjusted input data length.

	// Initialize variables and temporary buffer pointers.
	out_buffer_pointer = PCA_data_buffer_sed;
	allocated_memory = NOT_ALLOCATED_MEMORY; 

	for (int i = 0; i < 8; i++)
	{
		data_len_packet = (data_len_packet << 8) | data_in[i];
	}

	if (data_len_packet != data_in_length)
	{
		return MAC_NOT_VERIFIED; // Return error if not operational
	}
	// auxiliar length corresponding to the entire packet excluding HMAC signature
	data_in_len_aux = data_len_packet - HMAC_SHA256_SIGN_SIZE;

	// verify HMAC signature
	int result1 = API_CP_verify_HMAC_SHA256(data_in,key_HMAC,data_in + data_in_len_aux,data_in_len_aux,HMAC_SHA256_KEY_SIZE,HMAC_SHA256_SIGN_SIZE,verify);

	//if packet not verified, stop the operation
	if(!(*verify)){
		return MAC_NOT_VERIFIED;
	}

	//adjust new length for only the ciphertext
	data_in_len_aux -= IV_SIZE_HEADER_LENGTH;
	//allocate more memory if necesary for decryption
	if (data_in_len_aux > data_buffer_sign_encrypt_length)
	{
		out_buffer_pointer = API_MM_allocateMem(data_in_len_aux); // Allocate memory for the output buffer.
		allocated_memory = ALLOCATED_MEMORY;
	}

	//decipher the ciphertext
	int result2 = API_CP_AESCBC_decrypt(data_in + IV_SIZE_HEADER_LENGTH, &data_in_len_aux, key_AES, AES_KEY_SIZE_256, data_in + 8, out_buffer_pointer); // data in +8 to acced IV

	// assign output parameters
	*out_data = out_buffer_pointer;
	*out_data_length = data_in_len_aux;

	return allocated_memory; // Return success.
}
