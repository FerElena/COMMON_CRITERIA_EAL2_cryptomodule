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
unsigned char PCA_data_buffer_sed_aux[data_buffer_sign_encrypt_length];

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

	int error_management = 0;					   // Variable for error handling (not actively used in this fragment).
	unsigned char allocated_memory = NOT_ALLOCATED_MEMORY;		   // Flag to manage dynamically allocated memory release.
	unsigned char AES_IV[16];					   // Buffer for AES initialization vector.
	unsigned char *sign_out, *aux_buffer_pointer, *out_buffer_pointer; // Pointers for the signature and output buffers.
	unsigned int padding;						   // Variable for padding calculation.
	size_t aux_buffer_length, out_buffer_length, data_in_len_aux;	   // Buffer and input data lengths.

	// Initialize variables and temporary buffer pointers.
	data_in_len_aux = data_in_length;
	out_buffer_pointer = PCA_data_buffer_sed;
	aux_buffer_pointer = PCA_data_buffer_sed_aux;
	aux_buffer_length = data_in_len_aux + HMAC_SHA256_sign_size;   // Aux buffer size, includes signature size.
	out_buffer_length = aux_buffer_length + IV_size_header_length; // Output buffer length, includes extra space for IV and length.

	// Calculate the padding needed to align the size to a multiple of 16.
	padding = 16 - (aux_buffer_length % 16);

	// Adjust buffer sizes with the calculated padding.
	aux_buffer_length += padding;
	out_buffer_length += padding;

	// Generate HMAC signature.
	int result1 = API_CP_hmac_sha256(data_in, key_HMAC, data_in_len_aux, HMAC_SHA256_key_size, &sign_out);

	// Allocate memory if necessary.
	if (aux_buffer_length > data_buffer_sign_encrypt_length - 16)
	{
		out_buffer_pointer = API_MM_allocateMem(out_buffer_length); // Allocate memory for output buffer.
		aux_buffer_pointer = API_MM_allocateMem(aux_buffer_length); // Allocate memory for aux buffer.
		allocated_memory = ALLOCATED_MEMORY;
	}
	// Copy the signature and data into the aux buffer.
	memcpy(aux_buffer_pointer, sign_out, HMAC_SHA256_sign_size);
	memcpy(aux_buffer_pointer + HMAC_SHA256_sign_size, data_in, data_in_len_aux);

	// Update input data length to include the signature size.
	data_in_len_aux += HMAC_SHA256_sign_size;

	// Generate IV for AES encryption.
	int result2 = API_RNG_fill_buffer_random(AES_IV, 16);

	// Encrypt the data and signature using AES in CBC mode.
	int result3 = API_CP_AESCBC_encrypt(aux_buffer_pointer, &data_in_len_aux, key_AES, AES_KEY_SIZE_256, AES_IV, out_buffer_pointer + IV_size_header_length);

	// Copy the total size and IV to the beginning of the output buffer.
	size_t copysize = out_buffer_length;
	for (int i = 7; i >= 0; i--)
	{
		out_buffer_pointer[i] = (unsigned char)(copysize & 0xFF);
		copysize >>= 8;
	}
	memcpy(out_buffer_pointer + 8, AES_IV, 16);

	// Assign the output buffer and its length to the output pointers.
	*out_data = out_buffer_pointer;
	*out_data_length = out_buffer_length;

	// Free memory if dynamically allocated.
	if (allocated_memory)
		API_MM_freeMem(aux_buffer_pointer);

	return allocated_memory; // Return success.
}

// Function to decrypt a data packet and verify its signature.
int API_PCA_decrypt_verify_packet(unsigned char *data_in, size_t data_in_length, unsigned char *key_AES, unsigned char *key_HMAC, unsigned char **out_data, size_t *out_data_length, unsigned char *verify)
{
	if (API_SM_get_current_state() != STATE_CRYPTOGRAPHIC)
	{
		return SM_ERROR_STATE; // Return error if not operational
	}
	unsigned char *out_buffer_pointer;		       // Pointer to the output buffer.
	unsigned char allocated_memory = NOT_ALLOCATED_MEMORY; // Flag for memory management.
	size_t data_len_packet;				       // Length of the plaintext after decryption.
	size_t data_in_len_aux;				       // Adjusted input data length.

	for (int i = 0; i < 8; i++)
	{
		data_len_packet = (data_len_packet << 8) | data_in[i];
	}

	if (data_len_packet != data_in_length)
	{
		return SM_ERROR_STATE; // Return error if not operational
	}
	// Adjust the input data length, excluding the size and IV.
	data_in_len_aux = data_in_length - IV_size_header_length;

	// Use default buffer or allocate memory if necessary.
	out_buffer_pointer = PCA_data_buffer_sed;
	if (data_in_length > data_buffer_sign_encrypt_length)
	{
		out_buffer_pointer = API_MM_allocateMem(data_in_length); // Allocate memory for the output buffer.
		allocated_memory = ALLOCATED_MEMORY;
	}

	// Decrypt the data.
	int result1 = API_CP_AESCBC_decrypt(data_in + IV_size_header_length, &data_in_len_aux, key_AES, AES_KEY_SIZE_256, data_in + 8, out_buffer_pointer); // +24 to skip the size and IV parts.

	// Verify the HMAC signature.
	int result2 = API_CP_verify_HMAC_SHA256(out_buffer_pointer + HMAC_SHA256_sign_size, key_HMAC, out_buffer_pointer, data_in_len_aux - HMAC_SHA256_sign_size, HMAC_SHA256_key_size, HMAC_SHA256_sign_size, verify);

	// Assign the output pointer to the start of the useful data in the buffer.
	*out_data = out_buffer_pointer + HMAC_SHA256_sign_size;
	*out_data_length = data_in_len_aux - HMAC_SHA256_sign_size;

	return allocated_memory; // Return success.
}
