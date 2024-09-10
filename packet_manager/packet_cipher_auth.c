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

// Función para cifrar y firmar un paquete de datos.
int API_PCA_sign_encrypt_packet(unsigned char *data_in, size_t data_in_length, unsigned char *key_AES, unsigned char *key_HMAC, unsigned char **out_data, size_t *out_data_length)
{
	int error_management = 0;  // Variable para manejar errores (no usada activamente en este fragmento).
	unsigned char allocated_memory = NOT_ALLOCATED_MEMORY;  // Bandera para gestionar la liberación de memoria asignada dinámicamente.
	unsigned char AES_IV[16];  // Buffer para el vector de inicialización AES.
	unsigned char *sign_out, *aux_buffer_pointer, *out_buffer_pointer;  // Punteros para la firma y los buffers de salida.
	unsigned int padding;  // Variable para el cálculo del padding.
	size_t aux_buffer_length , out_buffer_length , data_in_len_aux;  // Longitudes de los buffers y datos de entrada.

	// Inicialización de variables y punteros a buffers temporales.
	data_in_len_aux = data_in_length;
	out_buffer_pointer = data_buffer_sed;
	aux_buffer_pointer = data_buffer_sed_aux;
	aux_buffer_length = data_in_len_aux + HMAC_SHA256_sign_size;  // Tamaño del buffer auxiliar, incluye tamaño de la firma.
	out_buffer_length = aux_buffer_length + 24;  // Longitud del buffer de salida, incluye espacio extra para el IV y longitud.

	// Cálculo del padding necesario para alinear el tamaño a un múltiplo de 16.
	padding = 16 - (aux_buffer_length % 16);

	// Ajuste de los tamaños de buffer con el padding calculado.
	aux_buffer_length += padding;
	out_buffer_length += padding;
	

	// Generación de la firma HMAC.
	int result1 = API_CP_hmac_sha256(data_in, key_HMAC, data_in_len_aux, HMAC_SHA256_key_size, &sign_out);

	// Asignación de memoria si es necesario.
	if (aux_buffer_length > data_buffer_sign_encrypt_length - 16)
	{
		out_buffer_pointer = API_MM_allocateMem(out_buffer_length); // Asignar memoria para el buffer de salida.
		aux_buffer_pointer = API_MM_allocateMem(aux_buffer_length); // Asignar memoria para el buffer auxiliar.
		allocated_memory = ALLOCATED_MEMORY;
	}
	// Copia de la firma y los datos en el buffer auxiliar.
	memcpy(aux_buffer_pointer, sign_out, HMAC_SHA256_sign_size);
	memcpy(aux_buffer_pointer + HMAC_SHA256_sign_size, data_in, data_in_len_aux);

	// Actualización de la longitud de datos de entrada con el tamaño de la firma.
	data_in_len_aux += HMAC_SHA256_sign_size;

	// Generación del IV para el cifrado AES.
	int result2 = fill_buffer_with_random_bytes(AES_IV, 16);

	// Cifrado de los datos y firma en modo CBC.
	int result3 = API_CP_AESCBC_encrypt(aux_buffer_pointer, &data_in_len_aux, key_AES, AES_KEY_SIZE_256, AES_IV, out_buffer_pointer + 24);

	// Copia del tamaño total y el IV al inicio del buffer de salida.
	memcpy(out_buffer_pointer, &out_buffer_length, 8);
	memcpy(out_buffer_pointer + 8, AES_IV, 16);

	// Asignación del buffer de salida y su longitud a los punteros de salida.
	*out_data = out_buffer_pointer;
	*out_data_length = out_buffer_length;

	// Liberación de memoria si se asignó dinámicamente.
	if (allocated_memory)
		API_MM_freeMem(aux_buffer_pointer);

	return allocated_memory;  // Retorno de éxito.
}

// Función para descifrar un paquete de datos y verificar su firma.
int API_PCA_decrypt_verify_packet(unsigned char *data_in, size_t data_in_length, unsigned char *key_AES, unsigned char *key_HMAC, unsigned char **out_data, size_t *out_data_length, unsigned char *verify)
{
	unsigned char *out_buffer_pointer;  // Puntero al buffer de salida.
	unsigned char allocated_memory = NOT_ALLOCATED_MEMORY;  // Bandera para la gestión de memoria.
	size_t data_len_plaintext;  // Longitud del texto plano después del descifrado.
	size_t data_in_len_aux;  // Longitud ajustada de los datos de entrada.

	// Ajuste de la longitud de los datos de entrada, excluyendo el tamaño y el IV.
	data_in_len_aux = data_in_length - 24;

	// Uso de buffer predeterminado o asignación de memoria si es necesario.
	out_buffer_pointer = data_buffer_sed;
	if (data_in_length > data_buffer_sign_encrypt_length)
	{
		out_buffer_pointer = API_MM_allocateMem(data_in_length);  // Asignar memoria para el buffer de salida.
		allocated_memory = ALLOCATED_MEMORY;
	}

	// Descifrado de los datos.
	int result1 = API_CP_AESCBC_decrypt(data_in + 24, &data_in_len_aux, key_AES, AES_KEY_SIZE_256, data_in + 8, out_buffer_pointer); // +24 para omitir la parte del tamaño y el IV del paquete.

	// Verificación de la firma HMAC.
	int result2 = API_CP_verify_HMAC_SHA256(out_buffer_pointer + HMAC_SHA256_sign_size, key_HMAC, out_buffer_pointer, data_in_len_aux - HMAC_SHA256_sign_size, HMAC_SHA256_key_size, HMAC_SHA256_sign_size, verify);

	// Asignación del puntero al inicio de los datos útiles en el buffer de salida.
	*out_data = out_buffer_pointer;
	*out_data_length = data_in_len_aux;

	return allocated_memory;  // Retorno de éxito.
}
