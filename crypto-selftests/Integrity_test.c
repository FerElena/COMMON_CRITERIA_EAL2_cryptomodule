#include "Integrity_test.h"

#include <stdio.h>
#include <stdlib.h>

// Function to load the program's own binary into a buffer
int load_self_binary_to_buffer(unsigned char **buffer, size_t *buffer_size)
{
	// Maximum buffer size (4MB)
	size_t max_size = 4 * 1024 * 1024; // 4MB

	// Open the program's own binary using /proc/self/exe
	FILE *file = fopen("/proc/self/exe", "rb");
	if (file == NULL)
	{
		return -1;
	}
	// Allocate memory for the buffer
	*buffer = (unsigned char *)API_MM_allocateMem(max_size);
	if (*buffer == NULL)
	{
		fclose(file);
		return -1;
	}
	// Read the binary content into the buffer
	*buffer_size = fread(*buffer, 1, max_size, file);
	if (ferror(file))
	{
		free(*buffer);
		fclose(file);
		return -1;
	}
	// Close the file
	fclose(file);
	return 0;
}

int API_SFT_check_module_integrity()
{
    // Buffer to store the module binary and the public key signature
    unsigned char *buffer_integrity = NULL;
    unsigned char *sign_pubkey = NULL;
    
    // Size variables for buffers
    size_t bufferintegrity_size = 0;
    unsigned int sign_pubkey_size = 0;
    
    // Hash buffer (SHA-256 produces 32 bytes)
    uint8_t hash[32];
    
    // Load the current binary into buffer
    if (load_self_binary_to_buffer(&buffer_integrity, &bufferintegrity_size) != 0) {
        return INTEGRITY_ERROR;
    }

    // Load the signature and public key from the file
    int result = API_FS_read_file_data(CERT_FILENAME, strlen(CERT_FILENAME), &sign_pubkey, &sign_pubkey_size);
    if (result != FILESYSTEM_OK) {
        return INTEGRITY_ERROR;
    }

    // Compute the SHA-256 hash of the binary buffer
    API_sha256(buffer_integrity, bufferintegrity_size, hash);

    // Verify the signature using the public key (signature is assumed to be at the end of sign_pubkey)
    result = API_ecdsa_verify(sign_pubkey + 64, hash, sign_pubkey); // Assuming 64-byte signature
    if (result != 1) {
        return INTEGRITY_ERROR;
    }

    // If everything is correct, return INTEGRITY_OK
    return INTEGRITY_OK;
}
