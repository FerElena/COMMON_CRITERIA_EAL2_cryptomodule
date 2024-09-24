#include "Key_management.h"

current_key_in_use Current_key_in_use;
const char *Keyname_initial = "KEY_";

int API_KM_storekey(unsigned char In_Key[32], size_t key_size, unsigned char *Key_id, size_t Key_id_length)
{
	// Check if the current state is CSP, required for key management operations
	if (API_SM_get_current_state() != STATE_CSP)
	{
		return SM_ERROR_STATE;
	}

	// Validate input parameters
	if (In_Key == NULL || key_size > AES_KEY_SIZE_256 || Key_id == NULL || Key_id_length > MAXLENGTH_KEYID)
	{
		return KM_PARAMETERS_ERROR;
	}

	// Ensure the Key ID contains only alphanumeric characters
	for (size_t i = 0; i < Key_id_length; i++)
	{
		if (!isalnum(Key_id[i]))
		{
			return KM_PARAMETERS_ERROR;
		}
	}

	// Construct the file name with the prefix "KEY_"
	unsigned char keyname[MAX_FILENAME_LENGTH] = {0};
	strncat(keyname, Keyname_initial, sizeof(keyname) - strlen(keyname) - 1);									     // Secure concatenation
	strncat(keyname, (char *)Key_id, Key_id_length < (sizeof(keyname) - strlen(keyname) - 1) ? Key_id_length : (sizeof(keyname) - strlen(keyname) - 1)); // Secure concatenation with bounds check

	// Store the key securely in the file system
	int result = API_FS_create_file_data(keyname, strlen((char *)keyname), In_Key, key_size, IS_CSP);

	// Check for file system operation success
	if (result != FILESYSTEM_OK)
	{
		return result;
	}
	return KM_OK;
}

int API_KM_loadkey(unsigned char *Key_id, size_t Key_id_length)
{
	// Check if the current state is CSP, required for key management operations
	if (API_SM_get_current_state() != STATE_CSP)
	{
		return SM_ERROR_STATE;
	}

	// Validate input parameters
	if (Key_id == NULL || Key_id_length > MAXLENGTH_KEYID)
	{
		return KM_PARAMETERS_ERROR;
	}

	// Construct the file name with the prefix "KEY_"
	unsigned char keyname[MAX_FILENAME_LENGTH] = {0};
	const char *Keyname_initial = "KEY_";
	strncat(keyname, Keyname_initial, sizeof(keyname) - strlen(keyname) - 1);									     // Secure concatenation
	strncat(keyname, (char *)Key_id, Key_id_length < (sizeof(keyname) - strlen(keyname) - 1) ? Key_id_length : (sizeof(keyname) - strlen(keyname) - 1)); // Secure concatenation with bounds check

	// Variables to hold key data and its length
	unsigned char *key_data;
	unsigned int data_length;
	int result = API_FS_read_file_data(keyname, strlen((char *)keyname), &key_data, &data_length);

	// Check if the loaded key size matches the expected AES-256 key size
	if (data_length != AES_KEY_SIZE_256)
	{
		return KM_PARAMETERS_ERROR;
	}

	// Copy the loaded key data to the current key structure
	memcpy(Current_key_in_use.Main_key, key_data, data_length);

	// Derive complex keys from the main key
	API_KDF_derive_complex_key(Current_key_in_use.Main_key, Current_key_in_use.Cipher_key, Current_key_in_use.Auth_key);

	// Store the key name in the current key structure
	memcpy(Current_key_in_use.keyname, keyname, strlen((char *)keyname));

	// Update the memory tracker for the current key in use
	result = API_MT_update_tracker(&trackers[TI_Current_Key_In_Use]);
	if (result != MT_OK)
	{
		return result;
	}

	return KM_OK;
}
