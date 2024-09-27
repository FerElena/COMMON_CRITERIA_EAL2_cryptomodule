#include "Key_management.h"

current_key_in_use Current_key_in_use = {.IsLoaded = 0};
const char *Keyname_initial = "KEY_ID:";


int API_KM_storekey(uint8_t In_Key[32], size_t key_size, unsigned char *Key_id, size_t Key_id_length)
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
	strncat(keyname, Keyname_initial, sizeof(keyname) - strlen(keyname) - 1);									     // Secure concatenation
	strncat(keyname, (char *)Key_id, Key_id_length < (sizeof(keyname) - strlen(keyname) - 1) ? Key_id_length : (sizeof(keyname) - strlen(keyname) - 1)); // Secure concatenation with bounds check

	// Variables to hold key data and its length
	unsigned char *key_data;
	unsigned int data_length;
	int result = API_FS_read_file_data(keyname, strlen((char *)keyname), &key_data, &data_length);

	if(result != FILESYSTEM_OK){ // error
		return result;
	}
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
	memcpy(Current_key_in_use.keyname, Key_id, Key_id_length);

	// Update the memory tracker for the current key in use
	Current_key_in_use.IsLoaded = 1;
	result = API_MT_update_tracker(&trackers[TI_Current_Key_In_Use]);
	if (result != MT_OK)
	{
		Current_key_in_use.IsLoaded = 0;
		return result;
	}
	return KM_OK;
}

int API_KM_delete_key(unsigned char *Key_id, size_t Key_id_length)
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
    strncat(keyname, Keyname_initial, sizeof(keyname) - strlen(keyname) - 1);  // Secure concatenation
    strncat(keyname, (char *)Key_id, Key_id_length < (sizeof(keyname) - strlen(keyname) - 1) ? Key_id_length : (sizeof(keyname) - strlen(keyname) - 1));  // Secure concatenation with bounds check

    // Delete the file corresponding to the key
    int result = API_FS_delete_file(keyname, strlen((char *)keyname));

    // Check if the file system deletion was successful
    if (result != FILESYSTEM_OK) {
        return result;
    }
    if(memcmp(Key_id,Current_key_in_use.keyname,Key_id_length) == 0){
	API_MM_secure_zeroize(&Current_key_in_use,sizeof(Current_key_in_use));
	Current_key_in_use.IsLoaded = 0;
    }

    return KM_OK;
}
