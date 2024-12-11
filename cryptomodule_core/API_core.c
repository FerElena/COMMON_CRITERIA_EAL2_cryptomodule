/**
 * @file API_core.c
 * @brief File containing all the function implementations of the API_core
 */

#include "API_core.h"

int API_MC_getcurrent_state()
{ // returns current state
    return API_SM_get_current_state();
}

int API_MC_Initialize_module(unsigned char *KEK_CERTIFICATE_file, unsigned char *Cryptodata_filename)
{ // FALTA IMPLEMENTAR MÁQUINA DE ESTADOS
    int Operation_result = 0;

    // Change the state to ON and begin initialization
    API_SM_State_Change(STATE_ON);
    API_SM_State_Change(STATE_INITIALIZATION);

    // Initialize module components (filesystem, memory tracker, etc.)
    Operation_result = API_INIT_initialize_module(KEK_CERTIFICATE_file, Cryptodata_filename);

    if (Operation_result == INITIALIZE_OK_FIRST_INIT)
    {
        // Log first-time initialization success
        API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);
        API_LT_traceWrite("Module first initialization:", "CORRECT", NULL);
        API_LT_traceWrite("Secure_memory_tracker first initialization:", "CORRECT", NULL);
        API_LT_traceWrite("Filesystem first initialization:", "CORRECT", NULL);
    }
    else if (Operation_result == INITIALIZE_OK_NORMAL_INIT)
    {
        // Log normal initialization success
        API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);
        API_LT_traceWrite("Module consecutive initialization:", "CORRECT", NULL);
        API_LT_traceWrite("Secure_memory_tracker consecutive initialization:", "CORRECT", NULL);
        API_LT_traceWrite("Filesystem consecutive initialization:", "CORRECT", NULL);
    }
    else
    {
        // Initialization error handling, cannot write traces cause Library tracer have not been correctly initialized
        API_SM_State_Change(STATE_ERROR);
        API_EM_zeroize_entire_module();
        return MC_INITIALIZATION_ERROR;
    }

    // Initialize error manager and set error counter
    Operation_result = API_EM_init_error_counter();

    if (Operation_result == Errormanager_OK)
    {
        API_LT_traceWrite("Error_manager correct initialization,", "error counter set to 0", NULL);
    }
    else
    {
        API_LT_traceWrite("Error_manager incorrect initialization:,", API_EM_get_error_message(Operation_result), NULL);
        API_SM_State_Change(STATE_ERROR);
        return MC_INITIALIZATION_ERROR;
    }

    // Run self-tests
    API_SM_State_Change(STATE_SELF_TEST);
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    Operation_result = API_SFT_initSelfTests();

    if (Operation_result == SELFTEST_PASSED)
    {
        // Log successful self-tests
        API_LT_traceWrite("Every self test passed", "procceding to operational state", NULL);
    }
    else
    {
        // Self-test failure handling
        API_LT_traceWrite("Self test failed:", API_EM_get_error_message(Operation_result), NULL);
        API_SM_State_Change(STATE_ERROR); // FALTA IMPLEMENTAR LA LÓGICA PARA QUE ENTRE EN ERROR STATE SI REINICIA EL MODULO, también la zeroización
        API_EM_zeroize_entire_module();
        API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);
        return MC_INITIALIZATION_ERROR;
    }

    // Set state to operational after successful initialization
    API_LT_traceWrite("Module Initialization correct ", NULL);
    API_SM_State_Change(STATE_OPERATIONAL);
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    return INITIALIZATION_OK;
}

int API_MC_Insert_Key(uint8_t In_Key[32], size_t key_size, unsigned char *Key_id, size_t Key_id_length)
{
    if (API_SM_get_current_state() != STATE_OPERATIONAL)
    {
        API_LT_traceWrite("incorrect state to insert key, returning error", NULL);
        API_EM_increment_error_counter(10);
        return SM_ERROR_STATE; // Not in operational state
    }

    API_SM_State_Change(STATE_CSP); // Switch to CSP mode
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    int Operation_result = API_KM_storekey(In_Key, key_size, Key_id, Key_id_length); // Store key

    if (Operation_result != KM_OK)
    {
        API_LT_traceWrite("Error in key insertion:", API_EM_get_error_message(Operation_result), NULL);
        API_EM_increment_error_counter(10);     // Log error and increment counter
        API_SM_State_Change(STATE_OPERATIONAL); // Revert state
        API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);
        return Operation_result;
    }

    API_LT_traceWrite("KEY with id:", Key_id, "correctly inserted", NULL);
    API_SM_State_Change(STATE_OPERATIONAL); // Revert state
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    return KEY_OPERATION_OK; // Success
}

int API_MC_Load_Key(unsigned char *Key_id, size_t Key_id_length)
{
    if (API_SM_get_current_state() != STATE_OPERATIONAL)
    {
        API_LT_traceWrite("incorrect state to load key, returning error", NULL);
        API_EM_increment_error_counter(10);
        return SM_ERROR_STATE; // Not in operational state
    }

    API_SM_State_Change(STATE_CSP); // Switch to CSP mode
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    int Operation_result = API_KM_loadkey(Key_id, Key_id_length); // Load key

    if (Operation_result != KM_OK)
    {
        API_LT_traceWrite("Error in key loading:", API_EM_get_error_message(Operation_result), NULL);
        API_EM_increment_error_counter(5);      // Log error and increment counter
        API_SM_State_Change(STATE_OPERATIONAL); // Revert state
        API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);
        return Operation_result;
    }

    API_LT_traceWrite("KEY with id:", Key_id, "correctly loaded", NULL);
    API_SM_State_Change(STATE_OPERATIONAL); // Revert state
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    return KEY_OPERATION_OK; // Success
}

int API_MC_Delete_Key(unsigned char *Key_id, size_t Key_id_length)
{
    if (API_SM_get_current_state() != STATE_OPERATIONAL)
    {
        API_LT_traceWrite("incorrect state to delete key, returning error", NULL);
        API_EM_increment_error_counter(10);
        return SM_ERROR_STATE; // Not in operational state
    }

    API_SM_State_Change(STATE_CSP); // Switch to CSP mode
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    int Operation_result = API_KM_delete_key(Key_id, Key_id_length); // Delete key

    if (Operation_result != KM_OK)
    {
        API_LT_traceWrite("Error in key deleting:", API_EM_get_error_message(Operation_result), NULL);
        API_EM_increment_error_counter(5);      // Log error and increment counter
        API_SM_State_Change(STATE_OPERATIONAL); // Revert state
        API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);
        return Operation_result;
    }

    API_LT_traceWrite("KEY with id:", Key_id, "correctly deleted", NULL);
    API_SM_State_Change(STATE_OPERATIONAL); // Revert state
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    return KEY_OPERATION_OK; // Success
}

int API_MC_fill_buffer_random(unsigned char *buffer, size_t size){ // wrapper of rng function, tbd make it more optimal
    // Check if the system is in an operational state
    if (API_SM_get_current_state() != STATE_OPERATIONAL)
    {
        API_LT_traceWrite("incorrect state to ask forr andom numbers", API_SM_get_current_state_name(), NULL);
        API_EM_increment_error_counter(10);
        return SM_ERROR_STATE; // Return error if not operational
    }
    // Validate input parameters
    if (buffer == NULL || size > 4 * 1024 * 1024) // max random is 4MB
    {
        API_LT_traceWrite("Error:", API_EM_get_error_message(KM_PARAMETERS_ERROR), NULL);
        return RNG_RANDOM_GENERATION_FAILED;
    }

    int result = API_RNG_fill_buffer_random(buffer,size);

    return result;
}

int API_MC_Sing_Cipher_Packet(unsigned char *data_in, size_t data_size, unsigned char *packet_out, size_t *packet_out_length)
{
    // Check if the system is in an operational state
    if (API_SM_get_current_state() != STATE_OPERATIONAL)
    {
        API_LT_traceWrite("incorrect state to cipher packet", API_SM_get_current_state_name(), NULL);
        API_EM_increment_error_counter(10);
        return SM_ERROR_STATE; // Return error if not operational
    }

    // Check if the current key is loaded
    if (Current_key_in_use.IsLoaded == 0)
    {
        API_LT_traceWrite("Error:", API_EM_get_error_message(KM_KEY_NOT_LOADED), NULL);
        API_EM_increment_error_counter(5); // Log error and increment counter
        return KM_KEY_NOT_LOADED;          // Return error if key is not loaded
    }

    // Validate input parameters
    if (data_in == NULL || packet_out == NULL || packet_out_length == NULL)
    {
        API_LT_traceWrite("Error:", API_EM_get_error_message(KM_PARAMETERS_ERROR), NULL);
        return KM_PARAMETERS_ERROR;
    }

    // Switch system state to CSP mode for cryptographic operations
    API_SM_State_Change(STATE_CSP);
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    // Verify the integrity of the key in use
    int Operation_result = API_MT_verify_integrity(&trackers[TI_Current_Key_In_Use]);
    if (Operation_result != MT_OK)
    {
        API_LT_traceWrite("Key integrity compromised, switching to error state: ", API_EM_get_error_message(Operation_result), NULL);
        API_SM_State_Change(SM_ERROR);
        API_EM_zeroize_entire_module();
        API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);
        return Operation_result;
    }

    // Key integrity is verified, proceed to sign and encrypt the data
    API_LT_traceWrite("Key Integrity checked,", "proceeding to sign and cipher", NULL);
    API_SM_State_Change(STATE_CRYPTOGRAPHIC);
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    // Perform the sign and encrypt operation
    unsigned char *out_data;
    size_t out_length;
    Operation_result = API_PCA_sign_encrypt_packet(data_in, data_size, Current_key_in_use.Cipher_key, Current_key_in_use.Auth_key, &out_data, &out_length);

    if (Operation_result == SM_ERROR_STATE)
    {
        API_SM_State_Change(STATE_OPERATIONAL);
        return SM_ERROR_STATE;
    }
    else if(Operation_result == RNG_RANDOM_GENERATION_FAILED){
        API_SM_State_Change(STATE_OPERATIONAL);
        return RNG_RANDOM_GENERATION_FAILED;
    }
    // Copy the signed and encrypted data to the output buffer
    memcpy(packet_out, out_data, out_length);
    *packet_out_length = out_length;

    // Free the allocated memory if necessary
    if (Operation_result == ALLOCATED_MEMORY)
    {
        int free_result = API_MM_freeMem(out_data);
    }

    // Return system state to operational
    API_LT_traceWrite("Sign and cipher operation: ", "OK", NULL);
    API_SM_State_Change(STATE_OPERATIONAL);
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    return CIPHER_AUTH_OPERATION_OK; // Return success code
}

int API_MC_Decipher_Auth_Packet(unsigned char *data_in, size_t data_in_length, unsigned char *out_data, size_t *out_data_length)
{
    // Check if system is operational
    if (API_SM_get_current_state() != STATE_OPERATIONAL)
    {
        API_LT_traceWrite("incorrect state to decipher packet", API_SM_get_current_state_name(), NULL);
        API_EM_increment_error_counter(10);
        return SM_ERROR_STATE;
    }

    // Check if key is loaded
    if (Current_key_in_use.IsLoaded == 0)
    {
        API_LT_traceWrite("Error:", API_EM_get_error_message(KM_KEY_NOT_LOADED), NULL);
        API_EM_increment_error_counter(5);
        return KM_KEY_NOT_LOADED;
    }

    // Validate input parameters
    if (data_in == NULL || out_data == NULL || out_data_length == NULL)
    {
        API_LT_traceWrite("Error:", API_EM_get_error_message(KM_PARAMETERS_ERROR), NULL);
        return KM_PARAMETERS_ERROR;
    }

    // Switch to CSP state for cryptoparameters operations
    API_SM_State_Change(STATE_CSP);
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    // Verify key integrity
    int Operation_result = API_MT_verify_integrity(&trackers[TI_Current_Key_In_Use]);
    if (Operation_result != MT_OK)
    {
        API_LT_traceWrite("Key integrity compromised", API_EM_get_error_message(Operation_result), NULL);
        API_SM_State_Change(SM_ERROR);
        API_EM_zeroize_entire_module();
        API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);
        return Operation_result;
    }
    // Key integrity is verified, proceed to sign and encrypt the data
    API_LT_traceWrite("Key Integrity checked,", "proceeding to sign and cipher", NULL);
    API_SM_State_Change(STATE_CRYPTOGRAPHIC); // Switch to cryptographic state
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    // Proceed to decrypt and verify packet
    unsigned char *out_data_aux;
    size_t out_length_aux;
    unsigned char verify;
    Operation_result = API_PCA_decrypt_verify_packet(data_in, data_in_length, Current_key_in_use.Cipher_key, Current_key_in_use.Auth_key, &out_data_aux, &out_length_aux, &verify);

    if (Operation_result == SM_ERROR_STATE)
    {
        API_SM_State_Change(STATE_OPERATIONAL);
        return SM_ERROR_STATE;
    }
    else if(Operation_result == MAC_NOT_VERIFIED){
        API_LT_traceWrite("Error:", API_EM_get_error_message(MC_PACKET_INTEGRITY_COMPROMISED), NULL);
        API_EM_increment_error_counter(3);
        API_MM_secure_zeroize(out_data, out_length_aux); // Zeroize decrypted data on failure
        API_SM_State_Change(STATE_OPERATIONAL);
        return MC_PACKET_INTEGRITY_COMPROMISED;
    }

    // Copy the decrypted and verified data to the output buffer
    memcpy(out_data, out_data_aux, out_length_aux);
    *out_data_length = out_length_aux;
    // Handle packet integrity failure before copying the data
    // Free memory if necessary
    if (Operation_result == ALLOCATED_MEMORY)
    {
        int free_result = API_MM_freeMem(out_data_aux); //zeroize the data
    }

    // Return to operational state
    API_LT_traceWrite("Decipher and auth operation: ", "OK", NULL);
    API_SM_State_Change(STATE_OPERATIONAL);
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    return DECIPHER_AUTH_OPERATION_OK;
}

int API_MC_Shutdown_module()
{
    // Log the shutdown action
    API_LT_traceWrite("Shutting down the cryptomodule: ", "POWER OFF", NULL);

    // Zeroize and free all sensitive data
    API_MT_zeroize_and_free_all();

    // Zeroize entire dynamic memory tree
    API_MM_Zeroize_root();

    // Close the filesystem
    API_FS_Close_filesystem();

    // Change the state to OFF
    API_SM_State_Change(STATE_OFF);
}