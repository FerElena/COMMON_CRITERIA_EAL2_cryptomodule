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
        API_LT_traceWrite("Module first initialization", "Filesystem initialization correct", "Memory tracker initialization correct", NULL);
    }
    else if (Operation_result == INITIALIZE_OK_NORMAL_INIT)
    {
        // Log normal initialization success
        API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);
        API_LT_traceWrite("Module normal initialization", "Filesystem load correct", "Memory tracker initialization correct", NULL);
    }
    else
    {
        // Initialization error handling
        API_LT_traceWrite("Initialization Error", API_EM_get_error_message(Operation_result), NULL);
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
        API_SM_State_Change(SM_ERROR); // FALTA IMPLEMENTAR LA LÓGICA PARA QUE ENTRE EN ERROR STATE SI REINICIA EL MODULO, también la zeroización
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
        return SM_ERROR_STATE; // Not in operational state
    }

    API_SM_State_Change(STATE_CSP); // Switch to CSP mode
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    int Operation_result = API_KM_storekey(In_Key, key_size, Key_id, Key_id_length); // Store key

    if (Operation_result != KM_OK)
    {
        API_LT_traceWrite("Error in key insertion:", API_EM_get_error_message(Operation_result), NULL);
        API_EM_increment_error_counter(5);      // Log error and increment counter
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

int API_CP_Sing_Cipher_Packet(unsigned char *data_in, size_t data_size, unsigned char *packet_out, size_t *packet_out_length)
{
    // Check if the system is in an operational state
    if (API_SM_get_current_state() != STATE_OPERATIONAL)
    {
        return SM_ERROR_STATE; // Return error if not operational
    }
    // Check if the current key is loaded
    if (Current_key_in_use.IsLoaded == 0)
    {
        return KM_KEY_NOT_LOADED; // Return error if key is not loaded
    }

    // Switch system state to CSP mode for cryptographic operations
    API_SM_State_Change(STATE_CSP);
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    // Verify the integrity of the key in use
    int Operation_result = API_MT_verify_integrity(&trackers[TI_Current_Key_In_Use]);
    if (Operation_result != MT_OK)
    {
        // If integrity check fails, switch to error state and return the result
        API_LT_traceWrite("Key integrity compromised, switching to error state: ", API_SM_get_current_state_name(), NULL);
        API_SM_State_Change(SM_ERROR);
        return Operation_result;
    }

    // Key integrity is verified, proceed to sign and encrypt the data
    API_LT_traceWrite("Key Integrity checked", "proceeding to sign and cipher");
    API_SM_State_Change(STATE_CRYPTOGRAPHIC); // Switch to cryptographic state
    API_LT_traceWrite("Current state: ", API_SM_get_current_state_name(), NULL);

    // Perform the sign and encrypt operation
    unsigned char *out_data;
    size_t out_length;
    Operation_result = API_PCA_sign_encrypt_packet(data_in, data_size, Current_key_in_use.Cipher_key, Current_key_in_use.Auth_key, &out_data, &out_length);
    
    // Copy the signed and encrypted data to the output buffer
    memcpy(packet_out, out_data, out_length);
    *packet_out_length = out_length; // Update the output length

    // Free the allocated memory if necessary
    if(Operation_result == ALLOCATED_MEMORY){
        API_MM_freeMem(out_data);
    }

    // Return system state to operational
    API_SM_State_Change(STATE_OPERATIONAL); 
    return CIPHER_AUTH_OPERATION_OK; // Return success code
}

