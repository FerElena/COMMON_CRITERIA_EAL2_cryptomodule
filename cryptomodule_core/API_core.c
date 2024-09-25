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

