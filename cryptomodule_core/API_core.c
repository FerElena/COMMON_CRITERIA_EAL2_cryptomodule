#include "API_core.h"

int API_MC_Initialize_module(unsigned char *KEK_CERTIFICATE_file,unsigned char *Cryptodata_filename){
	//state machine initialization
	int Operation_result = 0;
	API_SM_State_Change(STATE_ON);
	//start initializing the cryptomodule (memory tracker, file system, library tracer and error manager)
	API_SM_State_Change(STATE_INITIALIZATION);

	Operation_result = API_INIT_initialize_module(KEK_CERTIFICATE_file,Cryptodata_filename);
	if(Operation_result == INITIALIZE_OK_FIRST_INIT){
		API_LT_traceWrite("Current state: ",API_SM_get_current_state_name(),NULL);
		API_LT_traceWrite("Module first initialization","Filesystem initialization correct","Memory tracker initialization correct",NULL);
	}
	else if(Operation_result == INITIALIZE_OK_NORMAL_INIT){
		API_LT_traceWrite("Current state: ",API_SM_get_current_state_name(),NULL);
		API_LT_traceWrite("Module normal initialization","Filesystem load correct","Memory tracker initialization correct",NULL);
	}
	else{
		API_LT_traceWrite("Initialization Error",API_EM_get_error_message(Operation_result),NULL);
		return INITIALIZATION_ERROR;
	}

	Operation_result = API_EM_init_error_counter();
	if(Operation_result == Errormanager_OK){
		API_LT_traceWrite("Error_manager correct initialization","error counter set to 0",NULL);
	}
	else{
		API_LT_traceWrite("Error_manager incorrect initialization:",API_EM_get_error_message(Operation_result),NULL);
		return INITIALIZATION_ERROR;
	}
	//start self-tests
	API_SM_State_Change(STATE_SELF_TEST);
	API_LT_traceWrite("Current state: ",API_SM_get_current_state_name(),NULL);
	Operation_result = API_SFT_initSelfTests();
	if(Operation_result == SELFTEST_PASSED){
		API_LT_traceWrite("every self test passed","procceding to operational state",NULL);
	}
	else{
		API_LT_traceWrite("Self test failed:",API_EM_get_error_message(Operation_result),NULL);
		return Operation_result;
	}
	API_SM_State_Change(STATE_OPERATIONAL);
	API_LT_traceWrite("Current state: ",API_SM_get_current_state_name(),NULL);
	return INITIALIZATION_OK;
}