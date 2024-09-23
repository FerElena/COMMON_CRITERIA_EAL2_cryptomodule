#include "API_core.h"

int API_MC_Initialize_module(unsigned char *KEK_CERTIFICATE_file,unsigned char *Cryptodata_filename){
	//state machine initialization
	State_Change(STATE_ON);
	int Operation_result = 0;
	//start initializing the cryptomodule
	State_Change(STATE_INITIALIZATION);

	Operation_result = API_INIT_initialize_module(KEK_CERTIFICATE_file,Cryptodata_filename);
	if(Operation_result == INITIALIZE_OK_FIRST_INIT){
		API_LT_traceWrite("Module_first_initialization",NULL);
	}
	else if(Operation_result == INITIALIZE_OK_NORMAL_INIT){
		API_LT_traceWrite("Module_Normal_initialization",NULL);
	}
	else{
		API_LT_traceWrite("Initialization Error",NULL);
		return initialized_module;
	}
	
	return 1;
}