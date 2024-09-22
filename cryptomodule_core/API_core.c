#include "API_core.h"

int API_MC_Initialize_module(unsigned char *KEK_CERTIFICATE_file,unsigned char *Cryptodata_filename){
	//state machine initialization
	State_Change(STATE_ON);
	int Operation_result = 0;
	//start initializing the cryptomodule
	State_Change(STATE_INITIALIZATION);
	API_INIT_initialize_module(KEK_CERTIFICATE_file,Cryptodata_filename);
	API_MT_traceWrite("");
	return 1;
}