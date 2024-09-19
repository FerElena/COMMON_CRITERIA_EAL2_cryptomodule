#include "module_initialization.h"

int Memory_tracking_initialization(){
	// array for result returning
	uint8_t correct_tracker_init_result[64] ;
	for(int i = 0; i < sizeof(correct_tracker_init_result) / sizeof(correct_tracker_init_result[0]); correct_tracker_init_result[i++] = 1);
	//initialize the memory tracker pointers
	API_MT_initialize_trackers();

}


int First_init_FS(unsigned char *cryptomodule_instance_name,size_t cryptomodule_instance_length,unsigned char *KeyEncryption_keyfile){

};