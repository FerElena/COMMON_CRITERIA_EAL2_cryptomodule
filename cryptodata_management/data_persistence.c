#include "data_persistence.h"

int initiate_data_persistence(){//the purpose of this file is initiate the files where the CSPs will remain persistent
	//create config file with the sign of the module binary
	int result1 = API_FS_create_file_data(configuraton_file_name,strlen(configuraton_file_name),&configuration_file,sizeof(configuration_file),NOT_CSP);
}