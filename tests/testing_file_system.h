#ifndef TESTING_FILE_SYSTEM_H
#define TESTING_FILE_SYSTEM_H

#include <stdint.h>

#include "../secure_memory_management/file_system.h"
#include "../crypto/CRC_Galileo.h"


#define file_system_rpath "filesystem_data" //filesystem path 

void print_test_Result(uint8_t result[],unsigned char test_name[]);

void FS_testing();  
#endif