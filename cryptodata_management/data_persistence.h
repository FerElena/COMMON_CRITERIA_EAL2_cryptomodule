#ifndef DATA_PERSISTENCE_H
#define DATA_PERSISTENCE_H

#include "../file_system/file_system.h"

typedef struct config_file
{
	uint8_t initialization_state;
	uint8_t certified_state;
	uint8_t ecdsa_seckp256_sign[64];
} Config_file;

Config_file configuration_file;
unsigned char *configuraton_file_name = "configuration_file";

#endif