#ifndef API_CORE_H
#define API_CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "module_initialization.h"
#include "Error_Manager.h"
#include "packet_cipher_auth.h"
#include "../state_machine/State_Machine.h"
#include "../library_tracer/log_manager.h"
#include "../crypto-selftests/selftests.h"


#define INITIALIZATION_OK 2000
#define INITIALIZATION_ERROR -2000

int API_MC_Initialize_module(unsigned char *KEK_CERTIFICATE_file,unsigned char *Cryptodata_filename);

#endif