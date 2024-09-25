#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "cryptomodule_core/API_core.h"
#include "crypto-selftests/selftests.h"
#include "tests/testing_file_system.h"  
#include "tests/MemoryTrackerTest.h"  
#include "tests/DmemmanagerTest.h"
#include "tests/packet_cipher_authtest.h"
#include "crypto/AES_OFB.h"
#include "secure_memory_management/file_system.h"
#include "library_tracer/log_manager.h"
#include "cryptomodule_core/packet_cipher_auth.h"
#include "prng/random_number.h"


int main(){    
    system("clear");
    printf("prueba inicio modulo\n");
    unsigned char *cryptodata_filename = "cryptodata_test"; 
    unsigned char *KEK_CERT_fileroute = "/home/ninjahacker/Escritorio/COMMON_CRITERIA_EAL2_cryptomodule/scripts/certificate_manager/testing_cert"; // your route to cert
    int result = API_MC_Initialize_module(KEK_CERT_fileroute,cryptodata_filename);
    printf("el resultado de la inicialización del modulo es : %d\n",result);
    
    uint8_t key1[32],key2[32];
    API_RNG_fill_buffer_random((unsigned char*)key1,32);
    API_RNG_fill_buffer_random((unsigned char*)key2,32);
    unsigned char *key_name1 = "Key1";
    unsigned char *key_name2 = "Key2";

    result = API_MC_Insert_Key(key1,32,key_name1,strlen(key_name1));
    result = API_MC_Insert_Key(key1,32,key_name2,strlen(key_name2));
    printf("el resultado de insertar la clave es : %d\n",result);

    result = API_MC_Load_Key(key_name2,strlen(key_name2));
    printf("el resultado de cargar la clave es : %d\n",result);

    result = API_MC_Delete_Key(key_name2,strlen(key_name2));
    printf("el resultado de borrar la clave es : %d\n",result);

    usleep(5000);
    API_FS_Close_filesystem(); 
    
    /*
    API_SFT_initSelfTests();
    FS_testing();
    MemoryTracker_tests();
    Test_DmemManager();  
    run_tests_packets(100000);
 
    */
    return 0;  
}  