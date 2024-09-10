#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>


#include "crypto-selftests/selftests.h"
#include "tests/testing_file_system.h"
#include "tests/MemoryTrackerTest.h"
#include "tests/DmemmanagerTest.h"
#include "tests/packet_cipher_authtest.h"
#include "crypto/AES_OFB.h"
#include "file_system/file_system.h"
#include "library_tracer/log_manager.h"
#include "packet_manager/packet_cipher_auth.h"


int main(){
    system("clear");
    printf("prueba inicio selftests\n");
    API_SFT_initSelfTests();
    FS_testing();
    MemoryTracker_tests();
    Test_DmemManager();
    run_tests_packets(100);

    return 0;
}