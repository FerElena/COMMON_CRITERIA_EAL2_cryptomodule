#include <stdio.h>
#include "crypto-selftests/selftests.h"
#include "tests/testing_file_system.h"
#include "tests/MemoryTrackerTest.h"
#include "tests/DmemmanagerTest.h"
#include "crypto/AES_OFB.h"
#include "file_system/file_system.h"
#include "library_tracer/log_manager.h"

int main(){
    printf("prueba inicio selftests\n");
    API_SFT_initSelfTests();
    FS_testing();
    MemoryTracker_tests();
    Test_DmemManager();
    
    
    
    return 0;
}