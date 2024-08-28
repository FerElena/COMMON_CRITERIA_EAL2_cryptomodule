#include <stdio.h>
#include "crypto-selftests/selftests.h"
#include "file_system/testing_file_system.h"
#include "memory_tracker/MemoryTrackerTest.h"
#include "Dynamic_Memory_Manager/DmemmanagerTest.h"
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