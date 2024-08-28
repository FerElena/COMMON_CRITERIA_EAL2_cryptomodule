/**
 * @file selftests.c
 * @brief File containing all the cryptographic functions and integrity hash verification selftest functionality
 */

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/
#include "selftests.h"

unsigned char *filename_hash = "binary_hash";
int filename_hash_length = 11;

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

void API_SFT_initSelfTests()
{
    int CorrectTest = TEST_PASSED; 
    if (!API_SFT_SHA256Tests()) // SHA256 selftests starts
    {
        CorrectTest = TEST_FAILED;
        printf("SHA-256 self-test failed\n");
    }
    else
    {
        printf("SHA-256 self-test passed successfully\n");
    }

    if (!API_SFT_HMACTest()) // HMAC selftests starts
    {
        CorrectTest = TEST_FAILED;
        printf("HMAC-SHA-256 self-test failed\n");
    }
    else
    {
        printf("HMAC-SHA-256 self-test passed successfully\n");
    } 

    if (!API_SFT_ECDSA256Tests()) // ECDSA256 selftests starts
    {
        CorrectTest = TEST_FAILED;
        printf("ECDSA-P256 self-test failed\n");
    }
    else
    {
        printf("ECDSA-P256 self-test passed successfully\n");
    }
    if(!API_SFT_AESTests()) // COPERNICUS256 selftests starts
    {
        CorrectTest = TEST_FAILED;
        printf("AESCBC self-tests failed\n");
    }
    else{
        printf("AESCBC self-tests passed succesfully\n");
    }
}
