/**
 * @file selftests.c
 * @brief File containing all the cryptographic functions and integrity sign verification selftest functionality
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

int API_SFT_initSelfTests()
{
    if(API_SM_get_current_state() != STATE_SELF_TEST){
        return STATE_INCORRECTSTATE_ERROR;
    }
    int CorrectTest = SELFTEST_PASSED; 
    if (!API_SFT_SHA256Tests()) // SHA256 selftests starts
    {
        return SHA256_SELFTEST_FAILED;
    }
    if (!API_SFT_HMACTest()) // HMAC selftests starts
    {
        return HMAC_SHA256_SELFTEST_FAILED;
    }
    if (!API_SFT_ECDSA256Tests()) // ECDSA256 selftests starts
    {
        return ECDSAP256_SELFTEST_FAILED;
    }
    if(!API_SFT_AESTests()) // COPERNICUS256 selftests starts
    {
        return AES256_CBC_SELFTEST_FAILED;
    }
    return SELFTEST_PASSED;
}
