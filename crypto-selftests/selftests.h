/**
 * @file selftests.h
 * @brief File containing the selftests function headers
 */


#ifndef SELFTESTS_H
#define SELFTESTS_H

/* Compile include files ............................................ */
#include <stdio.h>

/* Private include files ............................................ */
#include "../crypto/crypto.h"
#include "SHA256Tests.h"
#include "HMACTests.h"
#include "ECDSA256Tests.h"
#include "AESTests.h"

#include "../secure_memory_management/file_system.h"
#include "../library_tracer/log_manager.h"

/* Global variables definition ...................................... */

/**
 * @brief Test passed code
 * 
 * Code sent when a selftest is passed
 */
#define TEST_PASSED 1600

/**
 * @brief Test failed code
 * 
 * Code sent when a selftest does not passed
 */
#define TEST_FAILED -1600

/* Function declaration zone ........................................ */

/**
 * @brief Selftests initialization function
 * 
 * This function starts every cryptographic function selftest and the integrity cryptomodule verification selftest.
 * If it is passed, the library starts, and proceeds to operational state.
 * 
 * 
 */
void API_SFT_initSelfTests();


#endif
