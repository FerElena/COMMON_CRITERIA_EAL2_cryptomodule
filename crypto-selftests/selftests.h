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
#include "../state_machine/State_Machine.h"

/* Global variables definition ...................................... */

/**
 * @brief Test passed code
 * 
 * Code sent when a selftest is passed
 */
#define SELFTEST_PASSED 1600

/**
 * @brief Test failed code
 * 
 * Code sent when a selftest does not passed
 */
#define SELFTEST_FAILED -1600
#define SHA256_SELFTEST_FAILED -1601
#define HMAC_SHA256_SELFTEST_FAILED -1602
#define ECDSAP256_SELFTEST_FAILED -1603
#define AES256_CBC_SELFTEST_FAILED -1604
#define MODULE_INTEGRITY_SELFTEST_FAILED -1605

/* Function declaration zone ........................................ */

/**
 * @brief Selftests initialization function
 * 
 * This function starts every cryptographic function selftest and the integrity cryptomodule verification selftest.
 * If it is passed, the library starts, and proceeds to operational state.
 * 
 * 
 */
int API_SFT_initSelfTests();


#endif
