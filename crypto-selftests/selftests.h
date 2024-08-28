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

#include "../file_system/file_system.h"
#include "../library_tracer/log_manager.h"

/* Global variables definition ...................................... */

/**
 * @brief Test passed code
 * 
 * Code sent when a selftest is passed
 */
#define TEST_PASSED 1

/**
 * @brief Test failed code
 * 
 * Code sent when a selftest does not passed
 */
#define TEST_FAILED 0

/* Function declaration zone ........................................ */

/**
 * @brief Selftests initialization function
 * 
 * This function starts every cryptographic function selftest and the integrity hash verification selftest.
 * If it is passed, the library starts to accept clients.
 * 
 * @tsfi{LGOT, CMAC, HMAC, ECDSA, SHA, TESLA, SFTFUN}
 * @sfr{FCS_COP.1.1, FDP_ACF.1.1, FAU_GEN.1.1, FAU_GEN.1.2, FAU_STG.1.1, FPT_TST.1.1, FPT_TST.1.2, FPT_TST.1.3,
 *      FTA_TSE.1.1, FDP_ITC.2.1, FDP_ITC.2.2, FDP_ITC.2.3, FDP_ITC.2.4, FDP_ITC.2.5, FTA_SSL.4.1}
 * @methodOfUse{This function is invoked by handler.c and the API.c}
 * 
 * @param id Identifier for the client that requires the ntPacket function
 * @param path Init library path
 */
void API_SFT_initSelfTests();


/**
 * @brief Checks the library integrity to prevent malicious modifications
 * 
 * This function starts the integrity hash verification selftest making a new hash and matching 
 * it with the existing hash in the path designed.
 * 
 * @tsfi{SHA, SFTFUN}
 * @sfr{FCS_COP.1.1, FDP_ACF.1.1, FAU_GEN.1.1, FAU_GEN.1.2, FAU_STG.1.1, FPT_TST.1.1, FPT_TST.1.2, FPT_TST.1.3,
 *      FTA_TSE.1.1, FDP_ITC.2.1, FDP_ITC.2.2, FDP_ITC.2.3, FDP_ITC.2.4, FDP_ITC.2.5, FTA_SSL.4.1}
 * @methodOfUse{This function is invoked by the API_SFT_initSelfTests function}
 * 
 * @param id id Identifier for the client that requires the ntPacket function
 * @param path Init library path
 * @return The result of the check (1 success, 0 fail)
 * 
 * @errors
 * @error{ ERROR 1, Returns FAIL if the hash file cannot be opened}
 * @error{ ERROR 2, Returns FAIL if the file to hash cannot be opened} 
 */
int SFT_checkIntegrityFile(unsigned char *id, unsigned char *path);
#endif
