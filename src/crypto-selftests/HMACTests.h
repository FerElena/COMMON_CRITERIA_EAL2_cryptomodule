/**
 * @file HMACTests.h
 * @brief File which contains the necessary functions to perform the unit tests required to validate our HMAC algorithm according to the NIST test vectors.
 */

#ifndef HMACTESTS_H
#define HMACTESTS_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "../crypto/HMAC_SHA256.h"

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief This function compares the result of the HMAC algorithm with the test vectors given by NIST, with the expected result, if equal, returns 1, otherwise 0.
 * 
 * 
 * @param key Key used to perform the HMAC algorithm given by NIST
 * @param lenKey Length of the key
 * @param msg Message in plaintext to be verified by the HMAC algorithm
 * @param lenMsg Length of the message to be verified
 * @param mac Message authentication code to be verified which has been previously generated with the plaintext and the key
 * @param lenMac Length of the MAC code
 * 
 * @return If the comparation between the given MAC and the generated MAC is True, returns 1, else returns 0
*/
int SFT_HMAC_Compare(unsigned char *key, int lenKey, unsigned char *msg, int lenMsg, unsigned char *mac, int lenMac);

/**
 * @brief The function initiates the HMAC test verifiying all the hardcoded NIST test-vectors, if a single vector fails, the test fails
 * 
 * 
 * @return Returns 1 if the test is passed, 0 if not
*/
int API_SFT_HMAC256_SHA256_Test();

#endif