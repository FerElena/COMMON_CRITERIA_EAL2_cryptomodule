/**
 * @file ECDSA256Tests.h
 * @brief File which contains the necessary functions to perform the unit tests required to validate our ECDSA algorithm according to the NIST test vectors.
 */

#ifndef ECDSA256TESTS_H
#define ECDSA256TESTS_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "../crypto/ECDSA_256.h"
#include "../crypto/SHA256.h"

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief This function compares the result of the ECDSA algorithm with the test vectors given by NIST, with the expected result, if equal, returns 1, otherwise 0.
 * 
 * 
 * @param Qx Coordinate x of the public key
 * @param Qy Coordinate y of the public key
 * @param ECDSA_msg ECDSA message
 * @param ECDSA_msg_len ECDSA message length
 * @param r Integer r from the signature
 * @param s Integer s from the signature
 * 
 * @return If the ECDSA result and the given result matches, returns 1, else returns 0
 */
int SFT_ECDSA256_verify_test(unsigned char *Qx, size_t Qx_length, unsigned char *Qy, size_t Qy_length, unsigned char *ECDSA_msg, int ECDSA_msg_len, unsigned char *r, size_t r_length,unsigned char *s, size_t s_length);

/**
 * @brief The function initiates the ECDSA test verifiying all the hardcoded NIST test-vectors, if a single verification fails, the test fails
 * 
 * 
 * @return Returns 1 if the test is passed, 0 if not
*/
int API_SFT_ECDSA256Tests();

#endif