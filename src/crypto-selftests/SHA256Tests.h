/**
 * @file SHA256Tests.h
 * @brief File which contains the necessary functions to perform the unit tests required to validate our SHA256 algorithm according to the NIST test vectors.
 */


#ifndef SHA256TESTS_H
#define SHA256TESTS_H

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdio.h>
#include <string.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "../crypto/SHA256.h"

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief This function is used to compare a given hash of a message, with the hash produced by our SHA256 algorithm test vectors are given by the NIST
 * 
 * 
 * @param hashvector1 Message to be hashed with our SHA256 algorithm 
 * @param msglength Length of the given message
 * @param hashvector2 Already known hash of the message to be compared with the produced hash bit by bit
 * 
 * @return Returns 1 if the comparation between the hash is true, 0 if false
*/
int SFT_SHA256compare(unsigned char *hashvector1, int msglength, unsigned char *hashvector2);

/**
 * @brief The function initiates the SHA-256 test verifiying all the hardcoded NIST test-vectors, if a single vector fails, the test fails
 * 
 * 
 * @return Returns 1 if the test is passed, 0 if not
*/
int API_SFT_SHA256Tests();


/**
 * @brief Puts an array of equal length of the number of test vectors to 1
 * 
 * 
 * @param array Array to manage the test results  
 * @param len Array length
*/
void SFT_putToOne(int array[], int len);

#endif
