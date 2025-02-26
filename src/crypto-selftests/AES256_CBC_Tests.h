/**
 * @file AESCBCTests.h
 * @brief File which contains the necessary functions to perform the tests required to validate our AES algorithm according to the NIST test vectors.
 */
#ifndef AESCBCTESTS_H
#define AESCBCTESTS_H
#pragma once


/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "../crypto/AES_CBC.h"
#include "../crypto/AES_CORE.h"

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

int SFT_AESCBC_256_encryptCompare(unsigned char *plaintext, int *len, unsigned char* expected_output, int lenExpected, unsigned char *key, unsigned char* iv);

int SFT_AESCBC_256_decryptCompare(unsigned char *ciphertext, int *len, unsigned char* expected_output, int lenExpected, unsigned char *key, unsigned char* iv);

int SFT_AESCBC_256_decryptCompareMC(unsigned char *ciphertext, int *len, unsigned char* expected_output, int lenExpected, unsigned char *key, unsigned char* iv);

int SFT_AESCBC_256_encryptCompareMC(unsigned char *plaintext, int *len, unsigned char* expected_output, int lenExpected, unsigned char* key, unsigned char *iv);

int SFT_AES256CBC_mmtTests();

int SFT_AES256CBC_katTests();

int SFT_AES256CBC_mcTests();

int API_SFT_AES256_CBC_Tests();


#endif
