/**
 * @file AESOFBTests.c
 * @brief File containing all the neccesary code to perform the AES tests.
 */

#ifndef AESOFBTESTS_H
#define AESOFBTESTS_H
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

#include "../crypto/AES_OFB.h"
#include "../crypto/AES_CORE.h"

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

int SFT_AESOFB_256_encrypt_decrypt_compare(unsigned char *input, int len, unsigned char *iv, unsigned char* key , unsigned char* expected_output );

int SFT_AESOFB_256_encrypt_decrypt_compareMC(unsigned char *input, int len, unsigned char *iv, unsigned char* key , unsigned char* expected_output );

int SFT_AES256OFB_mmtTests();

int SFT_AES256OFB_katTests();

int SFT_AES256OFB_mcTests();

int API_SFT_AES256_OFB_Tests();


#endif
