/**
 * @file mac.h
 * @brief File containing all the function headers of the HMAC and CMAC message hashing.
 */

#ifndef MAC_VERIFY_H
#define MAC_VERIFY_H
#pragma once

/* Compiler include files ............................................ */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Private include files ............................................ */
#include "hmac.h"

/* Global variables definition ...................................... */


/**
 * @brief MAC not verified value
 * This variable defines the value when the MAC is not verified
 */
#define MAC_NOT_VERIFIED 0

/**
 * @brief MAC verified value
 * This variable defines the value when the MAC is verified
 */
#define MAC_VERIFIED 1

/* Function declaration zone ........................................ */

/**
 * @brief Verify the HMAC-SHA256 signature sent by the receiver
 *
 * The purpose of this function is to verify the HMAC-SHA256 signature received by the
 * library and verify if it is correct or not. Then returns the result of the verification
 *
 * @tsfi{HMAC}
 * @sfr{FCS_COP.1.1}
 * @methodOfUse{This function is invoked by the crypto.c}
 *
 * @param msg Message we want to verify
 * @param key Key used to sign the message
 * @param sign HMAC signature generated to grant the message integrity
 * @param length_msg Message length
 * @param length_key HMAC key length
 * @param length_sign HMAC signature length 
 * 
 * @return Returns an 1 if the function was successfull, or 0 if the function failed
 *
 * @errors
 * @error{ ERROR 1, The parameter msg key sign or mode has a NULL value or is empty }
 * @error{ ERROR 2, The parameter sign or length_sign is incorrect NULL or zero }
 */
int API_verify_HMAC(unsigned char* msg, unsigned char* key, unsigned char* sign, size_t length_msg, size_t length_key, size_t length_sign);



#endif 
