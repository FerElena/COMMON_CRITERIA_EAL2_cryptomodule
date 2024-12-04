/**
 * @file ECDSA_256.h
 * @brief Header file for ECDSA 256-bit implementation using SECPK256 curve.
 *
 * This file provides the function declarations for ECDSA key generation, 
 * signing, verification, and signature compression for the SECP256R1 curve.
 * 
 * @copyright
 * Copyright (c) 2013, Kenneth MacKay. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions, and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions, and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _EASY_ECC_H_
#define _EASY_ECC_H_

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <stdint.h>
#include <stdio.h>

/****************************************************************************************************************
 * Global variables/constants definition
 ****************************************************************************************************************/

/** @def secp256r1 
 *  @brief Defines the SECP256R1 curve.
 */
#define secp256r1 32

#define NUM_ECC_DIGITS (ECC_BYTES/8)
#define MAX_TRIES 16

#ifndef ECC_CURVE
    /** @def ECC_CURVE 
     *  @brief Defines the default elliptic curve to use (secp256r1).
     */
    #define ECC_CURVE secp256r1
#endif

#if (ECC_CURVE != secp128r1 && ECC_CURVE != secp192r1 && ECC_CURVE != secp256r1 && ECC_CURVE != secp384r1)
    #error "Must define ECC_CURVE to one of the available curves"
#endif

/** @def ECC_BYTES
 *  @brief Defines the byte size of the elliptic curve used.
 */
#define ECC_BYTES ECC_CURVE

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EccPoint
{
    uint64_t x[NUM_ECC_DIGITS];
    uint64_t y[NUM_ECC_DIGITS];
} EccPoint;

#define CONCAT1(a, b) a##b
#define CONCAT(a, b) CONCAT1(a, b)

#define Curve_P_32 {0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull, 0x0000000000000000ull, 0xFFFFFFFF00000001ull}
#define Curve_B_32 {0x3BCE3C3E27D2604Bull, 0x651D06B0CC53B0F6ull, 0xB3EBBD55769886BCull, 0x5AC635D8AA3A93E7ull}   
#define Curve_G_32 { \
    {0xF4A13945D898C296ull, 0x77037D812DEB33A0ull, 0xF8BCE6E563A440F2ull, 0x6B17D1F2E12C4247ull}, \
    {0xCBB6406837BF51F5ull, 0x2BCE33576B315ECEull, 0x8EE7EB4A7C0F9E16ull, 0x4FE342E2FE1A7F9Bull}}
#define Curve_N_32 {0xF3B9CAC2FC632551ull, 0xBCE6FAADA7179E84ull, 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull}

//parameters which make operations with ECDSA-256 private key, CSP PARAMETERS

extern uint64_t ECDSA_curve_p[NUM_ECC_DIGITS];
extern uint64_t ECDSA_curve_b[NUM_ECC_DIGITS];
extern EccPoint ECDSA_curve_G;
extern uint64_t ECDSA_curve_n[NUM_ECC_DIGITS];

extern uint64_t ECDSA_k[NUM_ECC_DIGITS];
extern uint64_t ECDSA_l_tmp[NUM_ECC_DIGITS];
extern uint64_t ECDSA_l_s[NUM_ECC_DIGITS];

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

/**
 * @brief Generate a public/private key pair using ECDSA.
 * 
 * This function generates an ECDSA public/private key pair using the specified 
 * elliptic curve.
 *
 * @param[out] p_publicKey  Pointer to buffer where the generated public key will be stored.
 * @param[out] p_privateKey Pointer to buffer where the generated private key will be stored.
 * @return 1 on success, 0 on failure.
 */
int ecc_make_key(uint8_t p_publicKey[ECC_BYTES+1], uint8_t p_privateKey[ECC_BYTES]);

/**
 * @brief Generate an ECDSA signature for a given hash.
 * 
 * This function generates an ECDSA signature for the given message hash using the provided
 * private key.
 *
 * @param[in]  p_privateKey  Pointer to the private key.
 * @param[in]  p_hash        Pointer to the hash of the message.
 * @param[out] p_signature   Pointer to buffer where the generated signature will be stored.
 * @return 1 on success, 0 on failure.
 */
int ecdsa_sign(const uint8_t p_privateKey[ECC_BYTES], const uint8_t p_hash[ECC_BYTES], uint8_t p_signature[ECC_BYTES*2]);

/**
 * @brief Verify an ECDSA signature.
 * 
 * This function verifies an ECDSA signature for the given message hash using the provided
 * public key.
 *
 * @param[in] p_publicKey Pointer to the public key.
 * @param[in] p_hash      Pointer to the hash of the signed message.
 * @param[in] p_signature Pointer to the ECDSA signature (r and s components).
 * @return 1 if the signature is valid, 0 if it is invalid.
 */
int API_ecdsa_verify(const uint8_t p_publicKey[ECC_BYTES+1], const uint8_t p_hash[ECC_BYTES], const uint8_t p_signature[ECC_BYTES*2]);

/**
 * @brief Compress an ECDSA signature.
 * 
 * This function compresses an ECDSA signature by combining the r and s components.
 * 
 * @param[out] ECDSA_sign   Pointer to the buffer where the compressed signature will be stored.
 * @param[in]  r            Pointer to the r component of the signature.
 * @param[in]  s            Pointer to the s component of the signature.
 * @param[in]  r_len        Length of the r component.
 * @param[in]  s_len        Length of the s component.
 */
void API_ECDSA256_compress_signature(uint8_t* ECDSA_sign, unsigned char* r, unsigned char* s, int r_len, int s_len);

/**
 * @brief Decompress an ECDSA signature.
 * 
 * This function decompresses an ECDSA signature into its r and s components.
 * 
 * @param[in]  ECDSA_sign Pointer to the compressed signature.
 * @param[out] r          Pointer to the buffer where the r component will be stored.
 * @param[out] s          Pointer to the buffer where the s component will be stored.
 * @param[in]  sign_len   Length of the compressed signature.
 */
void API_ECDSA256_CP_decompress_signature(unsigned char* ECDSA_sign, unsigned char* r, unsigned char* s, int sign_len);

/**
 * @brief Compress a public key.
 * 
 * This function compresses a public key using its x and y coordinates.
 * 
 * @param[in]  Qx            Pointer to the x coordinate of the public key.
 * @param[in]  length_qx     Length of the x coordinate.
 * @param[in]  Qy            Pointer to the y coordinate of the public key.
 * @param[in]  length_qy     Length of the y coordinate.
 * @param[out] compressed_key Pointer to the buffer where the compressed key will be stored.
 */
void API_ECDSA256_API_CP_compress_key(unsigned char *Qx, int length_qx, unsigned char *Qy, int length_qy, uint8_t *compressed_key);

#ifdef __cplusplus
}
#endif

#endif /* _EASY_ECC_H_ */
