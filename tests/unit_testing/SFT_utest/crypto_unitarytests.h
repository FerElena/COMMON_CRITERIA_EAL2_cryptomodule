/**
 * @file crypto_unitarytests.h
 * @brief File containing the unitary testing of the crypto primitives in the module (is just a wraper of the selftests, because the selftest module can 
 *  check the correctness of the cryptoalgorithms by itself)
 */
#ifndef CRYPTO_UNITARYTESTS_H
#define CRYPTO_UNITARYTESTS_H

#include <check.h>

//include the already made selftests
#include "../../../src/crypto-selftests/AES256_CBC_Tests.h"
#include "../../../src/crypto-selftests/ECDSA256Tests.h"
#include "../../../src/crypto-selftests/HMACTests.h"
#include "../../../src/crypto-selftests/SHA256Tests.h"

Suite *crypto_suite(void);

#endif