/**
 * @file crypto_unitarytests.c
 * @brief File containing the unitary testing of the crypto primitives in the module (is just a wraper of the selftests, because the selftest module can 
 *  check the correctness of the cryptoalgorithms by itself)
 */

#include "crypto_unitarytests.h"

START_TEST(test_crypto_primitives)
{
    ck_assert_int_eq(API_SFT_SHA256Tests(),1); 
    ck_assert_int_eq(API_SFT_HMAC256_SHA256_Test(),1);
    ck_assert_int_eq(API_SFT_AES256_CBC_Tests(),1);
    ck_assert_int_eq(API_SFT_ECDSA256_SHA256_Tests(),1);
}

// test_suite
Suite *crypto_suite(void){
    Suite *s;
    TCase *tc_core;

    s = suite_create("cryptographic_primitives_utests");
    tc_core = tcase_create("Core_crypto_utest");

    // adding test cases
    tcase_add_test(tc_core, test_crypto_primitives);

    suite_add_tcase(s, tc_core);

    return s;
}
