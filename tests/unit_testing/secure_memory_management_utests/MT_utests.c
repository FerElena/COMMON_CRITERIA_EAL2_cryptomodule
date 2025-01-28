/**
 * @file MT_utest.c
 * @brief File containing the unitary testing of the Memory_tracking system
 */

#include "MT_utest.h"


// test_suite
Suite *MT_suite(void){
    Suite *s;
    TCase *tc_core;

    s = suite_create("Memory_tracker_utests");
    tc_core = tcase_create("Core_MT_utest");


    suite_add_tcase(s, tc_core);

    return s;
}


