/**
 * @file utests_main.c
 * @brief File containing the main function calling all the unitary tests
 */

/****************************************************************************************************************
 * Compiler include files
 ****************************************************************************************************************/

#include <check.h>

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "secure_memory_management_utests/MM_utest.h"
#include "secure_memory_management_utests/MT_utest.h"

// unitary test execution
int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    //////////////////////////////// SECURE MEMORY MANAGEMENT UNITARY TESTS/////////////////////////////////////////////

    // Dynamic memory management unitary tests
    s = MM_suite();
    sr= srunner_create(s);


    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr); 

    // Dynamic memory management unitary tests
    s = MT_suite();
    sr= srunner_create(s);


    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr); 

    return (number_failed == 0) ? 0 : 1;
}