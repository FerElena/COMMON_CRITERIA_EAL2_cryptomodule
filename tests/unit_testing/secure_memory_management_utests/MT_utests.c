/**
 * @file MT_utest.c
 * @brief File containing the unitary testing of the Memory_tracking system
 */

#include "MT_utest.h"

START_TEST(test_API_MT_initialize_trackers)
{
    // Check both pointers correctly start null
    ck_assert_ptr_null(Free_Tracker_List);
    ck_assert_ptr_null(Used_MT_trackers_List);

    // Initialize MT_trackers
    API_MT_initialize_trackers();

    // Check that the free tracker list is not NULL.
    ck_assert_ptr_nonnull(Free_Tracker_List); 
    // Check end of list is correct
    ck_assert_ptr_null(MT_trackers[MAX_MT_trackers - 1].next); 
    // Check MT_trackers are correctly linked in the free list
    for(int i = 0 ; i < MAX_MT_trackers - 1; i++){
        ck_assert_ptr_eq(MT_trackers[i].next, &MT_trackers[i + 1]);
    }
    // Ensure the free list starts at the first tracker.
    ck_assert_ptr_eq(Free_Tracker_List, &MT_trackers[0]);
}
END_TEST

START_TEST(test_get_free_tracker)
{
    API_MT_initialize_trackers(); // Ensure the system is initialized before testing
    
    MemoryTracker *tracker;

    // Fetch all available MT_trackers and verify the integrity of the free list.
    for (int i = 0; i < MAX_MT_trackers; i++) {
        tracker = get_free_tracker();
        ck_assert_ptr_nonnull(tracker); // Ensure a tracker is fetched

        // The fetched tracker should be detached from the free list.
        ck_assert_ptr_null(tracker->next);

        // Verify that the free list head updates correctly
        if (i < MAX_MT_trackers - 1) {
            ck_assert_ptr_eq(Free_Tracker_List, &MT_trackers[i + 1]);
        } else {
            ck_assert_ptr_null(Free_Tracker_List);
        }
    }

    // After fetching all MT_trackers, there should be no free MT_trackers left
    ck_assert_ptr_null(get_free_tracker()); 
}
END_TEST

START_TEST(test_return_tracker)
{
    API_MT_initialize_trackers(); // Ensure the system is initialized before testing

    // Fetch a tracker to work with.
    MemoryTracker *tracker = get_free_tracker();
    ck_assert_ptr_nonnull(tracker); // Ensure a tracker is fetched

    // Modify the next pointer of the tracker to something non-NULL.
    tracker->next = (MemoryTracker*) 0xDEADBEEF; // Some invalid address to check if it gets overwritten.

    // Return the tracker to the free list.
    return_tracker(tracker);

    // Check that the tracker is correctly inserted back into the free list.
    ck_assert_ptr_eq(Free_Tracker_List, tracker);
    ck_assert_ptr_ne( tracker -> next , (MemoryTracker*) 0xDEADBEEF); // Ensure the tracker next pointer is set to NULL.
    
    // Fetch all available MT_trackers from the free list and check the order.
    for (int i = 0; i < MAX_MT_trackers; i++) {
        MemoryTracker *t = get_free_tracker();
        ck_assert_ptr_nonnull(t);
    }

    // Ensure that no more free MT_trackers are available.
    ck_assert_ptr_null(get_free_tracker());
}

START_TEST(test_API_MT_add_tracker)
{
    void *ptr;
    int result;

    // Case 1: Null pointer
    ptr = NULL;
    result = API_MT_add_tracker(ptr, 100, 1); // Assuming 1 represents CSP
    ck_assert_int_eq(result, INVALID_INPUT_MT); // Should return invalid input error

    // Case 2: Negative size (simulated with unsigned overflow)
    result = API_MT_add_tracker(ptr, (size_t)(-100), 1); // Negative size
    ck_assert_int_eq(result, INVALID_INPUT_MT); // Should return invalid input error

    // Case 3: Invalid isCSP value (out of valid range)
    ptr = malloc(100);
    result = API_MT_add_tracker(ptr, 100, 2); // Suppose CSP value 2 is invalid
    ck_assert_int_eq(result, INVALID_INPUT_MT); // Should return invalid input error
    free(ptr);

    // Case 4: No more free MT_trackers available
    API_MT_initialize_trackers(); // Ensure the system is initialized
    unsigned char test_data[128];
    for (int i = 0; i < MAX_MT_trackers; i++) {
        result = API_MT_add_tracker(test_data, 128, 1);
        ck_assert_int_ge(result, 0); // All results should be valid indices
    }
    
    // One more addition should fail due to lack of free MT_trackers
    result = API_MT_add_tracker(test_data, 128, 1);
    ck_assert_int_eq(result, MT_NO_MORE_MT_trackers); // Should indicate no more MT_trackers available

    API_MT_initialize_trackers(); // Re-initialize MT_trackers

    // Case 6: Successful addition
    ptr = malloc(50);
    result = API_MT_add_tracker(ptr, 50, 0); // This should succeed
    ck_assert_int_ge(result, 0); // Valid index should be returned
    
    MemoryTracker *tracker = &MT_trackers[result];
    ck_assert_ptr_eq(tracker->ptr, ptr); // Verify pointer match
    ck_assert_int_eq(tracker->size, 50); // Verify size match
    ck_assert_int_eq(tracker->IsCSP, 0); // Verify CSP flag
    ck_assert_int_eq(API_MT_verify_integrity(tracker), MT_OK); // Ensure integrity
    
    free(ptr);
}
END_TEST

START_TEST(test_API_MT_verify_integrity)
{
    void *ptr;
    int result;
    API_MT_initialize_trackers(); // Ensure the system is initialized

    // Case 1: Null tracker
    result = API_MT_verify_integrity(NULL);
    ck_assert_int_eq(result, INVALID_INPUT_MT);

    // Case 2: Integrity intact
    char data[100] = "Data to verify integrity";
    int index = API_MT_add_tracker(data, sizeof(data), 0);
    MemoryTracker *tracker = &MT_trackers[index];
    result = API_MT_verify_integrity(tracker);
    ck_assert_int_eq(result, MT_OK);

    // Case 3: Data corrupted
    // Simulate data corruption
    data[0] = 'X';
    result = API_MT_verify_integrity(tracker);
    ck_assert_int_eq(result, MT_MEMORYVIOLATION);

}

START_TEST(test_API_MT_update_tracker)
{
    API_MT_initialize_trackers(); // Ensure the system is initialized
    // Case 1: Null tracker
    int result = API_MT_update_tracker(NULL);
    ck_assert_int_eq(result, INVALID_INPUT_MT);

    // Case 2: Tracker is updated successfully with valid data
    char data[100] = "Valid data to be tracked";
    int index = API_MT_add_tracker(data, sizeof(data), 0);
    MemoryTracker *tracker = &MT_trackers[index];
    ck_assert_int_ge(index,0);

    // Case 3: Data in memory tracker updates and maintains integrity
    memset(data, 'A', sizeof(data)); // Change the data content
    result = API_MT_update_tracker(tracker); // Update tracker with new data
    ck_assert_int_eq(result, MT_OK);
    ck_assert_int_eq(API_MT_verify_integrity(tracker), MT_OK); // Verify new integrity
}
END_TEST

START_TEST(test_API_MT_change_tracker)
{
    API_MT_initialize_trackers(); // Ensure the system is initialized
    int result;

    // Case 1: Null tracker
    result = API_MT_change_tracker(NULL, (void*)1, 100);
    ck_assert_int_eq(result, INVALID_INPUT_MT);

    // Case 2: Null new_ptr
    char data[100] = "Valid data for tracking";
    int index = API_MT_add_tracker(data, sizeof(data), 0);
    MemoryTracker *tracker = &MT_trackers[index];

    result = API_MT_change_tracker(tracker, NULL, 100);
    ck_assert_int_eq(result, INVALID_INPUT_MT);


    // Case 3: Successful tracker change
    char new_data[150] = "New data for tracking";
    result = API_MT_change_tracker(tracker, new_data, sizeof(new_data));
    ck_assert_int_eq(result, MT_OK);
    ck_assert_ptr_eq(tracker->ptr, new_data);
    ck_assert_int_eq(tracker->size, sizeof(new_data));
    ck_assert_int_eq(API_MT_verify_integrity(tracker), MT_OK);
}
END_TEST

START_TEST(test_API_MT_remove_tracker)
{
    int result;
    char data1[50] = "Data to remove";
    char data2[60] = "More data to remove";
    API_MT_initialize_trackers(); // Ensure the system is initialized

    // Case 1: Null pointer
    result = API_MT_remove_tracker(NULL);
    ck_assert_int_eq(result, INVALID_INPUT_MT);

    // Case 2: Pointer not tracked
    result = API_MT_remove_tracker(data1);
    ck_assert_int_eq(result, INVALID_INPUT_MT);

    // Case 3: Tracker is CSP and removal is successful with zeroization
    int index = API_MT_add_tracker(data1, sizeof(data1), 1);
    MemoryTracker *tracker1 = &MT_trackers[index];

    // Lock the memory to simulate actual scenario
    result = API_MT_remove_tracker(data1);
    ck_assert_int_eq(result, MT_OK);

    // Validate zeroization
    for (int i = 0; i < sizeof(data1); i++) {
        ck_assert(data1[i] != 'D');
    }

    // Case 4: Tracker is not CSP and removal is successful
    index = API_MT_add_tracker(data2, sizeof(data2), 0);
    MemoryTracker *tracker2 = &MT_trackers[index];

    result = API_MT_remove_tracker(data2);
    ck_assert_int_eq(result, MT_OK);

    // Ensure data is not zeroized since it's not CSP
    ck_assert_str_eq(data2, "More data to remove");

    // Case 5: Integrity violation before removal
    index = API_MT_add_tracker(data2, sizeof(data2), 0);
    MemoryTracker *tracker3 = &MT_trackers[index];

    // Corrupt the data so integrity check fails
    data2[0] = 'X';
    result = API_MT_remove_tracker(data2);
    ck_assert_int_eq(result, MT_MEMORYVIOLATION_BEFORE_DELETE);
}
END_TEST

START_TEST(test_API_MT_zeroize_and_free_all)
{
    char data1[50] = "Data to zeroize";
    char data2[60] = "More data to zeroize";
    char data3[70] = "Regular data to free";

    // Case 1: Zeroize CSPs and free all
    API_MT_initialize_trackers(); // Ensure the system is initialized; // Initialize the tracker system
    API_MT_add_tracker(data1, sizeof(data1), 1); // Add a CSP tracker
    API_MT_add_tracker(data2, sizeof(data2), 1); // Add another CSP tracker
    API_MT_add_tracker(data3, sizeof(data3), 0); // Add a regular tracker (non-CSP)

    // Lock memory to simulate actual scenario
    mlock(data1, sizeof(data1));
    mlock(data2, sizeof(data2));
    mlock(data3, sizeof(data3));

    // Call the function to zeroize and free all
    API_MT_zeroize_and_free_all();

    // Check that Used_MT_trackers_List is cleared
    ck_assert_ptr_null(Used_MT_trackers_List);

    // Validate zeroization of CSPs
    for (int i = 0; i < sizeof(data1); i++) {
        ck_assert(data1[i] == 0x55);
    }

    for (int i = 0; i < sizeof(data2); i++) {
        ck_assert(data2[i] == 0x55);
    }

    // Ensure regular data is not zeroized
    ck_assert_str_eq(data3, "Regular data to free");
    
    // Check that trackers are returned to the free list
    for (int i = 0; i < MAX_MT_trackers; i++) {
        MemoryTracker *tracker = get_free_tracker();
        ck_assert_ptr_nonnull(tracker);
    }
}
END_TEST

// test_suite
Suite *MT_suite(void){
    Suite *s;
    TCase *tc_core;

    s = suite_create("Memory_tracker_utests");
    tc_core = tcase_create("Core_MT_utest");

    // adding test cases
    tcase_add_test(tc_core, test_API_MT_initialize_trackers);
    tcase_add_test(tc_core, test_get_free_tracker);
    tcase_add_test(tc_core, test_return_tracker);
    tcase_add_test(tc_core, test_API_MT_add_tracker);
    tcase_add_test(tc_core, test_API_MT_verify_integrity);
    tcase_add_test(tc_core, test_API_MT_update_tracker);
    tcase_add_test(tc_core, test_API_MT_change_tracker);
    tcase_add_test(tc_core, test_API_MT_remove_tracker);
    tcase_add_test(tc_core, test_API_MT_zeroize_and_free_all);

    suite_add_tcase(s, tc_core);

    return s;
}


