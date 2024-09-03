#include "MemoryTrackerTest.h"

void test_initialize_trackers()
{
    initialize_trackers();
    printf("\n\nTest Initialize Trackers: Expected Free_Tracker_List to not be NULL, Actual %p\n", Free_Tracker_List);
}

void test_add_tracker_success()
{
    char data[100] = "Test data for memory tracking";
    int index = add_tracker(data, sizeof(data), 1);
    printf("Test Add Tracker (Success): Expected index >= 0, Actual %d\n", index);
}

void test_add_tracker_failure()
{
    char *data = NULL; // Invalid data pointer
    int index = add_tracker(data, 100, 1);
    printf("Test Add Tracker (Failure): Expected INVALID_INPUT_MT, Actual %d\n", index);
}

void test_verify_integrity_success()
{
    char data[100] = "Integrity check data";
    int index = add_tracker(data, sizeof(data), 0);
    MemoryTracker *tracker = &trackers[index];
    int result = verify_integrity(tracker);
    printf("Test Verify Integrity (Success): Expected 1, Actual %d\n", result);
}

void test_verify_integrity_failure()
{
    char data[100] = "Data will be corrupted";
    int index = add_tracker(data, sizeof(data), 0);
    MemoryTracker *tracker = &trackers[index];
    data[0] = 'X'; // Corrupt the data
    int result = verify_integrity(tracker);
    printf("Test Verify Integrity (Failure): Expected 0, Actual %d\n", result);
}

void test_update_tracker_success()
{
    char data[100] = "Initial data";
    char updatedData[150] = "Updated data with more content";
    int index = add_tracker(data, sizeof(data), 0);
    MemoryTracker *tracker = &trackers[index];
    int update_result = update_tracker(tracker, updatedData, sizeof(updatedData));
    printf("Test Update Tracker (Success): Expected MT_OK, Actual %d\n", update_result);
}

void test_update_tracker_failure()
{
    char data[100] = "Some data";
    int index = add_tracker(data, sizeof(data), 0);
    MemoryTracker *tracker = &trackers[index];
    int update_result = update_tracker(tracker, NULL, 150); // Invalid pointer
    printf("Test Update Tracker (Failure): Expected INVALID_INPUT_MT, Actual %d\n", update_result);
}

void test_remove_tracker_success()
{
    char data[50] = "Data to remove";
    int index = add_tracker(data, sizeof(data), 1);
    int result = remove_tracker(data);
    printf("Test Remove Tracker (Success): Expected MT_OK, Actual %d\n", result);
}

void test_remove_tracker_failure()
{
    char data[50] = "Data not tracked";
    int result = remove_tracker(data); // Attempting to remove untracked data
    printf("Test Remove Tracker (Failure): Expected INVALID_INPUT_MT, Actual %d\n", result);
}

void test_zeroize_and_free_all()
{
    char data1[50] = "Data to zeroize";
    char data2[60] = "More data to zeroize";
    add_tracker(data1, sizeof(data1), 1);
    add_tracker(data2, sizeof(data2), 1);
    zeroize_and_free_all();
    printf("Test Zeroize and Free All: Check console for all zeroized message and no remaining trackers.\n");
}

void MemoryTracker_tests()
{
    test_initialize_trackers();
    test_add_tracker_success();
    test_add_tracker_failure();
    test_verify_integrity_success();
    test_verify_integrity_failure();
    test_update_tracker_success();
    test_update_tracker_failure();
    test_remove_tracker_success();
    test_remove_tracker_failure();
    test_zeroize_and_free_all();
}
