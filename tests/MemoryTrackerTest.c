#include "MemoryTrackerTest.h"

#define GREEN "\x1B[32m"
#define RED "\x1B[31m"
#define RESET "\x1B[0m"

void test_initialize_trackers()
{
    initialize_trackers();
    printf("\n\nTest Initialize Trackers: %s%s%s\n", Free_Tracker_List != NULL ? GREEN : RED, Free_Tracker_List != NULL ? "Passed" : "Failed", RESET);
}

void test_add_tracker_success()
{
    char data[100] = "Test data for memory tracking";
    int index = add_tracker(data, sizeof(data), 1);
    printf("Test Add Tracker (Success): %s%s%s\n", index >= 0 ? GREEN : RED, index >= 0 ? "Passed" : "Failed", RESET);
}

void test_add_tracker_failure()
{
    char *data = NULL; // Invalid data pointer
    int index = add_tracker(data, 100, 1);
    printf("Test Add Tracker (Failure): %s%s%s\n", index == INVALID_INPUT_MT ? GREEN : RED, index == INVALID_INPUT_MT ? "Passed" : "Failed", RESET);
}

void test_verify_integrity_success()
{
    char data[100] = "Integrity check data";
    int index = add_tracker(data, sizeof(data), 0);
    MemoryTracker *tracker = &trackers[index];
    int result = verify_integrity(tracker);
    printf("Test Verify Integrity (Success): %s%s%s\n", result == MT_OK ? GREEN : RED, result == MT_OK ? "Passed" : "Failed", RESET);
}

void test_verify_integrity_failure()
{
    char data[100] = "Data will be corrupted";
    int index = add_tracker(data, sizeof(data), 0);
    MemoryTracker *tracker = &trackers[index];
    data[0] = 'X'; // Corrupt the data
    int result = verify_integrity(tracker);
    printf("Test Verify Integrity (Failure): %s%s%s\n", result == MEMORYVIOLATION ? GREEN : RED, result == MEMORYVIOLATION ? "Passed" : "Failed", RESET);
}

void test_update_tracker_success()
{
    char data[100] = "Initial data";
    char updatedData[150] = "Updated data with more content";
    int index = add_tracker(data, sizeof(data), 0);
    MemoryTracker *tracker = &trackers[index];
    int update_result = update_tracker(tracker, updatedData, sizeof(updatedData));
    printf("Test Update Tracker (Success): %s%s%s\n", update_result == MT_OK ? GREEN : RED, update_result == MT_OK ? "Passed" : "Failed", RESET);
}

void test_update_tracker_failure()
{
    char data[100] = "Some data";
    int index = add_tracker(data, sizeof(data), 0);
    MemoryTracker *tracker = &trackers[index];
    int update_result = update_tracker(tracker, NULL, 150); // Invalid pointer
    printf("Test Update Tracker (Failure): %s%s%s\n", update_result == INVALID_INPUT_MT ? GREEN : RED, update_result == INVALID_INPUT_MT ? "Passed" : "Failed", RESET);
}

void test_remove_tracker_success()
{
    char data[50] = "Data to remove";
    int index = add_tracker(data, sizeof(data), 1);
    int result = remove_tracker(data);
    printf("Test Remove Tracker (Success): %s%s%s\n", result == MT_OK ? GREEN : RED, result == MT_OK ? "Passed" : "Failed", RESET);
}

void test_remove_tracker_failure()
{
    char data[50] = "Data not tracked";
    int result = remove_tracker(data); // Attempting to remove untracked data
    printf("Test Remove Tracker (Failure): %s%s%s\n", result == INVALID_INPUT_MT ? GREEN : RED, result == INVALID_INPUT_MT ? "Passed" : "Failed", RESET);
}

void test_zeroize_and_free_all()
{
    char data1[50] = "Data to zeroize";
    char data2[60] = "More data to zeroize";
    add_tracker(data1, sizeof(data1), 1);
    add_tracker(data2, sizeof(data2), 1);
    zeroize_and_free_all();
    printf("Test Zeroize and Free All: %sCheck console for all zeroized message and no remaining trackers.%s\n", GREEN, RESET);
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
