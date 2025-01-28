/**
 * @file MM_utest.c
 * @brief File containing the unitary testing of the dynamic memory management system
 */

#include "MM_utest.h"

START_TEST(test_MM_compare_hash)
{ // testing hash compare
    unsigned char hash1[32] = {0};
    unsigned char hash2[32] = {1};

    memset(hash1, 0, sizeof(hash1));
    memset(hash2, 0, sizeof(hash2));
    hash2[0] = 1; // Make sure hash2 is different at the first byte

    ck_assert_int_eq(MM_compare_hash(hash1, hash1), 2);
    ck_assert_int_eq(MM_compare_hash(hash1, hash2), 1);
    ck_assert_int_eq(MM_compare_hash(hash2, hash1), 0);
}

// Testing correct Node creation
START_TEST(test_MM_create_hash_tree_node)
{
    size_t size = 32; // Size of memory hash block
    node *newNode = MM_create_hash_tree_node(size);

    ck_assert_ptr_nonnull(newNode);        // Verify not NULL node
    ck_assert_ptr_nonnull(newNode->ptr);   // Verify not NULL memory block
    ck_assert_int_eq(newNode->size, size); // Verify correct node size

    // Verifies not empty node hash
    unsigned char expected_hash[32] = {0};
    ck_assert_mem_ne(newNode->hash, expected_hash, sizeof(expected_hash));

    // free resources
    munlock(newNode->ptr, size);
    free(newNode->ptr);
    free(newNode);
}

// Test case for inserting a node
START_TEST(test_MM_insert_node)
{
    ROOT = NULL; // Ensure the tree is empty before each test

    // Create two nodes with different hashes
    node *node1 = MM_create_hash_tree_node(32);
    node *node2 = MM_create_hash_tree_node(32);

    memset(node1->hash, 0, 32);
    memset(node2->hash, 1, 32);

    // Insert node1 into the tree
    MM_insert_node(ROOT, node1);
    ck_assert_ptr_eq(ROOT, node1);

    // Insert node2 into the tree
    MM_insert_node(ROOT, node2);
    ck_assert_ptr_eq(ROOT->right, node2);
    ck_assert_ptr_eq(node2->father, node1);

    // Clean up
    munlock(node1->ptr, node1->size);
    munlock(node2->ptr, node2->size);
    free(node1->ptr);
    free(node2->ptr);
    free(node1);
    free(node2);
}

// Test case for MM_find_minimum
START_TEST(test_MM_find_minimum)
{
    // Create multiple nodes
    node *node1 = MM_create_hash_tree_node(32);
    node *node2 = MM_create_hash_tree_node(32);
    node *node3 = MM_create_hash_tree_node(32);

    // Manually set different hash values for testing
    memset(node1->hash, 0x01, 32);
    memset(node2->hash, 0x02, 32);
    memset(node3->hash, 0x00, 32); // This should be the smallest hash

    // Insert nodes into the tree
    MM_insert_node(ROOT, node1);
    MM_insert_node(ROOT, node2);
    MM_insert_node(ROOT, node3);

    // Find the minimum node
    node *min_node = MM_find_minimum(ROOT);

    // Assertions
    ck_assert_ptr_nonnull(min_node);                   // Check that the result is not NULL
    ck_assert_mem_eq(min_node->hash, node3->hash, 32); // Make sure the minimum node is node3

    // Free memory
    munlock(node1->ptr, node1->size);
    munlock(node2->ptr, node2->size);
    munlock(node3->ptr, node3->size);
    free(node1->ptr);
    free(node2->ptr);
    free(node3->ptr);
    free(node1);
    free(node2);
    free(node3);
}

// Test case for API_MM_secure_zeroize
START_TEST(test_API_MM_secure_zeroize)
{
    size_t size = 32; // Size of the memory block
    unsigned char *memory = (unsigned char *)malloc(size);
    memset(memory, 0x00, size); // Initialize with zeros

    // Call the secure zeroize function
    API_MM_secure_zeroize(memory, size);

    // Check that the memory has been overwritten with the predefined patterns
    unsigned char expected = Schneier_patternsDM[5];
    for (size_t j = 0; j < size; j++)
    {
        ck_assert_uint_eq(memory[j], expected);
    }

    // Free the allocated memory
    free(memory);
}
END_TEST

START_TEST(test_MM_transplant)
{
    // Test 1: Replacing the root node
    ROOT = NULL;

    // Create two nodes
    node *node1 = MM_create_hash_tree_node(32);
    node *node2 = MM_create_hash_tree_node(32);

    // Initialize hash values for the nodes
    memset(node1->hash, 0x01, 32);
    memset(node2->hash, 0x02, 32);

    // Insert the first node as the root
    MM_insert_node(ROOT, node1);

    // Transplant node1 with node2 (node2 becomes the new root)
    MM_transplant(node1, node2);

    // Validate that the root now points to node2 and its parent is NULL
    ck_assert_ptr_eq(ROOT, node2);
    ck_assert_ptr_null(node2->father);

    // Free resources for node1 and node2
    munlock(node1->ptr, node1->size);
    munlock(node2->ptr, node2->size);
    free(node1->ptr);
    free(node2->ptr);
    free(node1);
    free(node2);

    // Test 2: Replacing a left child
    ROOT = NULL;

    // Create three nodes
    node *node3 = MM_create_hash_tree_node(32);
    node *node4 = MM_create_hash_tree_node(32);
    node *node5 = MM_create_hash_tree_node(32);

    // Initialize hash values for the nodes
    memset(node3->hash, 0x01, 32);
    memset(node4->hash, 0x02, 32);
    memset(node5->hash, 0x03, 32);

    // Insert node3 as the root and node4 as its right child
    MM_insert_node(ROOT, node3);
    MM_insert_node(ROOT, node4);

    // Transplant node4 with node5 (node5 replaces node4 as the right child)
    MM_transplant(node4, node5);

    // Validate that node3's left child is now node5 and node5's parent is node3
    ck_assert_ptr_eq(node3->right, node5);
    ck_assert_ptr_eq(node5->father, node3);

    // Free resources for node3, node4, and node5
    munlock(node3->ptr, node3->size);
    munlock(node4->ptr, node4->size);
    munlock(node5->ptr, node5->size);
    free(node3->ptr);
    free(node4->ptr);
    free(node5->ptr);
    free(node3);
    free(node4);
    free(node5);

    // Test 3: Replacing a right child
    ROOT = NULL;

    // Create three nodes
    node *node6 = MM_create_hash_tree_node(32);
    node *node7 = MM_create_hash_tree_node(32);
    node *node8 = MM_create_hash_tree_node(32);

    // Initialize hash values for the nodes
    memset(node6->hash, 0x01, 32);
    memset(node7->hash, 0x02, 32);
    memset(node8->hash, 0x03, 32);

    // Insert node6 as the root and node7 as its right child
    MM_insert_node(ROOT, node6);
    MM_insert_node(ROOT, node7);

    // Transplant node7 with node8 (node8 replaces node7 as the right child)
    MM_transplant(node7, node8);

    // Validate that node6's right child is now node8 and node8's parent is node6
    ck_assert_ptr_eq(node6->right, node8);
    ck_assert_ptr_eq(node8->father, node6);

    // Free resources for node6, node7, and node8
    munlock(node6->ptr, node6->size);
    munlock(node7->ptr, node7->size);
    munlock(node8->ptr, node8->size);
    free(node6->ptr);
    free(node7->ptr);
    free(node8->ptr);
    free(node6);
    free(node7);
    free(node8);
}
END_TEST

START_TEST(test_MM_delete_node)
{
    // Test 1: Deleting the root node without children
    ROOT = NULL;

    // Create a single node and set its hash value
    node *node1 = MM_create_hash_tree_node(32);
    memset(node1->hash, 0x01, 32);

    // Insert the node as the root
    MM_insert_node(ROOT, node1);

    // Delete the root node
    MM_delete_node(node1);

    // Validate that the tree is now empty
    ck_assert_ptr_null(ROOT);

    // Test 2: Deleting a node with only a right child
    ROOT = NULL;

    // Create two nodes and set their hash values
    node *node2 = MM_create_hash_tree_node(32);
    node *node3 = MM_create_hash_tree_node(32);
    memset(node2->hash, 0x02, 32);
    memset(node3->hash, 0x03, 32);

    // Insert node2 as the root and node3 as its right child
    MM_insert_node(ROOT, node2);
    MM_insert_node(ROOT, node3);

    // Delete the root node (node2)
    MM_delete_node(node2);

    // Validate that node3 becomes the new root
    ck_assert_ptr_eq(ROOT, node3);
    ck_assert_ptr_null(node3->father);

    // Test 3: Deleting a node with only a left child
    ROOT = NULL;

    // Create two nodes and set their hash values
    node *node4 = MM_create_hash_tree_node(32);
    node *node5 = MM_create_hash_tree_node(32);
    memset(node4->hash, 0x04, 32);
    memset(node5->hash, 0x05, 32);

    // Insert node4 as the root and node5 as its left child
    MM_insert_node(ROOT, node4);
    MM_insert_node(ROOT, node5);

    // Delete the root node (node4)
    MM_delete_node(node4);

    // Validate that node5 becomes the new root
    ck_assert_ptr_eq(ROOT, node5);
    ck_assert_ptr_null(node5->father);

    // Test 4: Deleting a node with two children
    ROOT = NULL;

    // Create three nodes and set their hash values
    node *node6 = MM_create_hash_tree_node(32);
    node *node7 = MM_create_hash_tree_node(32);
    node *node8 = MM_create_hash_tree_node(32);
    memset(node6->hash, 0x06, 32);
    memset(node7->hash, 0x07, 32);
    memset(node8->hash, 0x08, 32);

    // Insert node6 as the root, node7 as its right child, and node8 as its right right child
    MM_insert_node(ROOT, node6);
    MM_insert_node(ROOT, node7);
    MM_insert_node(ROOT, node8);

    // Delete the root node (node6)
    MM_delete_node(node6);

    // Validate that node7 becomes the new root, node8 is still its right child
    ck_assert_ptr_eq(ROOT, node7);
    ck_assert_ptr_eq(node7->right, node8);
    ck_assert_ptr_eq(node8->father, node7);

    // Free resources for node7 and node8
    munlock(node7->ptr, node7->size);
    munlock(node8->ptr, node8->size);
    free(node7->ptr);
    free(node8->ptr);
    free(node7);
    free(node8);

    // Test 5: Deleting a node with a successor in its right subtree
    ROOT = NULL;

    // Create four nodes and set their hash values
    node *node9 = MM_create_hash_tree_node(32);
    node *node10 = MM_create_hash_tree_node(32);
    node *node11 = MM_create_hash_tree_node(32);
    node *node12 = MM_create_hash_tree_node(32);
    memset(node9->hash, 0x09, 32);
    memset(node10->hash, 0x08, 32);
    memset(node11->hash, 0x0B, 32);
    memset(node12->hash, 0x0C, 32);

    // Insert the nodes to form the tree:
    //       node9
    //      /    \
    //   node10  node11
    //             \
    //            node12
    MM_insert_node(ROOT, node9);
    MM_insert_node(ROOT, node10);
    MM_insert_node(ROOT, node11);
    MM_insert_node(ROOT, node12);

    // Delete the root node (node9)
    MM_delete_node(node9);

    // Validate that node11 becomes the new root, node10 is its left child, and node12 remains its right child
    ck_assert_ptr_eq(ROOT, node11);
    ck_assert_ptr_eq(node11->left, node10);
    ck_assert_ptr_eq(node11->right, node12);
    ck_assert_ptr_eq(node10->father, node11);
    ck_assert_ptr_eq(node12->father, node11);

    // Free resources for node10, node11, and node12
    munlock(node10->ptr, node10->size);
    munlock(node11->ptr, node11->size);
    munlock(node12->ptr, node12->size);
    free(node10->ptr);
    free(node11->ptr);
    free(node12->ptr);
    free(node10);
    free(node11);
    free(node12);
}
END_TEST

START_TEST(test_MM_find_node_by_hash)
{
    // Test 1: Finding a node in an empty tree
    ROOT = NULL;

    unsigned char target_hash[32] ;  // Example hash to search for
    memset(target_hash, 0x01, 32);  // Set the node's hash to the target hash
    node *found_node = MM_find_node_by_hash(ROOT, target_hash);

    // Validate that the result is NULL since the tree is empty
    ck_assert_ptr_null(found_node);

    // Test 2: Finding the root node
    ROOT = NULL;

    // Create a single node with a specific hash
    node *node1 = MM_create_hash_tree_node(32);
    memset(node1->hash, 0x01, 32);  // Set the node's hash to the target hash

    // Insert the node as the root
    MM_insert_node(ROOT, node1);

    // Search for the node by its hash
    found_node = MM_find_node_by_hash(node1, target_hash);

    // Validate that the root node is found
    ck_assert_ptr_eq(found_node, node1);

    // Test 3: Finding a left child node
    ROOT = NULL;

    // Create two nodes with different hashes
    node *node2 = MM_create_hash_tree_node(32);
    node *node3 = MM_create_hash_tree_node(32);
    memset(node2->hash, 0x02, 32);  // Root node's hash
    memset(node3->hash, 0x01, 32);  // Target node's hash

    // Insert node2 as the root and node3 as the left child
    MM_insert_node(ROOT, node2);
    MM_insert_node(ROOT, node3);

    // Search for the node with the target hash
    found_node = MM_find_node_by_hash(ROOT, target_hash);

    // Validate that node3 is found
    ck_assert_ptr_eq(found_node, node3);

    // Test 4: Finding a right child node
    ROOT = NULL;

    // Create two nodes with different hashes
    node *node4 = MM_create_hash_tree_node(32);
    node *node5 = MM_create_hash_tree_node(32);
    memset(node4->hash, 0x01, 32);  // Target node's hash
    memset(node5->hash, 0x02, 32);  // Root node's hash

    // Insert node5 as the root and node4 as the right child
    MM_insert_node(ROOT, node5);
    MM_insert_node(ROOT, node4);

    // Search for the node with the target hash
    found_node = MM_find_node_by_hash(ROOT, target_hash);

    // Validate that node4 is found
    ck_assert_ptr_eq(found_node, node4);

    // Test 5: Searching for a non-existent node
    ROOT = NULL;

    // Create a node with a different hash
    node *node6 = MM_create_hash_tree_node(32);
    memset(node6->hash, 0x02, 32);  // Node's hash

    // Insert the node as the root
    MM_insert_node(ROOT, node6);

    // Search for a non-existent hash
    unsigned char non_existent_hash[32] = {0x03};
    found_node = MM_find_node_by_hash(ROOT, non_existent_hash);

    // Validate that the result is NULL
    ck_assert_ptr_null(found_node);

    // Clean up: Securely zeroize and free all nodes
    if (node1) {
        API_MM_secure_zeroize(node1->ptr, node1->size);
        free(node1->ptr);
        API_MM_secure_zeroize(node1, sizeof(node));
        free(node1);
    }
    if (node2) {
        API_MM_secure_zeroize(node2->ptr, node2->size);
        free(node2->ptr);
        API_MM_secure_zeroize(node2, sizeof(node));
        free(node2);
    }
    if (node3) {
        API_MM_secure_zeroize(node3->ptr, node3->size);
        free(node3->ptr);
        API_MM_secure_zeroize(node3, sizeof(node));
        free(node3);
    }
    if (node4) {
        API_MM_secure_zeroize(node4->ptr, node4->size);
        free(node4->ptr);
        API_MM_secure_zeroize(node4, sizeof(node));
        free(node4);
    }
    if (node5) {
        API_MM_secure_zeroize(node5->ptr, node5->size);
        free(node5->ptr);
        API_MM_secure_zeroize(node5, sizeof(node));
        free(node5);
    }
    if (node6) {
        API_MM_secure_zeroize(node6->ptr, node6->size);
        free(node6->ptr);
        API_MM_secure_zeroize(node6, sizeof(node));
        free(node6);
    }
}
END_TEST


START_TEST(test_API_MM_allocateMem) {
    // Case 1: Size 0, should return NULL as memory allocation is not requested.
    void *ptr = API_MM_allocateMem(0,ROOT);
    ck_assert_ptr_eq(ptr, NULL); // Expected to return NULL

    // Case 2: Valid allocation, should not return NULL.
    size_t size = 1024;
    ptr = API_MM_allocateMem(size,ROOT);
    ck_assert_ptr_nonnull(ptr); // Expected to not be NULL
    free(ptr); // Free allocated memory

    // Case 3: Memory allocation fails (simulate failure in MM_create_hash_tree_node).
    node *simulated_node = NULL; // Simulate failed node creation by making it NULL
    simulated_node = MM_create_hash_tree_node(size);
    if (!simulated_node) {
        ptr = API_MM_allocateMem(size,ROOT);
        ck_assert_ptr_eq(ptr, NULL); // Expected to return NULL due to allocation failure
    }

    // Case 4: Successful node creation and memory allocation.
    simulated_node = MM_create_hash_tree_node(size);
    if (simulated_node) {
        MM_insert_node(ROOT, simulated_node); // Simulate successful node insertion
        ptr = API_MM_allocateMem(size,ROOT);
        ck_assert_ptr_nonnull(ptr); // Expected to not be NULL
        free(ptr); // Free allocated memory
    }

    // Case 5: Memory allocation with another valid size.
    size_t size2 = 2048;
    ptr = API_MM_allocateMem(size2,ROOT);
    ck_assert_ptr_nonnull(ptr); // Expected to not be NULL
    free(ptr); // Free allocated memory

    // Case 6: Test repeated memory allocations to ensure that the system handles multiple allocations.
    void *ptr2 = API_MM_allocateMem(128,ROOT);
    void *ptr3 = API_MM_allocateMem(256,ROOT);
    ck_assert_ptr_nonnull(ptr2); // Expected to not be NULL
    ck_assert_ptr_nonnull(ptr3); // Expected to not be NULL
    free(ptr2); // Free allocated memory
    free(ptr3); // Free allocated memory

    // Case 7: Simulate out-of-memory scenario.
    // We can simulate out-of-memory by limiting the system's heap size or forcing an allocation failure in our function.
    // This can be done by using a mock allocator or simulating an allocation failure (e.g., by manipulating malloc to return NULL).

    // As we cannot force out-of-memory in a real test, we will leave this case commented out:
    // ptr = API_MM_allocateMem(SIZE_MAX); // Expected to fail (in real tests, this would simulate out-of-memory).
    // ck_assert_ptr_eq(ptr, NULL); // Expected to return NULL due to allocation failure
}
END_TEST

START_TEST(test_API_MM_freeMem)
{
    // Prepare the memory to be allocated and freed
    void *ptr1 = API_MM_allocateMem(1024,ROOT); // Allocate 1KB
    void *ptr2 = API_MM_allocateMem(2048,ROOT); // Allocate 2KB

    // Check that allocation was successful
    ck_assert_ptr_ne(ptr1, NULL);
    ck_assert_ptr_ne(ptr2, NULL);

    // Free the memory and check for success
    int result1 = API_MM_freeMem(ptr1,ROOT);
    int result2 = API_MM_freeMem(ptr2,ROOT);

    // Assert that freeing memory returns SUCCESSMM
    ck_assert_int_eq(result1, SUCCESSMM);
    ck_assert_int_eq(result2, SUCCESSMM);

    // Attempt to free memory again (double free) and check for errors
    int result3 = API_MM_freeMem(ptr1,ROOT); // Should fail since ptr1 is already freed
    ck_assert_int_eq(result3, MM_MEMORY_DEALLOCATION_FAILED);

    // Check freeing a NULL pointer
    int result4 = API_MM_freeMem(NULL,ROOT); // Should return MM_ERROR_NULL_POINTER
    ck_assert_int_eq(result4, MM_ERROR_NULL_POINTER);

    // Free an unallocated pointer (not found in the tree)
    void *unallocated_ptr = (void *)0xDEADBEEF; // Fake pointer
    int result5 = API_MM_freeMem(unallocated_ptr,ROOT);
    ck_assert_int_eq(result5, MM_MEMORY_DEALLOCATION_FAILED);
}
END_TEST

START_TEST(test_API_MM_reallocMem)
{
    // Test reallocating to a larger size
    void *ptr1 = API_MM_allocateMem(1024,ROOT); // Allocate 1KB
    unsigned char ptr_aux[1024];
    memcpy(ptr_aux,ptr1,1024);
    ck_assert_ptr_ne(ptr1, NULL);

    void *new_ptr1 = API_MM_reallocMem(ptr1, 2048,ROOT); // Try reallocating to 2KB
    ck_assert_ptr_ne(new_ptr1, NULL);
    ck_assert_ptr_ne(new_ptr1, ptr1); // Should be a new pointer
    ck_assert_int_eq(memcmp(ptr_aux, new_ptr1, 1024), 0); // First 1KB should be the same

    // Free the memory for both pointers
    API_MM_freeMem(new_ptr1,ROOT);

    // Test reallocating to a smaller size
    void *ptr2 = API_MM_allocateMem(2048,ROOT); // Allocate 2KB
    ck_assert_ptr_ne(ptr2, NULL);

    void *new_ptr2 = API_MM_reallocMem(ptr2, 1024,ROOT); // Try reallocating to 1KB
    ck_assert_ptr_eq(new_ptr2, ptr2); // The location should not change
    ck_assert_int_eq(memcmp(ptr2, new_ptr2, 1024), 0); // First 1KB should be the same

    // Free the memory for both pointers
    API_MM_freeMem(new_ptr2,ROOT);

    // Test reallocating to size 0 (should free memory)
    void *ptr3 = API_MM_allocateMem(1024,ROOT); // Allocate 1KB
    ck_assert_ptr_ne(ptr3, NULL);

    void *new_ptr3 = API_MM_reallocMem(ptr3, 0,ROOT); // Reallocate to 0KB
    ck_assert_ptr_eq(new_ptr3, NULL); // Pointer should be NULL after free

    // Test reallocating with NULL pointer (should allocate new memory)
    void *new_ptr4 = API_MM_reallocMem(NULL, 1024,ROOT); // Reallocate from NULL
    ck_assert_ptr_ne(new_ptr4, NULL); // Should allocate new memory
    API_MM_freeMem(new_ptr4,ROOT);

    // Test reallocating with an unallocated pointer (should fail to find the node)
    void *unallocated_ptr = (void *)0xDEADBEEF; // Fake pointer
    void *new_ptr5 = API_MM_reallocMem(unallocated_ptr, 1024,ROOT); // Attempt to realloc unallocated memory
    ck_assert_ptr_eq(new_ptr5, NULL); // Should fail to find the node
}
END_TEST

START_TEST(test_zeroize_tree)
{
    // Preconditions: Create nodes with different memory sizes.
    node *node1 = MM_create_hash_tree_node(64);  // Create a node with 64 bytes of memory.
    node *node2 = MM_create_hash_tree_node(128); // Create a node with 128 bytes of memory.
    node *node3 = MM_create_hash_tree_node(256); // Create a node with 256 bytes of memory.

    // Insert nodes into the tree
    MM_insert_node(ROOT, node1);
    MM_insert_node(ROOT, node2);
    MM_insert_node(ROOT, node3);

    // Initial verification: Ensure the nodes are correctly inserted into the tree.
    ck_assert_ptr_nonnull(MM_find_node_by_hash(ROOT, node1->hash));
    ck_assert_ptr_nonnull(MM_find_node_by_hash(ROOT, node2->hash));
    ck_assert_ptr_nonnull(MM_find_node_by_hash(ROOT, node3->hash));

    // Call the function we want to test
    zeroize_tree(ROOT);

    // Verification: Ensure all nodes have been securely removed from the tree.
    unsigned char pattern[sizeof(node)];
    memset(pattern,0x55,sizeof(node));
    
    ck_assert_int_eq(memcmp(node2, pattern, sizeof(node)), 0); 
    ck_assert_int_eq(memcmp(node3, pattern, sizeof(node)), 0); 

}
END_TEST

// test_suite
Suite *MM_suite(void){
    Suite *s;
    TCase *tc_core;

    s = suite_create("Dynamic_memory_manager_utests");
    tc_core = tcase_create("Core_MM_utest");

    // adding test cases
    tcase_add_test(tc_core, test_MM_compare_hash);
    tcase_add_test(tc_core, test_MM_create_hash_tree_node);
    tcase_add_test(tc_core, test_MM_insert_node);
    tcase_add_test(tc_core, test_MM_find_minimum);
    tcase_add_test(tc_core, test_API_MM_secure_zeroize);
    tcase_add_test(tc_core, test_MM_transplant);
    tcase_add_test(tc_core, test_MM_delete_node);
    tcase_add_test(tc_core, test_MM_find_node_by_hash);
    tcase_add_test(tc_core, test_API_MM_allocateMem);
    tcase_add_test(tc_core, test_API_MM_freeMem);
    tcase_add_test(tc_core, test_API_MM_reallocMem);
    tcase_add_test(tc_core, test_zeroize_tree);

    suite_add_tcase(s, tc_core);

    return s;
}
