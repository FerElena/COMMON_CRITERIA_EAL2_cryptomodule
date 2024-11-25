#include "DmemmanagerTest.h"

#define GREEN "\x1B[32m"
#define RED "\x1B[31m"
#define RESET "\x1B[0m"

void test_MM_compare_hash() {
    unsigned char hash1[32] = {0};
    unsigned char hash2[32] = {1};
    memset(hash1, 0, sizeof(hash1));
    memset(hash2, 0, sizeof(hash2));
    hash2[0] = 1; // Make sure hash2 is different at the first byte

    printf("\n\nTesting MM_compare_hash:\n");
    printf("  Result when arrays are equal: %s%s%s\n", MM_compare_hash(hash1, hash1) == 2 ? GREEN : RED, MM_compare_hash(hash1, hash1) == 2 ? "Passed" : "Failed", RESET);
    printf("  Result when arr1 < arr2: %s%s%s\n", MM_compare_hash(hash1, hash2) == 1 ? GREEN : RED, MM_compare_hash(hash1, hash2) == 1 ? "Passed" : "Failed", RESET);
    printf("  Result when arr1 > arr2: %s%s%s\n", MM_compare_hash(hash2, hash1) == 0 ? GREEN : RED, MM_compare_hash(hash2, hash1) == 0 ? "Passed" : "Failed", RESET);
}

void test_MM_hash_address() {
    void *ptr = malloc(1); // Allocate 1 byte of memory to test
    unsigned char out[32];
    MM_hash_address(ptr, out);

    printf("Testing MM_hash_address:\n");
    printf("  Hash generated (visual check): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", out[i]);
    }
    printf("\n");

    free(ptr);
}

void test_MM_create_hash_tree_node() {
    size_t size = 64;
    node *newNode = MM_create_hash_tree_node(size);

    printf("Testing MM_create_hash_tree_node:\n");
    printf("  Node creation: %s%s%s\n", newNode != NULL ? GREEN : RED, newNode != NULL ? "Passed" : "Failed", RESET);
    if (newNode) {
        printf("  Memory allocation for node: %s%s%s\n", newNode->ptr != NULL ? GREEN : RED, newNode->ptr != NULL ? "Passed" : "Failed", RESET);
        printf("  Node size initialization: %s%s%s\n", newNode->size == size ? GREEN : RED, newNode->size == size ? "Passed" : "Failed", RESET);
        printf("  Node structure initialization: %s%s%s\n", (newNode->left == NULL && newNode->right == NULL && newNode->father == NULL) ? GREEN : RED, (newNode->left == NULL && newNode->right == NULL && newNode->father == NULL) ? "Passed" : "Failed", RESET);

        free(newNode->ptr);
        free(newNode);
    }
}

void test_MM_insert_node() {
    printf("Testing MM_insert_node:\n");
    ROOT = NULL; // Ensure ROOT is NULL at start
    node *root = MM_create_hash_tree_node(10);
    node *child = MM_create_hash_tree_node(20);
    MM_insert_node(ROOT, root); // Insert root node first
    MM_insert_node(ROOT, child); // Now insert child

    printf("  Root check: %s%s%s\n", ROOT == root ? GREEN : RED, ROOT == root ? "Passed" : "Failed", RESET);
    printf("  Child insertion check: %s%s%s\n", (root->left == child || root->right == child) ? GREEN : RED, (root->left == child || root->right == child) ? "Passed" : "Failed", RESET);

    free(root->ptr);
    free(root);
    free(child->ptr);
    free(child);
}

void test_MM_delete_node() {
    printf("Testing MM_delete_node:\n");
    ROOT = NULL;
    node *root = MM_create_hash_tree_node(10);
    MM_insert_node(ROOT, root);
    MM_delete_node(root);

    printf("  Node deletion check: %s%s%s\n", ROOT == NULL ? GREEN : RED, ROOT == NULL ? "Passed" : "Failed", RESET);
}

void test_MM_find_node_by_hash() {
    printf("Testing MM_find_node_by_hash:\n");
    ROOT = NULL; // Reset ROOT for the test
    node *n1 = MM_create_hash_tree_node(100);
    unsigned char hash[32];
    MM_hash_address(n1->ptr, hash); // Get hash of the node's memory address

    MM_insert_node(ROOT, n1); // Insert node into the tree
    node *found = MM_find_node_by_hash(ROOT, hash);

    printf("  Finding existing node by hash: %s%s%s\n", found == n1 ? GREEN : RED, found == n1 ? "Passed" : "Failed", RESET);

    unsigned char wrong_hash[32] = {0}; // A hash that does not correspond to any node
    node *not_found = MM_find_node_by_hash(ROOT, wrong_hash);
    printf("  Finding non-existing node by hash: %s%s%s\n", not_found == NULL ? GREEN : RED, not_found == NULL ? "Passed" : "Failed", RESET);

    free(n1->ptr);
    free(n1);
}

void test_API_MM_allocateMem() {
    printf("Testing API_MM_allocateMem:\n");
    ROOT = NULL; // Reset ROOT for the test

    void *mem = API_MM_allocateMem(128); // Allocate memory
    printf("  Allocating 128 bytes: %s%s%s\n", mem != NULL ? GREEN : RED, mem != NULL ? "Passed" : "Failed", RESET);

    void *zero_mem = API_MM_allocateMem(0); // Allocate zero bytes
    printf("  Allocating 0 bytes: %s%s%s\n", zero_mem == NULL ? GREEN : RED, zero_mem == NULL ? "Passed" : "Failed", RESET);
    
    if (mem) {
        free(((node *)ROOT)->ptr);
        free(ROOT);
    }
}

void test_API_MM_freeMem() {
    printf("Testing API_MM_freeMem:\n");
    ROOT = NULL; // Reset ROOT for the test

    void *mem = API_MM_allocateMem(64);
    int result = API_MM_freeMem(mem); // Free the allocated memory
    printf("  Freeing allocated memory: %s%s%s\n", result == SUCCESSMM ? GREEN : RED, result == SUCCESSMM ? "Passed" : "Failed", RESET);

    result = API_MM_freeMem(NULL); // Try to free NULL pointer
    printf("  Freeing NULL pointer: %s%s%s\n", result == MM_ERROR_NULL_POINTER ? GREEN : RED, result == MM_ERROR_NULL_POINTER ? "Passed" : "Failed", RESET);
}

void test_API_MM_realloc() {
    printf("Testing API_MM_realloc:\n");
    ROOT = NULL; // Reset ROOT for the test

    void *mem = API_MM_allocateMem(32);
    void *realloced_mem = API_MM_reallocMem(mem, 64); // Reallocate to larger size
    printf("  Reallocating to larger size: %s%s%s\n", realloced_mem != NULL ? GREEN : RED, realloced_mem != NULL ? "Passed" : "Failed", RESET);

    void *smaller_mem = API_MM_reallocMem(realloced_mem, 16); // Reallocate to smaller size
    printf("  Reallocating to smaller size: %s%s%s\n", smaller_mem != NULL ? GREEN : RED, smaller_mem != NULL ? "Passed" : "Failed", RESET);

    void *null_realloc = API_MM_reallocMem(NULL, 128); // Reallocate NULL pointer
    printf("  Reallocating NULL pointer: %s%s%s\n", null_realloc != NULL ? GREEN : RED, null_realloc != NULL ? "Passed" : "Failed", RESET);

    void *zero_size_realloc = API_MM_reallocMem(smaller_mem, 0); // Reallocate to zero size
    printf("  Reallocating to zero size (should free memory): %s%s%s\n", zero_size_realloc == NULL ? GREEN : RED, zero_size_realloc == NULL ? "Passed" : "Failed", RESET);

    if (null_realloc) {
        free(((node *)ROOT)->ptr);
        free(ROOT);
    }
}

void print_node_values(node *current_node) {
    if (current_node != NULL) {
        printf("Node at %p, left at %p, right at %p, father at %p\n",
               (void *)current_node,
               (void *)current_node->left,
               (void *)current_node->right,
               (void *)current_node->father);
        print_node_values(current_node->left);
        print_node_values(current_node->right);
    }
}

void test_zeroize_tree() {
    printf("Testing zeroize_tree:\n");
    ROOT = NULL; // Ensure ROOT is reset

    // Setup a small tree
    node *root = MM_create_hash_tree_node(10);
    node *leftChild = MM_create_hash_tree_node(20);
    node *rightChild = MM_create_hash_tree_node(30);

    // Construct the tree
    MM_insert_node(ROOT, root);
    MM_insert_node(ROOT, leftChild);
    MM_insert_node(ROOT, rightChild);

    // Print tree structure before zeroization
    printf("Before zeroize_tree:\n");
    print_node_values(ROOT);

    // Apply zeroize_tree
    zeroize_tree(ROOT);

    // Check results after zeroization
    printf("After zeroize_tree:\n");

    // Since nodes are freed, accessing them could lead to undefined behavior. We assume here they're properly handled.
    printf("zeroize_tree completed. Manual verification needed to check if nodes are zeroized.\n");

    // As nodes are freed, reset ROOT manually to prevent dangling pointer usage in the environment
    ROOT = NULL;
}

void Test_DmemManager(){
    test_MM_compare_hash();
    test_MM_hash_address();
    test_MM_create_hash_tree_node();
    test_MM_insert_node();
    test_MM_delete_node();
    test_MM_find_node_by_hash();
    test_API_MM_allocateMem();
    test_API_MM_freeMem();
    test_API_MM_realloc();
    test_zeroize_tree();
}
