#include "DmemManager.h"


void test_MM_compare_hash() {
    unsigned char hash1[32] = {0};
    unsigned char hash2[32] = {1};
    memset(hash1, 0, sizeof(hash1));
    memset(hash2, 0, sizeof(hash2));
    hash2[0] = 1; // Make sure hash2 is different at the first byte

    printf("\n\nTesting MM_compare_hash:\n");
    printf("  Result when arrays are equal: %s\n", MM_compare_hash(hash1, hash1) == 2 ? "Passed" : "Failed");
    printf("  Result when arr1 < arr2: %s\n", MM_compare_hash(hash1, hash2) == 1 ? "Passed" : "Failed");
    printf("  Result when arr1 > arr2: %s\n", MM_compare_hash(hash2, hash1) == 0 ? "Passed" : "Failed");
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
    printf("  Node creation: %s\n", newNode != NULL ? "Passed" : "Failed");
    if (newNode) {
        printf("  Memory allocation for node: %s\n", newNode->ptr != NULL ? "Passed" : "Failed");
        printf("  Node size initialization: %s\n", newNode->size == size ? "Passed" : "Failed");
        printf("  Node structure initialization: %s\n", (newNode->left == NULL && newNode->right == NULL && newNode->father == NULL) ? "Passed" : "Failed");

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

    printf("  Root check: %s\n", ROOT == root ? "Passed" : "Failed");
    printf("  Child insertion check: %s\n", (root->left == child || root->right == child) ? "Passed" : "Failed");

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

    printf("  Node deletion check: %s\n", ROOT == NULL ? "Passed" : "Failed");
    // Note: MM_delete_node should also zeroize and free the node's memory, which should be checked here if possible.
}

void test_MM_find_node_by_hash() {
    printf("Testing MM_find_node_by_hash:\n");
    ROOT = NULL; // Reset ROOT for the test
    node *n1 = MM_create_hash_tree_node(100);
    unsigned char hash[32];
    MM_hash_address(n1->ptr, hash); // Get hash of the node's memory address

    MM_insert_node(ROOT, n1); // Insert node into the tree
    node *found = MM_find_node_by_hash(ROOT, hash);

    printf("  Finding existing node by hash: %s\n", found == n1 ? "Passed" : "Failed");

    unsigned char wrong_hash[32] = {0}; // A hash that does not correspond to any node
    node *not_found = MM_find_node_by_hash(ROOT, wrong_hash);
    printf("  Finding non-existing node by hash: %s\n", not_found == NULL ? "Passed" : "Failed");

    free(n1->ptr);
    free(n1);
}

void test_API_MM_allocateMem() {
    printf("Testing API_MM_allocateMem:\n");
    ROOT = NULL; // Reset ROOT for the test

    void *mem = API_MM_allocateMem(128); // Allocate memory
    printf("  Allocating 128 bytes: %s\n", mem != NULL ? "Passed" : "Failed");

    void *zero_mem = API_MM_allocateMem(0); // Allocate zero bytes
    printf("  Allocating 0 bytes: %s\n", zero_mem == NULL ? "Passed" : "Failed");
    
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
    printf("  Freeing allocated memory: %s\n", result == SUCCESS ? "Passed" : "Failed");

    void *null_result = API_MM_freeMem(NULL); // Try to free NULL pointer
    printf("  Freeing NULL pointer: %s\n", null_result == NULL ? "Passed" : "Failed");
}

void test_API_MM_realloc() {
    printf("Testing API_MM_realloc:\n");
    ROOT = NULL; // Reset ROOT for the test

    void *mem = API_MM_allocateMem(32);
    void *realloced_mem = API_MM_reallocMem(mem, 64); // Reallocate to larger size
    printf("  Reallocating to larger size: %s\n", realloced_mem != NULL ? "Passed" : "Failed");

    void *smaller_mem = API_MM_reallocMem(realloced_mem, 16); // Reallocate to smaller size
    printf("  Reallocating to smaller size: %s\n", smaller_mem != NULL ? "Passed" : "Failed");

    void *null_realloc = API_MM_reallocMem(NULL, 128); // Reallocate NULL pointer
    printf("  Reallocating NULL pointer: %s\n", null_realloc != NULL ? "Passed" : "Failed");

    void *zero_size_realloc = API_MM_reallocMem(smaller_mem, 0); // Reallocate to zero size
    printf("  Reallocating to zero size (should free memory): %s\n", zero_size_realloc == NULL ? "Passed" : "Failed");

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


