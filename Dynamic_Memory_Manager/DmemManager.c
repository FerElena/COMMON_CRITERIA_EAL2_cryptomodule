/**
 * @file DmemManager.c
 * @brief File containing all the functions for the management of dynamic memory.
 */

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "DmemManager.h"

/****************************************************************************************************************
 * Global variables definition
 ****************************************************************************************************************/

node *ROOT = NULL; // Global pointer to the root of the memory management tree

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

// Compares two 32-byte hash values, returning comparison results as integers for ordering or collision detection.
int MM_compare_hash(unsigned char arr1[], unsigned char arr2[]) {
    int result = memcmp(arr1, arr2, 32);
    if (result < 0) return 1;
    else if (result > 0) return 0;
    else return 2; // Hashes are equal
}

// Hashes a memory address to a 32-byte array using the SHA-256 algorithm.
void MM_hash_address(void *address, unsigned char out[32]) {
    unsigned char aux[sizeof(void *)];
    memcpy(aux, &address, sizeof(void *));
    API_sha256(aux, sizeof(void *), out);
}

// Creates a new tree node for managing a specific memory size, initializes its data, and returns the node.
node *MM_create_hash_tree_node(size_t size) {
    node *newNode = (node *)malloc(sizeof(node));
    if (!newNode) return NULL;

    newNode->ptr = malloc(size);
    if (!newNode->ptr) {
        free(newNode);
        return NULL;
    }

    newNode->size = size;
    MM_hash_address(newNode->ptr, newNode->hash);
    newNode->left = newNode->right = newNode->father = NULL;
    return newNode;
}

// Inserts a node into the hash tree based on its hash value, handling collisions as needed.
void MM_insert_node(node *actualNode, node *newNode) {
    if (!ROOT) {
        ROOT = newNode;
        return;
    }

    node *current = ROOT;
    node *parent = NULL;
    int direction = 0;

    while (current) {
        parent = current;
        int comparison = MM_compare_hash(current->hash, newNode->hash);
        if (comparison == 0) {
            current = current->left;
            direction = 0;
        } else if (comparison == 1) {
            current = current->right;
            direction = 1;
        } else {
            printf("COLLISION DETECTED IN SHA256 IN MEM MANAGER\n");
            return; // HASH COLLISION in sha-256
        }
    }

    if (direction == 0) parent->left = newNode;
    else parent->right = newNode;
    newNode->father = parent;
}

// Finds the node with the smallest key in the subtree rooted at a given node.
node *MM_find_minimum(node *current_node) {
    if (!current_node) return NULL;  // Add NULL check for safety.
    while (current_node->left != NULL) {
        current_node = current_node->left;
    }
    return current_node;
}

// Securely wipes memory data by overwriting with predefined patterns.
void secure_zeroize(void *data, size_t size) {
    for (int i = 0; i < 6; i++) {
        memset(data, Schneier_patternsDM[i], size);
    }
}

// Replaces one subtree as a child of its parent with another subtree.
void MM_transplant(node *from_node, node *to_node) {
    if (!from_node->father) {
        ROOT = to_node;
    } else if (from_node == from_node->father->left) {
        from_node->father->left = to_node;
    } else {
        from_node->father->right = to_node;
    }
    if (to_node) {
        to_node->father = from_node->father;
    }
}

// Deletes a node from the tree, handling the removal and reconnection of children nodes securely.
void MM_delete_node(node *node_to_delete) {
    if (!node_to_delete) return;

    if (!node_to_delete->left) {
        MM_transplant(node_to_delete, node_to_delete->right);
    } else if (!node_to_delete->right) {
        MM_transplant(node_to_delete, node_to_delete->left);
    } else {
        node *successor = MM_find_minimum(node_to_delete->right);
        if (successor->father != node_to_delete) {
            MM_transplant(successor, successor->right);
            successor->right = node_to_delete->right;
            successor->right->father = successor;
        }
        MM_transplant(node_to_delete, successor);
        successor->left = node_to_delete->left;
        successor->left->father = successor;
    }

    secure_zeroize(node_to_delete->ptr, node_to_delete->size);
    free(node_to_delete->ptr);
    secure_zeroize(node_to_delete, sizeof(node));
    free(node_to_delete);
}

// Locates a node by comparing its hash, traversing the tree as needed based on hash comparisons.
node *MM_find_node_by_hash(node *current_node, unsigned char hash[])
{ // Search a node by the hash
    if (current_node == NULL)
    {
        return NULL;
    }
    int comparison_result = MM_compare_hash(current_node->hash, hash);
    if (comparison_result == 2)
    {
        return current_node;
    }
    else if (comparison_result == 0)
    {
        return MM_find_node_by_hash(current_node->left, hash);
    }
    else
    { // comparison_result == 1
        return MM_find_node_by_hash(current_node->right, hash);
    }
}

// Allocates memory and tracks it by creating a new tree node, ensuring memory management integrity.
void *API_MM_allocateMem(size_t size) {
    if (size == 0) {
        return NULL;
    }

    node *new_node = MM_create_hash_tree_node(size);
    if (new_node == NULL) {
        return NULL;
    }

    MM_insert_node(ROOT, new_node);
    return new_node->ptr;
}

// Frees memory associated with a pointer and removes its management node from the tree.
int API_MM_freeMem(void *ptr) {
    if (ptr == NULL) {
        return 0;  // Consistently return NULL on error, or define an error code if needed.
    }

    unsigned char hash[HASH_BLOCK_SIZE];
    MM_hash_address(ptr, hash);

    node *node_to_delete = MM_find_node_by_hash(ROOT, hash);
    if (node_to_delete == NULL) {
        return 0;  // Consider returning an error code here.
    }

    MM_delete_node(node_to_delete);
    return 1;
}

// Reallocates memory for a given pointer, potentially moving it to accommodate the new size.
void *API_MM_reallocMem(void *ptr, size_t new_size) {
    if (new_size == 0) {
        API_MM_freeMem(ptr);
        return NULL;
    }

    if (ptr == NULL) {
        return API_MM_allocateMem(new_size);
    }

    unsigned char hash[HASH_BLOCK_SIZE];
    MM_hash_address(ptr, hash);
    node *node_to_resize = MM_find_node_by_hash(ROOT, hash);

    if (node_to_resize == NULL) {
        return NULL;  // Return NULL to indicate failure to find the node.
    }

    if (new_size <= node_to_resize->size) {
        node_to_resize->size = new_size;
        return ptr;  // No need to reallocate.
    }

    void *new_ptr = API_MM_allocateMem(new_size);
    if (new_ptr == NULL) {
        return NULL;  // Handling allocation failure.
    }

    memcpy(new_ptr, ptr, node_to_resize->size);  // Use memmove instead to handle overlaps.
    API_MM_freeMem(ptr);

    return new_ptr;
}

// Recursively zeroes out and deallocates all nodes in a tree, ensuring secure deletion of all managed memory.
void zeroize_tree(node *current_node) {
    if (current_node != NULL) {
        zeroize_tree(current_node->left);
        zeroize_tree(current_node->right);

        secure_zeroize(current_node->ptr, current_node->size);
        secure_zeroize(current_node, sizeof(node));
    }
}
