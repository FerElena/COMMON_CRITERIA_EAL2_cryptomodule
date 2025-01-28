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
// Compares two 32-byte hash values.
// Returns 1 if arr1 < arr2, 0 if arr1 > arr2, and 2 if they are equal.
int MM_compare_hash(unsigned char arr1[], unsigned char arr2[])
{
    int result = memcmp(arr1, arr2, 32); // Compare hashes byte by byte.
    if (result < 0)
        return 1;
    else if (result > 0)
        return 0;
    return 2; // Hashes are equal.
}

// Hashes a memory address into a 32-byte array using SHA-256.
void MM_hash_address(void *address, unsigned char out[32])
{
    unsigned char aux[sizeof(void *)];     // Buffer for address.
    memcpy(aux, &address, sizeof(void *)); // Copy address into buffer.
    API_sha256(aux, sizeof(void *), out);  // Compute the SHA-256 hash.
}

// Creates a new tree node for managing a memory block.
// Allocates memory for the node and the memory block it will manage.
node *MM_create_hash_tree_node(size_t size)
{
    node *newNode = (node *)malloc(sizeof(node)); // Allocate space for the node.
    if (!newNode)
        return NULL; // Return NULL if node allocation fails.

    // Allocate memory for the block to be managed by the node.
    newNode->ptr = malloc(size);
    if (!newNode->ptr)
    {
        free(newNode); // Free node if block allocation fails.
        return NULL;
    }

    mlock(newNode->ptr, size); // Lock memory in RAM to prevent swapping.

    newNode->size = size;                                    // Set the size of the allocated block.
    MM_hash_address(newNode->ptr, newNode->hash);            // Hash the address of the memory block.
    newNode->left = newNode->right = newNode->father = NULL; // Initialize pointers.
    return newNode;
}

// Inserts a node into the memory management tree, ordered by hash values.
void MM_insert_node(node *actualNode, node *newNode)
{
    if (!ROOT)
    { // If the tree is empty, set the new node as the root.
        ROOT = newNode;
        return;
    }

    node *current = ROOT;
    node *parent = NULL;
    int direction = 0; // Direction determines left or right insertion.

    // Traverse the tree, comparing hash values to determine insertion point.
    while (current)
    {
        parent = current;
        int comparison = MM_compare_hash(current->hash, newNode->hash); // Compare hash values.
        if (comparison == 0)
        { // If newNode is smaller, go left.
            current = current->left;
            direction = 0;
        }
        else if (comparison == 1)
        { // If newNode is larger, go right.
            current = current->right;
            direction = 1;
        }
        else
        {
            // Handle hash collision.
            return;
        }
    }

    // Insert the node at the correct position.
    if (direction == 0)
        parent->left = newNode;
    else
        parent->right = newNode;
    newNode->father = parent;
}

// Finds the node with the smallest hash value in a subtree.
node *MM_find_minimum(node *current_node)
{
    if (!current_node)
        return NULL; // Return NULL if node is empty.

    // Traverse the left children until the smallest (leftmost) node is found.
    while (current_node->left != NULL)
    {
        current_node = current_node->left;
    }
    return current_node;
}

// Securely wipes the memory by overwriting it with predefined patterns.
void API_MM_secure_zeroize(void *data, size_t size)
{
    for (int i = 0; i < 6; i++)
    {
        memset(data, Schneier_patternsDM[i], size); // Overwrite memory with each pattern.
    }
}

// Replaces one subtree with another in the tree.
void MM_transplant(node *from_node, node *to_node)
{
    if (!from_node->father)
    { // If from_node is the root, replace it with to_node.
        ROOT = to_node;
    }
    else if (from_node == from_node->father->left)
    {
        from_node->father->left = to_node; // Replace left child.
    }
    else
    {
        from_node->father->right = to_node; // Replace right child.
    }
    if (to_node)
    {
        to_node->father = from_node->father; // Update to_node’s parent.
    }
}

// Deletes a node from the tree, securely wiping its memory and reattaching children.
void MM_delete_node(node *node_to_delete)
{
    if (!node_to_delete)
        return; // Return if node is NULL.

    if (!node_to_delete->left)
    {
        MM_transplant(node_to_delete, node_to_delete->right); // Replace with right child if no left child.
    }
    else if (!node_to_delete->right)
    {
        MM_transplant(node_to_delete, node_to_delete->left); // Replace with left child if no right child.
    }
    else
    {
        node *successor = MM_find_minimum(node_to_delete->right); // Find the smallest node in right subtree.
        if (successor->father != node_to_delete)
        {
            MM_transplant(successor, successor->right); // Replace successor with its right child.
            successor->right = node_to_delete->right;
            successor->right->father = successor;
        }
        MM_transplant(node_to_delete, successor); // Replace node_to_delete with successor.
        successor->left = node_to_delete->left;
        successor->left->father = successor;
    }

    API_MM_secure_zeroize(node_to_delete->ptr, node_to_delete->size); // Securely wipe memory block.
    free(node_to_delete->ptr);                                        // Free memory block.
    API_MM_secure_zeroize(node_to_delete, sizeof(node));              // Securely wipe node structure.
    free(node_to_delete);                                             // Free node.
}

// Finds a node by its hash value, traversing the tree to locate it.
node *MM_find_node_by_hash(node *current_node, unsigned char hash[])
{
    if (!current_node)
        return NULL; // Return NULL if current_node is NULL.

    int comparison_result = MM_compare_hash(current_node->hash, hash); // Compare the node's hash with the target hash.
    if (comparison_result == 2)
        return current_node; // Return node if hashes match.

    // Recursively search left or right subtree based on comparison result.
    if (comparison_result == 0)
        return MM_find_node_by_hash(current_node->left, hash);
    return MM_find_node_by_hash(current_node->right, hash);
}

// Allocates memory and tracks it by creating a new tree node.
void *API_MM_allocateMem(size_t size,node *subtree_root)
{
    if (size == 0)
        return NULL; // Return NULL if size is zero.

    node *new_node = MM_create_hash_tree_node(size); // Create a new node to manage the memory block.
    if (!new_node)
        return NULL; // Return NULL if node creation fails.

    MM_insert_node(subtree_root, new_node); // Insert the node into the tree.
    return new_node->ptr;           // Return the pointer to the allocated memory.
}

// Frees memory and removes its corresponding node from the tree.
int API_MM_freeMem(void *ptr,node *subtree_root)
{
    if (!ptr)
        return MM_ERROR_NULL_POINTER; // Return 0 if pointer is NULL.

    unsigned char hash[HASH_BLOCK_SIZE];
    MM_hash_address(ptr, hash); // Hash the pointer.

    node *node_to_delete = MM_find_node_by_hash(subtree_root, hash); // Find the node corresponding to the pointer.
    if (!node_to_delete)
        return MM_MEMORY_DEALLOCATION_FAILED; // Return 0 if node not found.

    MM_delete_node(node_to_delete); // Delete the node and free its memory.
    return SUCCESSMM;               // Return success.
}

void *API_MM_reallocMem(void *ptr, size_t new_size,node *subtree_root)
{
    if (new_size == 0)
    {
        // If the new size is zero, free the memory and return NULL.
        return API_MM_freeMem(ptr,subtree_root) == SUCCESSMM ? NULL : NULL;
    }

    if (!ptr)
    {
        // If the pointer is NULL, allocate a new block of memory.
        return API_MM_allocateMem(new_size,subtree_root);
    }

    unsigned char hash[HASH_BLOCK_SIZE];
    MM_hash_address(ptr, hash); // Hash the pointer to locate the node.

    node *node_to_relocate = MM_find_node_by_hash(ROOT, hash); // Find the node for the allocated memory.
    if (!node_to_relocate)
    {
        // If no node is found, return NULL.
        return NULL;
    }

    if (node_to_relocate->size >= new_size)
    {
        // If the existing memory block is already large enough, just return the pointer.
        return ptr;
    }

    // Allocate new memory of the desired size.
    void *new_ptr = API_MM_allocateMem(new_size,subtree_root);
    if (!new_ptr)
    {
        // If memory allocation fails, return NULL.
        return NULL;
    }

    // Copy the contents of the old memory block to the new memory block.
    memcpy(new_ptr, ptr, node_to_relocate->size);

    // Free the old memory block.
    API_MM_freeMem(ptr,subtree_root);

    return new_ptr; // Return the pointer to the newly allocated memory.
}

// Recursively wipes and frees all nodes in a subtree, securely deleting all associated memory.
void zeroize_tree(node *current_node)
{
    if (current_node != NULL)
    {
        zeroize_tree(current_node->left);  // Recursively clear the left subtree.
        zeroize_tree(current_node->right); // Recursively clear the right subtree.

        API_MM_secure_zeroize(current_node->ptr, current_node->size); // Securely wipe the memory block.
        if(current_node != ROOT)
            API_MM_secure_zeroize(current_node, sizeof(node)); // Securely wipe the node structure, unless the node is ROOT
    }
}

// zeroize entire tree of nodes, functions for complete zeroization
void API_MM_Zeroize_root()
{
    zeroize_tree(ROOT);
}
