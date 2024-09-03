/**
 * @file DmemManager.h
 * @brief File containing all the functions for the management of dynamic memory used in the project.
 */

#ifndef MEMANAGER_H
#define MEMANAGER_H

 /* Compiler include files ........................................... */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Private include files ............................................ */

#include "../crypto/sha256.h"

/* Type definitions ................................................. */

#define SUCCESSMM 0
#define ERROR_NULL_POINTER -1
#define ERROR_MEMORY_ALLOCATION_FAILED -2
#define ERROR_HASH_COLLISION -3

/**
 * @brief Hash-tree node struct
 */
typedef struct Node {
    void *ptr; /**< Hash-tree node pointer */
    size_t size; /**< Hash-tree node size */
    unsigned char hash[32]; /**< Hash-tree node SHA-256 hash */
    struct Node *left; /**< Hash-tree node left children */
    struct Node *right; /**< Hash-tree node rigth children */
    struct Node *father; /**< Hash-tree node father */
} node;

static const unsigned char Schneier_patternsDM[6] = {0x00, 0xFF, 0xAA, 0x55, 0xAA, 0x55};  


/* External variables definition .................................... */

/**
 * @brief Hash-tree root
 */
extern node *ROOT;

/* Global variables definition ...................................... */

/**
 * @brief True boolean value
 */
#define TRUE 1

/**
 * @brief Hash block size
 * SHA256 digest message size
 */
#define HASH_BLOCK_SIZE 32 

/* Function declaration zone ........................................ */

/**
 * @brief Compare two hashes and return the result
 * 
 * The purpose of this function is to compare two hashes and return the value of the comparation (0, 1 or 2)
 * 
 * @methodOfUse{This function is invoked by MM_insert_node and the MM_find_node_by_hash functions}
 * 
 * @param arr1 First hash to compare
 * @param arr2 Second hash to compare
 * 
 * @return The result of the comparation (0 if arr1 < arr2, 2 if arr1 > arr2 and 2 if the hashes are the same) 
 */
int MM_compare_hash(unsigned char arr1[], unsigned char arr2[]);

/**
 * @brief Hash the memory address stored in a pointer
 * 
 * The purpose of this function is to hash a memory address
 * 
 * 
 * @param address Address to be hashed
 * @param out Struct where the hash is stored
 */
void MM_hash_address(void *address, unsigned char out[32]);

/**
 * @brief Create a new node
 * 
 * The purpose of this function is to create a new hash-tree node to store information about the cryptographic library
 * 
 * 
 * @param size New node size
 * 
 * @return The new hash-tree node 
 */
node *MM_create_hash_tree_node(size_t size);

/**
 * @brief Insert a node in the hash-tree
 * 
 * The purpose of this function is to insert a new node into the actual hash-tree node, trying to insert in his right or left branch
 * 
 * @methodOfUse{This function is invoked by the API_MM_allocateMem and API_MM_reallocMem functions. Also it is called recursively} 
 * 
 * @param actualNode Node hash-tree where the function try to insert the new node
 * @param newNode Hash-tree new node
 */
void MM_insert_node(node *actualNode, node *newNode);

/**
 * @brief Find the minimum left-node children
 * 
 * The purpose of this function is to subsitute a deleted node by the minimum left-node children into te hash-tree
 * 
 * @methodOfUse{This function is invoked by the MM_delete_node function} 
 * 
 * @param current_node Hash-tree current node
 * @return The minimum left-node children
 */
node *MM_find_minimum(node *current_node);

/**
 * @brief Move a node to another one
 * 
 * The purpose of this function is to move a hash-tree node to a new position
 * 
 * @methodOfUse{This function is invoked by the MM_delete_node function} 
 * 
 * @param from_node Origin node
 * @param to_node Destiny node
 */
void MM_transplant(node *from_node, node *to_node);

/**
 * @brief Delete a node from the hash-tree
 * 
 * The purpose of this function is to delete a node from the hash-tree and reorganizate the rest of the nodes
 * 
 * 
 * @param node_to_delete Node to delete from the hash-tree
 */
void MM_delete_node(node *node_to_delete);

/**
 * @brief Find a node in the hash-tree
 * 
 * The purpose of this function is, with a hash value, search the correspondant hash-tree node
 * 
 * 
 * @param current_node Hash-tree current node
 * @param hash Hash to search
 * 
 * @return The hash-tree node 
 */
node *MM_find_node_by_hash(node *current_node, unsigned char hash[]);

/**
 * @brief Allocates a specific memory block.
 * After allocating the memory block, its information is stored in a storaged block that is added to the list.
 * 
 * @param size Size in bytes of the required memory block
 * @return The address of the required memory block
 * 
 * @errors
 * @error{ ERROR 1, Returns NULL when allocating memory fails}
 */
void *API_MM_allocateMem(size_t size);

/**
 * @brief Frees a specific memory block.
 *
 * After freeing the memory block, its corresponging storage block is remove from the list.
 * Before freeing , all the data is zeroize.
 * Do nothing if the item is not found.
 * 
 * 
 * @param ptr Address of the memory block to remove
 * @return The result of the task (0 if all goes good, other value means an error)
 * 
 * @errors
 * @error{ ERROR 1, Returns NULL when there is no item to remove}
 */
int API_MM_freeMem(void *ptr);

/**
 * @brief Change the size of a specific memory block.
 *
 * Frees the previous memory block and add the new one in the same storage block
 * 
 * 
 * @param ptr Address of the memory block to edit
 * @param new_size Size in bytes to edit
 * @return The address of the 'new' memory block
 * 
 * @errors
 * @error{ ERROR 1, Returns NULL when allocating new memory fails}
 */
void *API_MM_reallocMem(void *ptr, size_t new_size);

/**
 * @brief Zeroizes every block allocated in the library
 * 
 */

void zeroize_tree(node *current_node);
/**
 * @brief Removes all the storage blocks in the list
 * Zeroises and frees all the stored memroy blocks. 
 * 
 * 
 * @param id Identifier for the client that requires the ntPacket function. If the ID is 9999, there is no user, is the module zeroization for attacks
 * @return The result of the zeroization, 1 completed, 0 failed
 * 
 * @errors
 * @error{ ERROR 1, Returns -1 if the state is not CRYPTOOFFICER_STATE or ERROR_STATE}
 */
int API_MM_zeroizeEntireModule(unsigned char* id);

#endif