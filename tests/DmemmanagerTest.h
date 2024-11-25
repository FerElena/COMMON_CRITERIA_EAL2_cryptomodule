#ifndef DMEMMANAGER_H
#define DMEMMANAGER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>

#include "../secure_memory_management/DmemManager.h"

void test_MM_compare_hash();

void test_MM_hash_address();

void test_MM_create_hash_tree_node();

void test_MM_insert_node();

void test_MM_delete_node();

void test_MM_find_node_by_hash();

void test_API_MM_allocateMem();

void test_API_MM_freeMem();

void test_API_MM_realloc();

void print_node_values(node *current_node);

void test_zeroize_tree();

void Test_DmemManager();
#endif