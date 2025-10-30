#pragma once
#ifndef CODE_H
#define CODE_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// config
#define MEMTABLE_SIZE 1
#define MAX_SSTABLES 10
#define KEY_SIZE 50
#define VALUE_SIZE 100

#define DATA_FILE "lsm_data.bin"

typedef struct
{
    char key[KEY_SIZE];
    char value[VALUE_SIZE];
} KeyValuePair;

// in memory (RAM)
typedef struct
{
    KeyValuePair *pairs;
    int size;
    int capacity;
} MemTable;

typedef struct
{
    KeyValuePair *pairs;
    int size;
    char filename[32];
} SSTable;

typedef struct
{
    MemTable memtable;
    SSTable sstables[MAX_SSTABLES];
    int sstable_count;
} LSMTree;

typedef struct
{
    uint8_t *bitmap;
    size_t size;
} BloomFilter;

typedef struct
{
    char key[KEY_SIZE];
    long file_offset;
} SparseIndexEntry;

/*
onion router
*/
typedef struct
{
    char onion_address[64];
    char password_hash[128];
    time_t timestamp;
} RouterEntry;

void init_lsm_tree(LSMTree *tree);
void free_lsm_tree(LSMTree *tree);
void lsm_put(LSMTree *tree, const char *key, const char *value);
char *lsm_get(LSMTree *tree, const char *key);
void flush_memtable_to_sstable(LSMTree *tree);
int compare_keys(const void *a, const void *b);
void compact_sstables(LSMTree *tree);
void save_sstable_to_disk(SSTable *sstable);
void load_sstable_from_disk(SSTable *sstable, const char *filename);
void lsm_delete(LSMTree *tree, const char *key);
void load_data_from_file(LSMTree *tree);
void save_all_data_to_file(LSMTree *tree);

#endif