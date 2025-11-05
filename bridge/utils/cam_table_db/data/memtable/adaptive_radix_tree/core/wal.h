#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef enum {
    WAL_INSERT = 'I',
    WAL_DELETE = 'D'
} wal_operation_t;

ltypedef struct {
    uint64_t timestamp;    
    char operation;
    uint32_t key_size;     
    uint32_t value_size;   
    char* key;            
    char* value;         
} wal_record_t;

typedef struct {
    int fd;                
    char* filename;        
    size_t current_size;  
    size_t max_size;       
    uint64_t sequence;     
} wal_t;

typedef int (*wal_apply_func_t)(char operation, const char* key, size_t key_len, 
                               const char* value, size_t value_len, void* user_data);

wal_t* wal_init(const char* base_filename, size_t max_size);

int wal_append(wal_t* wal, const char* key, size_t key_len, 
               const char* value, size_t value_len, char operation);

int wal_replay(wal_t* wal, wal_apply_func_t apply_func, void* user_data);

int wal_rotate(wal_t* wal);

int wal_clear(wal_t* wal);

void wal_close(wal_t* wal);

char* wal_find_latest(const char* base_filename);

int wal_recover(const char* base_filename, wal_apply_func_t apply_func, void* user_data);

#endif
