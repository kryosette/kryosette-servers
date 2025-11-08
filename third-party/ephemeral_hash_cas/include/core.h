#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

// ==================== Ephemeral Hash CAS Core ====================

// Generate unpredictable one-time hash
uint16_t generate_eph_hash();

// Tagged pointer with ephemeral hash
typedef struct
{
    uintptr_t ptr : 48;
    uintptr_t hash : 16;
} EHashPtr;

// Create tagged pointer
static inline EHashPtr make_ehash_ptr(void *ptr, uint16_t hash)
{
    return (EHashPtr){(uintptr_t)ptr, hash};
}

// Ephemeral Hash CAS primitive
static inline bool EHash_CAS(int *addr, EHashPtr expected, EHashPtr new_val)
{
    return atomic_compare_exchange_strong((atomic_int *)addr,
                                          (int *)&expected,
                                          *(int *)&new_val);
}

// Helper to load EHashPtr from memory
static inline EHashPtr EHash_load(int *addr)
{
    EHashPtr result;
    *(int *)&result = atomic_load((atomic_int *)addr);
    return result;
}

// ==================== Basic CAS Wrapper ====================

// Regular CAS (for comparison/fallback)
static inline bool CAS(int *ptr, int expected, int new_val)
{
    return atomic_compare_exchange_strong((atomic_int *)ptr, &expected, new_val);
}