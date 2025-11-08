#include "core.h"
#include <stdlib.h>

// ==================== Ephemeral Hash Implementation ====================

// Simple PRNG for ephemeral hashes (Knuth multiplicative)
static inline uint32_t prng(uint32_t x)
{
    return x * 2654435761U;
}

uint16_t generate_eph_hash()
{
    static atomic_uint32_t state = 0;

    // Get current state and update
    uint32_t current = atomic_fetch_add(&state, 1);

    // Generate hash using PRNG
    uint32_t hashed = prng(current);

    // Mix bits and return 16-bit hash
    return (uint16_t)((hashed >> 16) ^ hashed);
}

// ==================== EHash CAS Operations ====================

// CAS with automatic ephemeral hash generation
bool EHash_CAS_auto(int *addr, void *expected_ptr, void *new_ptr)
{
    uint16_t hash = generate_eph_hash();
    EHashPtr expected = make_ehash_ptr(expected_ptr, hash);
    EHashPtr new_val = make_ehash_ptr(new_ptr, hash);
    return EHash_CAS(addr, expected, new_val);
}

// Compare only pointers (ignore hash) - for validation
static inline bool ehash_ptr_equal(EHashPtr a, EHashPtr b)
{
    return a.ptr == b.ptr;
}

// Extract pointer from EHashPtr
static inline void *ehash_get_ptr(EHashPtr p)
{
    return (void *)p.ptr;
}