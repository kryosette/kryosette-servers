#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// ==================== Ephemeral Hash CAS Core ====================

typedef struct
{
    uint64_t ptr : 48;
    uint64_t hash : 16;
} EHashPtr;

typedef struct
{
    _Atomic(uint64_t) state;
} HashGenerator;

// ==================== Public API ====================

static inline void hash_generator_init(HashGenerator *gen, uint64_t seed)
{
    atomic_store(&gen->state, seed);
}

static inline uint16_t hash_generator_next(HashGenerator *gen)
{
    uint64_t old_state = atomic_load(&gen->state);
    uint64_t new_state;
    uint16_t hash;

    do
    {
        new_state = old_state;
        new_state ^= new_state >> 12;
        new_state ^= new_state << 25;
        new_state ^= new_state >> 27;
        hash = (uint16_t)((new_state * 0x2545F4914F6CDD1DULL) >> 48);
    } while (!atomic_compare_exchange_strong(&gen->state, &old_state, new_state));

    return hash;
}

static inline EHashPtr make_ehash_ptr(void *ptr, uint16_t hash)
{
    uintptr_t ptr_val = (uintptr_t)ptr;
    // Ensure pointer fits in 48 bits
    assert((ptr_val & 0xFFFF000000000000) == 0 && "Pointer must fit in 48 bits");
    return (EHashPtr){ptr_val, hash};
}

static inline void *ehash_get_ptr(EHashPtr p)
{
    return (void *)p.ptr;
}

static inline bool ehash_full_equal(EHashPtr a, EHashPtr b)
{
    return a.ptr == b.ptr && a.hash == b.hash;
}

static inline uint64_t ehash_to_uint64(EHashPtr p)
{
    return ((uint64_t)p.hash << 48) | (p.ptr & 0xFFFFFFFFFFFF);
}

static inline EHashPtr ehash_from_uint64(uint64_t val)
{
    return (EHashPtr){val & 0xFFFFFFFFFFFF, (val >> 48) & 0xFFFF};
}

static inline bool EHash_CAS(_Atomic(uint64_t) *addr, EHashPtr expected, EHashPtr new_val)
{
    uint64_t expected_raw = ehash_to_uint64(expected);
    uint64_t new_val_raw = ehash_to_uint64(new_val);
    return atomic_compare_exchange_strong(addr, &expected_raw, new_val_raw);
}

static inline EHashPtr EHash_load(_Atomic(uint64_t) *addr)
{
    return ehash_from_uint64(atomic_load(addr));
}

// ==================== Lock-Free Stack Implementation ====================

typedef struct EHashStackNode
{
    void *data;
    struct EHashStackNode *next;
} EHashStackNode;

typedef struct
{
    _Atomic(uint64_t) head;
    HashGenerator hash_gen;
} EHashStack;

static inline void ehash_stack_init(EHashStack *stack, uint64_t seed)
{
    atomic_store(&stack->head, 0);
    hash_generator_init(&stack->hash_gen, seed);
}

static inline void ehash_stack_push(EHashStack *stack, EHashStackNode *node)
{
    EHashPtr old_head, new_head;

    do
    {
        old_head = EHash_load(&stack->head);
        node->next = (EHashStackNode *)ehash_get_ptr(old_head);
        new_head = make_ehash_ptr(node, hash_generator_next(&stack->hash_gen));
    } while (!EHash_CAS(&stack->head, old_head, new_head));
}

static inline EHashStackNode *ehash_stack_pop(EHashStack *stack)
{
    EHashPtr old_head, new_head;
    EHashStackNode *node;

    do
    {
        old_head = EHash_load(&stack->head);
        node = (EHashStackNode *)ehash_get_ptr(old_head);
        if (!node)
            return NULL;

        new_head = make_ehash_ptr(node->next, hash_generator_next(&stack->hash_gen));
    } while (!EHash_CAS(&stack->head, old_head, new_head));

    return node;
}